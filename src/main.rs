mod zkevm_circuit;
mod aggregation;

use halo2_curves::bn256::Fq;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{ParamsProver, Params},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        }, VerificationStrategy,
    },
    transcript::{
        TranscriptReadBuffer, TranscriptWriterBuffer, EncodedChallenge,
    }, dev::MockProver,
};
use itertools::Itertools;
use zkevm_circuits::{
    pi_circuit::PiTestCircuit,
    util::SubCircuit,
};
use snark_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config}, loader::{native::NativeLoader, evm::{EvmLoader, self, encode_calldata, ExecutorBuilder, Address}}, verifier::SnarkVerifier,
};
use std::{fs, io::Cursor, rc::Rc};
use rand::rngs::OsRng;
use ark_std::{end_timer, start_timer};

fn write_params(degree: usize, params: &ParamsKZG<Bn256>) -> Result<(), std::io::Error> {
    let dir = "./generated";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/srs-{}", dir, degree);
    let mut file = fs::File::create(&path).unwrap_or_else(|_| panic!("create {}", &path));
    params.write(&mut file)
}

fn read_params(degree: usize) -> Result<ParamsKZG<Bn256>, std::io::Error> {
    let dir = "./generated";
    let path = format!("{}/srs-{}", dir, degree);
    let mut file = fs::File::open(&path)?;
    ParamsKZG::<Bn256>::read(&mut file)
}

fn gen_circuit_params<const D: usize>(degree: usize, degree_app: usize) -> (ParamsKZG<Bn256>, ParamsKZG<Bn256>) {
    let result = read_params(degree);
    let result_app = read_params(degree_app);
    
    if result.is_ok() && result_app.is_ok() {
        (result.unwrap(), result_app.unwrap())
    } else {
        let params = ParamsKZG::<Bn256>::setup(degree as u32, OsRng);
        let mut params_app = params.clone();
        params_app.downsize(degree_app as u32);
        write_params(degree, &params).expect("write srs ok");
        write_params(degree_app, &params_app).expect("write srs ok");
        (params, params_app)
    }
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_zkevm_snark(params: &ParamsKZG<Bn256>) -> aggregation::Snark {
    let circuit = zkevm_circuit::gen_pi_circuit();

    let pk = gen_pk(params, &circuit);
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg().with_num_instance(
            <PiTestCircuit::<
                Fr,
                { zkevm_circuit::MAX_TXS },
                { zkevm_circuit::MAX_CALLDATA },
            > as zkevm_circuit::InstancesExport>::num_instance()
        ),
    );

    let proof = gen_proof::<
        _,
        _,
        aggregation::PoseidonTranscript<NativeLoader, _>,
        aggregation::PoseidonTranscript<NativeLoader, _>,
    >(params, &pk, circuit.clone(), circuit.instance());
    aggregation::Snark::new(protocol, circuit.instance(), proof)
}

fn gen_aggregation_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(Some(accumulator_indices)),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = aggregation::PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    // first the verifier verifies the new accumulator is correctly accumulated from old ones
    // then the decider verifies if the accumulator itself is correct: do the pairing and check if the result is identity
    aggregation::PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, deployment_code.into(), 0.into())
            .address
            .unwrap();
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!(result.gas_used);

        !result.reverted
    };
    assert!(success);
}


fn main()  {

    let timer1 = start_timer!(|| "timer 1"); // 30.101s
    let (params, params_app) = gen_circuit_params::<0>(22, 19);
    end_timer!(timer1);

    let timer2 = start_timer!(|| "timer 2"); // 97.902s
    let zkevm_snarks = [(); 2].map(|_| gen_zkevm_snark(&params_app));
    end_timer!(timer2);

    let timer3 = start_timer!(|| "timer 3"); // 132.726s
    let agg_circuit = aggregation::AggregationCircuit::new(&params, zkevm_snarks);
    let pk = gen_pk(&params, &agg_circuit);
    let deployment_code = gen_aggregation_evm_verifier(
        &params,
        pk.get_vk(),
        aggregation::AggregationCircuit::num_instance(),
        aggregation::AggregationCircuit::accumulator_indices(),
    );
    end_timer!(timer3);

    let timer4 = start_timer!(|| "timer 4"); // 274.205s
    let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
    );
    evm_verify(deployment_code, agg_circuit.instances(), proof); // gas_used = 603477
    end_timer!(timer4);


    // // Change the propagated inner snark's instance
    // instances[0][0] += Fr::one();
    // // Then expect the verification to fail
    // assert_eq!(
    //     MockProver::run(21, &aggregation, instances)
    //         .unwrap()
    //         .verify_par(),
    //     Err(vec![
    //         VerifyFailure::Permutation {
    //             column: (Any::advice(), 0).into(),
    //             location: FailureLocation::InRegion {
    //                 region: (1, "Aggregate snarks").into(),
    //                 offset: 0
    //             }
    //         },
    //         VerifyFailure::Permutation {
    //             column: (Any::Instance, 0).into(),
    //             location: FailureLocation::OutsideRegion { row: 0 }
    //         }
    //     ])
    // );
    
}

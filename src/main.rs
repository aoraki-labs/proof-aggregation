mod zkevm_circuit1;
mod zkevm_circuit2;
mod aggregation;

use clap::{Parser, Subcommand};
use eth_types::Bytes;
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
use serde::{Serialize, Deserialize};
use zkevm_circuits::{
    pi_circuit::PiTestCircuit,
    util::SubCircuit,
};
use snark_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config}, loader::{native::NativeLoader, evm::{EvmLoader, self, encode_calldata, ExecutorBuilder, Address}}, verifier::SnarkVerifier,
};
use std::{fs::{self, File}, io::{Cursor, Read, Write}, rc::Rc};
use rand::{rngs::OsRng, RngCore};
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


fn gen_zkevm_circuit1_snark(params: &ParamsKZG<Bn256>) -> aggregation::Snark {
    
    let circuit = zkevm_circuit1::gen_pi_circuit(OsRng.next_u64());

    let pk = gen_pk(params, &circuit);
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg().with_num_instance(
            <PiTestCircuit::<
                Fr,
                { zkevm_circuit1::MAX_TXS },
                { zkevm_circuit1::MAX_CALLDATA },
            > as zkevm_circuit1::InstancesExport>::num_instance()
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

fn load_zkevm_circuit1_snark_from_calldata(
    params: &ParamsKZG<Bn256>,
    proof_data: ProofData,
) -> aggregation::Snark {
    
    let circuit = zkevm_circuit1::gen_pi_circuit(OsRng.next_u64());
    
    let call_data = proof_data.call_data;
    let num_instance = <PiTestCircuit::<
        Fr,
        { zkevm_circuit1::MAX_TXS },
        { zkevm_circuit1::MAX_CALLDATA },
    > as zkevm_circuit1::InstancesExport>::num_instance()[0];

    let instances = vec![(0..num_instance)
        .map(|i| {
            let a = call_data[(i * 32)..(i + 1) * 32].iter().rev().cloned().collect_vec();
            let mut dst = [0u8; 32];
            dst.clone_from_slice(&a);
            Fr::from_bytes(&dst).unwrap()
        })
        .collect_vec()];

    let proof: Vec<u8> = call_data[(num_instance * 32)..].into();

    let vk = keygen_vk(params, &circuit).unwrap();

    let protocol = compile(
        params,
        &vk,
        Config::kzg().with_num_instance(
            <PiTestCircuit::<
                Fr,
                { zkevm_circuit1::MAX_TXS },
                { zkevm_circuit1::MAX_CALLDATA },
            > as zkevm_circuit1::InstancesExport>::num_instance()
        ),
    );

    // test
    let proof_data = ProofData {
        call_data: encode_calldata(&instances, &proof).into()
    };

    File::create("proof1-test.json")
        .expect("open output_file")
        .write_all(&serde_json::to_vec(&proof_data).unwrap())
        .expect("write output_file");

    aggregation::Snark::new(protocol, instances, proof)
}

fn gen_zkevm_circuit2_snark(params: &ParamsKZG<Bn256>) -> aggregation::Snark {
    
    let circuit = zkevm_circuit2::gen_pi_circuit(OsRng.next_u64());

    let pk = gen_pk(params, &circuit);
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg().with_num_instance(
            <PiTestCircuit::<
                Fr,
                { zkevm_circuit2::MAX_TXS },
                { zkevm_circuit2::MAX_CALLDATA },
            > as zkevm_circuit2::InstancesExport>::num_instance()
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

fn load_zkevm_circuit2_snark_from_calldata(
    params: &ParamsKZG<Bn256>,
    proof_data: ProofData,
) -> aggregation::Snark {
    
    let circuit = zkevm_circuit2::gen_pi_circuit(OsRng.next_u64());
    
    let call_data = proof_data.call_data;
    let num_instance = <PiTestCircuit::<
        Fr,
        { zkevm_circuit2::MAX_TXS },
        { zkevm_circuit2::MAX_CALLDATA },
    > as zkevm_circuit2::InstancesExport>::num_instance()[0];

    let instances = vec![(0..num_instance)
        .map(|i| {
            let a = call_data[(i * 32)..(i + 1) * 32].iter().rev().cloned().collect_vec();
            let mut dst = [0u8; 32];
            dst.clone_from_slice(&a);
            Fr::from_bytes(&dst).unwrap()
        })
        .collect_vec()];

    let proof: Vec<u8> = call_data[(num_instance * 32)..].into();

    let vk = keygen_vk(params, &circuit).unwrap();

    let protocol = compile(
        params,
        &vk,
        Config::kzg().with_num_instance(
            <PiTestCircuit::<
                Fr,
                { zkevm_circuit2::MAX_TXS },
                { zkevm_circuit2::MAX_CALLDATA },
            > as zkevm_circuit2::InstancesExport>::num_instance()
        ),
    );

    // test
    let proof_data = ProofData {
        call_data: encode_calldata(&instances, &proof).into()
    };

    File::create("proof2-test.json")
        .expect("open output_file")
        .write_all(&serde_json::to_vec(&proof_data).unwrap())
        .expect("write output_file");

    aggregation::Snark::new(protocol, instances, proof)
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

    File::create("./generated/AggregationVerifier.sol")
        .expect("./generated/AggregationVerifier.sol")
        .write_all(&loader.yul_code().as_bytes())
        .expect("./generated/AggregationVerifier.sol");

    evm::compile_yul(&loader.yul_code())
}

fn export_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
    yul_path: String
) {
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
    aggregation::PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    
    File::create(&yul_path)
        .expect(&yul_path)
        .write_all(&loader.yul_code().as_bytes())
        .expect(&yul_path);
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let calldata_out: Bytes = calldata.clone().into();
    println!("calldata {:x}", calldata_out);
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

#[derive(Serialize, Deserialize, Debug)]
struct ProofData {
    // instances: Vec<U256>,
    // proof: Bytes,
    call_data: Bytes,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(next_line_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // Export Verifier
    ExportVerifier {
        yul_path: String,
    },
    // Gen EVM Circuit1 Proof
    GenCircuit1Proof {
        proof_path: String
    },
    // Gen EVM Circuit2 Proof
    GenCircuit2Proof {
        proof_path: String
    },
    // Gen Aggregated Proof
    GenAggregatedProof {
        proof1_path: String,
        proof2_path: String,
        agg_proof_path: String
    },
}

fn main()  {

    // let timer1 = start_timer!(|| "timer 1"); // 30.101s
    // let (params, params_app) = gen_circuit_params::<0>(22, 17);
    // end_timer!(timer1);

    let cli = Cli::parse();
    match cli.command {

        Some(Commands::ExportVerifier {
            yul_path
        }) => {
            let (params, params_app) = gen_circuit_params::<0>(22, 17);

            let zkevm_snarks = [
                gen_zkevm_circuit1_snark(&params_app),
                gen_zkevm_circuit2_snark(&params_app)
            ];
            let agg_circuit = aggregation::AggregationCircuit::new(&params, zkevm_snarks);
            let pk = gen_pk(&params, &agg_circuit);
            export_evm_verifier(
                &params,
                pk.get_vk(),
                aggregation::AggregationCircuit::num_instance(),
                aggregation::AggregationCircuit::accumulator_indices(),
                yul_path,
            );
        }

        Some(Commands::GenCircuit1Proof {
            proof_path
        }) => {
            let (_, params_app) = gen_circuit_params::<0>(22, 17);

            let snark = gen_zkevm_circuit1_snark(&params_app);
            let proof_data = ProofData {
                call_data: encode_calldata(&snark.instances, &snark.proof).into()
            };

            File::create(proof_path)
                .expect("open output_file")
                .write_all(&serde_json::to_vec(&proof_data).unwrap())
                .expect("write output_file");
        }

        Some(Commands::GenCircuit2Proof {
            proof_path
        }) => {
            let (_, params_app) = gen_circuit_params::<0>(22, 17);

            let snark = gen_zkevm_circuit2_snark(&params_app);
            let proof_data = ProofData {
                call_data: encode_calldata(&snark.instances, &snark.proof).into()
            };

            File::create(proof_path)
                .expect("open output_file")
                .write_all(&serde_json::to_vec(&proof_data).unwrap())
                .expect("write output_file");
        }

        Some(Commands::GenAggregatedProof {
            proof1_path,
            proof2_path,
            agg_proof_path
        }) => {

            let (params, params_app) = gen_circuit_params::<0>(22, 17);

            let mut proof1_buf = String::new();
            File::open(proof1_path)
                .expect("file to open")
                .read_to_string(&mut proof1_buf)
                .expect("read string");
            let proof1_data: ProofData = serde_json::from_str(&*proof1_buf).expect("invalid proof data");
            
            let mut proof2_buf = String::new();
            File::open(proof2_path)
                .expect("file to open")
                .read_to_string(&mut proof2_buf)
                .expect("read string");
            let proof2_data: ProofData = serde_json::from_str(&*proof2_buf).expect("invalid proof data");

            let zkevm_snarks = [
                load_zkevm_circuit1_snark_from_calldata(&params_app, proof1_data),
                load_zkevm_circuit2_snark_from_calldata(&params_app, proof2_data)
            ];
            
            let agg_circuit = aggregation::AggregationCircuit::new(&params, zkevm_snarks);
            let pk = gen_pk(&params, &agg_circuit);
            let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
                &params,
                &pk,
                agg_circuit.clone(),
                agg_circuit.instances(),
            );

            let proof_data = ProofData {
                call_data: encode_calldata(&agg_circuit.instances(), &proof).into()
            };

            File::create(agg_proof_path)
                .expect("open output_file")
                .write_all(&serde_json::to_vec(&proof_data).unwrap())
                .expect("write output_file");
        
        }

        None => {

            let (params, params_app) = gen_circuit_params::<0>(22, 17);
            let timer2 = start_timer!(|| "timer 2"); // 97.902s
            let zkevm_snarks = [(); 4].map(|_| gen_zkevm_circuit1_snark(&params_app));
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
        }

    }

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

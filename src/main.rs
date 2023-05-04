// Taiko using only PI circuit

use ark_std::{end_timer, start_timer};
use bus_mapping::{
    circuit_input_builder::{BuilderClient, CircuitsParams},
    Error,
    rpc::GethClient,
};
use ethers_providers::Http;
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fq, Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
        Circuit, ProvingKey, VerifyingKey
    },
    poly::commitment::{ParamsProver, Params},
    poly::kzg::{
        multiopen::{ProverGWC, VerifierGWC},
        strategy::AccumulatorStrategy,
    },
    poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
    poly::VerificationStrategy,
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use snark_verifier::{
    loader::evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::fs;
use std::rc::Rc;
use std::str::FromStr;
use zkevm_circuits::{
    evm_circuit::witness::block_convert,
    pi_circuit2::{PiCircuit, PiTestCircuit, PublicData},
    util::SubCircuit,
};

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

pub fn write_params(degree: usize, params: &ParamsKZG<Bn256>) -> Result<(), std::io::Error> {
    let dir = "./generated";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/srs-{}", dir, degree);
    let mut file = fs::File::create(&path).unwrap_or_else(|_| panic!("create {}", &path));
    params.write(&mut file)
}

pub fn read_params(degree: usize) -> Result<ParamsKZG<Bn256>, std::io::Error> {
    let dir = "./generated";
    let path = format!("{}/srs-{}", dir, degree);
    let mut file = fs::File::open(&path)?;
    ParamsKZG::<Bn256>::read(&mut file)
}

pub fn get_circuit_params<const D: usize>(degree: usize) -> ParamsKZG<Bn256> {
    let mut params = if let Ok(params) = read_params(degree) {
        params
    } else {
        let params = ParamsKZG::<Bn256>::setup(degree as u32, OsRng);
        write_params(degree, &params).expect("write srs ok");
        params
    };

    if D > 0 {
        params.downsize(D as u32);
    }
    params
}

trait InstancesExport {
    fn num_instance() -> Vec<usize>;

    fn instances(&self) -> Vec<Vec<Fr>>;
}

impl<const MAX_TXS: usize, const MAX_CALLDATA: usize> InstancesExport
    for PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA>
{
    fn num_instance() -> Vec<usize> {
        vec![2]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        // vec![vec![self.0]]
        self.0.instance()
    }
}

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

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

fn gen_proof<C: Circuit<Fr>>(
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
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
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
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
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

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub block_gas_limit: usize,
    pub max_txs: usize,
    pub max_calldata: usize,
    pub max_bytecode: usize,
    pub max_rws: usize,
    pub min_k: usize,
    pub pad_to: usize,
    pub min_k_aggregation: usize,
    pub keccak_padding: usize,
}

const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
    block_gas_limit: 6300000,
    max_txs: 10,
    max_calldata: 131072,
    max_bytecode: 131072,
    max_rws: 3161966,
    min_k: 19,
    pad_to: 2097152,
    min_k_aggregation: 26,
    keccak_padding: 336000,
};

async fn gen_data(block_num: u64, address: &str, geth_url: &str) -> Result<PublicData<Fr>, Error> {

    let prover = eth_types::Address::from_slice(
        &hex::decode(address.as_bytes()).expect("parse_address"),
    );

    let provider = Http::from_str(geth_url).expect("Http geth url");
    let geth_client = GethClient::new(provider);

    

    let circuit_params = CircuitsParams {
        max_rws: CIRCUIT_CONFIG.max_rws,
        max_txs: CIRCUIT_CONFIG.max_txs,
        max_calldata: CIRCUIT_CONFIG.max_calldata,
        max_bytecode: CIRCUIT_CONFIG.max_bytecode,
        keccak_padding: Some(CIRCUIT_CONFIG.keccak_padding),
    };

    let builder = BuilderClient::new(geth_client, circuit_params.clone()).await?;
    let (builder, _) = builder.gen_inputs(block_num).await?;
    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    
    Ok(PublicData::new(&block, prover))

}

#[tokio::main]
async fn main() -> Result<(), Error> {

    let (block_num, address, geth_url) = (
        5,
        "E743762B9F3C162E470Ad05e7a51328606f270cf",
        "http://3.132.151.8:8545"
    );

    let public_data = gen_data(block_num, address, geth_url).await?;

    let params = get_circuit_params::<0>(CIRCUIT_CONFIG.min_k as usize);

    let circuit =
        PiTestCircuit::<Fr, { CIRCUIT_CONFIG.max_txs }, { CIRCUIT_CONFIG.max_calldata }>(
            PiCircuit::new(
                CIRCUIT_CONFIG.max_txs,
                CIRCUIT_CONFIG.max_calldata,
                public_data,
            ),
        );

    let pk = keygen_pk(&params, keygen_vk(&params, &circuit).unwrap(), &circuit).unwrap();

    let deployment_code = gen_evm_verifier(
        &params,
        pk.get_vk(),
        PiTestCircuit::<
            Fr,
            { CIRCUIT_CONFIG.max_txs },
            { CIRCUIT_CONFIG.max_calldata },
        >::num_instance()
    );

    let start = start_timer!(|| "EVM circuit Proof verification");
    let proof = gen_proof(&params, &pk, circuit.clone(), circuit.instances());
    end_timer!(start);

    evm_verify(deployment_code, circuit.instances(), proof.clone());

    Ok(())

}

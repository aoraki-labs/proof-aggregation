use eth_types::Word;
use halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::{ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_xorshift::XorShiftRng;
use zkevm_circuits::{
    pi_circuit::{PiCircuit, PiTestCircuit, PublicData},
    util::SubCircuit,
};

// use std::fs;
// use rand::rngs::OsRng;

pub const MAX_TXS: usize = 10;
pub const MAX_CALLDATA: usize = 128;


fn generate_publicdata<const MAX_TXS: usize, const MAX_CALLDATA: usize>() -> PublicData {
    let mut public_data = PublicData::default();
    let chain_id: u64 = mock::MOCK_CHAIN_ID.low_u64();
    public_data.chain_id = Word::from(chain_id);

    let n_tx = MAX_TXS;
    for i in 0..n_tx {
        let eth_tx = eth_types::Transaction::from(mock::CORRECT_MOCK_TXS[i % 4].clone());
        public_data.transactions.push(eth_tx);
    }
    public_data
}

pub fn gen_pi_circuit() -> PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA>{
    
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let randomness = Fr::random(&mut rng);
    let rand_rpi = Fr::random(&mut rng);
    let public_data = generate_publicdata::<MAX_TXS, MAX_CALLDATA>();
    
    let circuit = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>(PiCircuit::<Fr>::new(
        MAX_TXS,
        MAX_CALLDATA,
        randomness,
        rand_rpi,
        public_data,
    ));

    circuit

}

pub trait InstancesExport {
    fn num_instance() -> Vec<usize>;

    fn instances(&self) -> Vec<Vec<Fr>>;
}

impl<const MAX_TXS: usize, const MAX_CALLDATA: usize> InstancesExport
    for PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA>
{
    fn num_instance() -> Vec<usize> {
        vec![5]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        // vec![vec![self.0]]
        self.0.instance()
    }
}


pub fn test_basic_pi_circuit() {

    const MAX_TXS: usize = 10;
    const MAX_CALLDATA: usize = 128;

    let degree: u32 = 19;

    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let randomness = Fr::random(&mut rng);
    let rand_rpi = Fr::random(&mut rng);
    let public_data = generate_publicdata::<MAX_TXS, MAX_CALLDATA>();
    
    let circuit = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>(PiCircuit::<Fr>::new(
        MAX_TXS,
        MAX_CALLDATA,
        randomness,
        rand_rpi,
        public_data,
    ));

    let instances = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>::instances(&circuit);
    let num_instance = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>::num_instance();
    println!("instances {:?}", instances);
    println!("num_instance {:?}", num_instance);


    let public_inputs = circuit.0.instance();
    let instance: Vec<&[Fr]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
        0xbc, 0xe5,
    ]);

    let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    // Initialize the proving key
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
    // Create a proof
    let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA>,
    >(
        &general_params,
        &pk,
        &[circuit],
        instances,
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&general_params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &verifier_params,
        pk.get_vk(),
        strategy,
        instances,
        &mut verifier_transcript,
    )
    .expect("failed to verify circuit");
}


// fn main()  {

//     zkevm_circuit::test_basic_pi_circuit();

// }

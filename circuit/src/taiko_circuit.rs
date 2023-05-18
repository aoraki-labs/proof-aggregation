// Taiko using only PI circuit
use bus_mapping::{
    circuit_input_builder::{BuilderClient, CircuitsParams},
    Error,
    rpc::GethClient,
};
use ethers_providers::Http;
use halo2_proofs::halo2curves::bn256::Fr;
use std::str::FromStr;
use zkevm_circuits::{
    evm_circuit::witness::block_convert,
    pi_circuit2::{PiTestCircuit, PublicData},
    util::SubCircuit,
};

pub const MAX_TXS: usize = 10;
pub const MAX_CALLDATA: usize = 131072;
pub const MAX_BYTECODE: usize = 131072;
pub const MAX_RWS: usize = 3161966;
const KECCAK_PADDING: usize = 336000;

pub trait InstancesExport {
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

pub(crate) async fn gen_data(block_num: u64, address: &str, geth_url: &str) -> Result<PublicData<Fr>, Error> {

    let prover = eth_types::Address::from_slice(
        &hex::decode(address.as_bytes()).expect("parse_address"),
    );

    let provider = Http::from_str(geth_url).expect("Http geth url");
    let geth_client = GethClient::new(provider);

    

    let circuit_params = CircuitsParams {
        max_rws: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        keccak_padding: Some(KECCAK_PADDING),
    };

    let builder = BuilderClient::new(geth_client, circuit_params.clone()).await?;
    let (builder, _) = builder.gen_inputs(block_num).await?;
    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    
    Ok(PublicData::new(&block, prover))

}


// #[tokio::main]
// async fn main() -> Result<(), Error> {

//     let (block_num, address, geth_url, degree) = (
//         5,
//         "E743762B9F3C162E470Ad05e7a51328606f270cf",
//         "http://3.132.151.8:8545",
//         19
//     );
//     let public_data = taiko::gen_data(block_num, address, geth_url).await?;

//     let params = get_circuit_params::<0>(degree as usize);

//     let circuit =
//         PiTestCircuit::<Fr, { taiko::MAX_TXS }, { taiko::MAX_CALLDATA }>(
//             PiCircuit::new(
//                 taiko::MAX_TXS,
//                 taiko::MAX_CALLDATA,
//                 public_data,
//             ),
//         );
    
//     let start = start_timer!(|| "EVM circuit Proof verification");
//     let proof = gen_proof(&params, &pk, circuit.clone(), circuit.instances());
//     end_timer!(start);

//     Ok(())

// }

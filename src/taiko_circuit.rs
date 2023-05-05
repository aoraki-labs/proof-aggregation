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

pub(crate) const MAX_TXS: usize = 10;
pub(crate) const MAX_CALLDATA: usize = 131072;
pub(crate) const MAX_BYTECODE: usize = 131072;
pub(crate) const MAX_RWS: usize = 3161966;
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

cargo build --profile release --package proof-aggregation --bin proof-aggregation
cp ./target/release/proof-aggregation .
RUST_BACKTRACE=1 ./proof-aggregation


./proof-aggregation export-verifier AggregatedVerifier.yul

./proof-aggregation gen-circuit1-proof proof1.json
./proof-aggregation gen-circuit2-proof proof2.json
RUST_BACKTRACE=full ./proof-aggregation gen-aggregated-proof proof1.json proof2.json agg.json


export-verifier
gen-circuit1-proof
gen-circuit2-proof
gen-aggregated-proof

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

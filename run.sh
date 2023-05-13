cargo build --profile release --package proof-aggregation --bin proof-aggregation
cp ./target/release/proof-aggregation .
RUST_BACKTRACE=1 ./proof-aggregation


# ./proof-aggregation export-verifier AggregatedVerifier.yul
# ./proof-aggregation gen-circuit1-proof proof1.json
# ./proof-aggregation gen-circuit2-proof proof2.json
# ./proof-aggregation gen-aggregated-proof proof1.json proof2.json agg.json
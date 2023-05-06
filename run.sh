cargo build --profile release --package proof-aggregation --bin proof-aggregation
cp ./target/release/proof-aggregation .
RUST_BACKTRACE=1 ./proof-aggregation
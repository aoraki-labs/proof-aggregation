## Proof Aggregator Demo

This repo demonstrates a basic proof aggregator use case: put multiple proofs into one to reduce onchain verification fee. The idea is from [vitalik's article](https://vitalik.ca/general/2022/09/17/layer_3.html). It comes with an aggregator and two zkevm rollups. Below is a step by step tutorial.

### Preparation

1. compile circuits

```bash
# in circuit folder
cargo build --profile release --package proof-aggregation --bin proof-aggregation
cp ./target/release/proof-aggregation .
```

2. compile contract

```bash
# in contract folder
npm install
npx hardhat compile
```

3. config `contract/.env` to your own key and get some test matic from [mumbai faucet](https://faucet.polygon.technology/)

```bash
# in contract folder
mv .env.example .env
```

### Going Through the Process

1. deploy the aggregator

```bash
# in contract folder
npx hardhat run ./scripts/1_deploy_aggregator.ts --network mumbai
```

2. register rollup1 & rollup2 onchain

```bash
# in contract folder
npx hardhat run ./scripts/2_deploy_and_register_rollups.ts --network mumbai
```

3. export aggregation verifier from circuit

```bash
# in circuit folder
./proof-aggregation export-verifier AggregationVerifier.yul
```

4. set verifier

```bash
# in contract folder
npx hardhat run ./scripts/3_deploy_verifier.ts --network mumbai
```

5. gen proof for rollup1 & rollup2

```bash
# in circuit folder
# gen proof for rollup1
./proof-aggregation gen-circuit1-proof proof1.json
# gen proof for rollup2
./proof-aggregation gen-circuit2-proof proof2.json
```

6. submit proof1 & proof2 onchain

```bash
npx hardhat run ./scripts/4_submit_proofs.ts --network mumbai
```

7. get proof1 and proof2 then gen aggregate proof

```bash
# in circuit folder
./proof-aggregation gen-aggregated-proof proof1.json proof2.json agg.json
```

8. submit aggregated proof

```bash
# in contract folder
npx hardhat run ./scripts/5_submit_batch_proof.ts --network mumbai
```
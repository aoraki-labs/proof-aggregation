cargo build --profile release --package proof-aggregation --bin proof-aggregation

cp ./target/release/proof-aggregation .

export GETH_URL=http://3.132.151.8:8545
export BLOCK_NUM=5
export ADDRESS=E743762B9F3C162E470Ad05e7a51328606f270cf
export TXS=4
export RUST_BACKTRACE=1 # RUST_BACKTRACE=full to see more backtrace in verbose

./proof-aggregation ${GETH_URL} ${BLOCK_NUM} ${ADDRESS}

# Arguments:
#   [GETH_URL]    geth_url
#   [BLOCK_NUM]   block_num
#   [ADDRESS]     prover address
#   [YUL_OUTPUT]  generate yul
#   [OUTPUT]      output_file

# BLOCK_NUM:
# // 1    ETH Transfer
# // 2    Deploy Contract: Greeter
# // 3    Deploy Contract: OpenZeppelinERC20TestToken
# // 4    Fund wallets
# // 5    Multiple ETH Transfers
# // 6    ERC20 OpenZeppelin transfer failed
# // 7    ERC20 OpenZeppelin transfer successful
# // 8    Multiple ERC20 OpenZeppelin transfers

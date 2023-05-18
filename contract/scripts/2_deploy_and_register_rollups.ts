import hre from "hardhat";
import * as utils from "./utils";

async function main() {

    const rollup1Tx = await utils.deployContract(hre, "Rollup1");
    utils.updateContractAddress("Rollup1", rollup1Tx.address);
    console.log("rollup1 address:", rollup1Tx.address);

    const rollup2Tx = await utils.deployContract(hre, "Rollup2");
    utils.updateContractAddress("Rollup2", rollup2Tx.address);
    console.log("rollup2 address:", rollup2Tx.address);

    const Rollup1 = await hre.ethers.getContractFactory("Rollup1");
    const rollup1 = Rollup1.attach(utils.getContractAddress("Rollup1"))
    const tx1 = await rollup1.setAggregator(utils.getContractAddress("Aggregator"));
    const receipt1 = await tx1.wait();
    console.log(receipt1.transactionHash);

    const Rollup2 = await hre.ethers.getContractFactory("Rollup2");
    const rollup2 = Rollup2.attach(utils.getContractAddress("Rollup2"))
    const tx2 = await rollup2.setAggregator(utils.getContractAddress("Aggregator"));
    const receipt2 = await tx2.wait();
    console.log(receipt2.transactionHash);

    const Aggregator = await hre.ethers.getContractFactory("Aggregator");
    const aggregator = Aggregator.attach(
        utils.getContractAddress("Aggregator")
    );
    
    const tx3 = await aggregator.register(
        "Rollup 1",
        rollup1.address,
    );
    const receipt3 = await tx3.wait()
    console.log(receipt3.transactionHash);

    const tx4 = await aggregator.register(
        "Rollup 2",
        rollup2.address,
    );
    const receipt4 = await tx4.wait()
    console.log(receipt4.transactionHash);
}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
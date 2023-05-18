import hre from "hardhat";
import * as utils from "./utils";

import * as fs from 'fs';




async function main() {

    const Aggregator = await hre.ethers.getContractFactory("Aggregator");
    const aggregator = Aggregator.attach(
        utils.getContractAddress("Aggregator")
    );
    
    const proof = utils.readProofCallData("data/agg.json")
    const ids = [0, 1];
    const tx = await aggregator.submit_batch(proof, ids);
    const receipt = await tx.wait()
    console.log(receipt.transactionHash);
    console.log(receipt);
}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
import hre from "hardhat";
import * as utils from "./utils";
import * as fs from 'fs';


async function main() {
    
    
    const Aggregator = await hre.ethers.getContractFactory("Aggregator");
    const aggregator = Aggregator.attach(
        utils.getContractAddress("Aggregator")
    );

    const proof1CallData = utils.readProofCallData("data/proof1.json");
    const tx1 = await aggregator.submit_proof(proof1CallData, 0);
    const receipt1 = await tx1.wait()
    console.log(receipt1.transactionHash);

    const proof2CallData = utils.readProofCallData("data/proof2.json");
    const tx2 = await aggregator.submit_proof(proof2CallData, 0);
    const receipt2 = await tx2.wait()
    console.log(receipt2.transactionHash);
    
}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
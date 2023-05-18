import hre from "hardhat";
import * as utils from "./utils";
import * as fs from 'fs';

async function main() {

    const aggregator = await utils.deployContract(hre, "Aggregator");

    utils.updateContractAddress("Aggregator", aggregator.address);

    console.log("address:", aggregator.address)
}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
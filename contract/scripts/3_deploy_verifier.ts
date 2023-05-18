import hre from "hardhat";
import * as utils from "./utils";

async function main() {
    
    const AggregationVerifierByteCode = utils.compileYulContract(
        "../contracts/AggregationVerifier.yul"
    );

    const verifierAddress = await utils.deployBytecode(
        hre,
        AggregationVerifierByteCode,
        "AggregationVerifier"
    );

    utils.updateContractAddress("AggregationVerifier", verifierAddress);

    console.log("address:", verifierAddress)


    const Aggregator = await hre.ethers.getContractFactory("Aggregator");
    const aggregator = Aggregator.attach(
        utils.getContractAddress("Aggregator")
    );
    const tx = await aggregator.set_verifier(verifierAddress);
    const receipt = await tx.wait()
    console.log(receipt.transactionHash);

}


main()
    .then(() => process.exit(0))
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
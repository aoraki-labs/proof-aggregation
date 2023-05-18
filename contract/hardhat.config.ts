import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import { config as dotEnvConfig } from "dotenv";

dotEnvConfig();

const config: HardhatUserConfig = {
  solidity: "0.8.18",
  defaultNetwork: "mumbai",
  networks: {
    hardhat: {},
    mumbai: {
      url: process.env.API_URL || "",
      accounts: process.env.PRIVATE_KEY !== undefined
          ? [process.env.PRIVATE_KEY]
          : [],
      gas: 9900000,
      gasPrice: 8000000000
    },
  },
  etherscan: {
    apiKey: process.env.POLYGONSCAN_API_KEY,
 },
};

export default config;
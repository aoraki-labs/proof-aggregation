// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
// import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import {IMessageReceiver} from "./IMessageReceiver.sol";

contract Rollup1 is IMessageReceiver, Ownable {
    event Verified(string info);

    address aggregator;

    function setAggregator(address _aggregator) public onlyOwner {
        aggregator = _aggregator;
    }

    function getAggregator() public view returns (address) {
        return aggregator;
    }

    function receiveMessage() public {
        emit Verified("Rollup1 Proof Verified");
    }
}
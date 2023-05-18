// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IMessageReceiver {
    function setAggregator(address) external;
    
    function getAggregator() view external returns (address);
    
    function receiveMessage() external;
}

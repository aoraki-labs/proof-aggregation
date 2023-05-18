// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/access/Ownable.sol";
import {IMessageReceiver} from "./IMessageReceiver.sol";

contract Aggregator is Ownable {

    struct CircuitEndpoint {
        string desc;
        address contractAddress;
    }

    struct Proof {
        bytes proof;
        bool isPending;
        uint256 circitId;
    }
    
    mapping(uint256 => CircuitEndpoint) public circuitEndpoints;
    uint circuitEndpointNum;
    
    mapping(uint256 => Proof) public proofs;
    uint proofNum;

    address verifier;

    function register(
        string memory desc,
        address contractAddress
    ) public {
        // IMessageReceiver(contractAddress).setAggregator(address(this));
        circuitEndpoints[circuitEndpointNum] = CircuitEndpoint(
            desc,
            contractAddress
        );
        circuitEndpointNum += 1;
    }

    function submit_proof(bytes calldata proof, uint circuitId) public {
        proofs[proofNum] = Proof(
            proof,
            true,
            circuitId
        );
        proofNum += 1;
    }

    function set_verifier(address _verifier) public onlyOwner {
        verifier = _verifier;
    }
    
    function submit_batch(
        bytes calldata proof,
        uint[] calldata ids
    ) public returns (bool isCallSuccess, bytes memory response) {
        // Skipped some necessary pre-check.
        (bool _isCallSuccess, bytes memory _response) = verifier.staticcall(proof);
        require(_isCallSuccess, "verifier failed");

        isCallSuccess = _isCallSuccess;
        response = _response;

        // uint lenIds = ids.length;
        // for (uint i = 0; i < lenIds; i ++) {
        //     Proof storage subProof = proofs[ids[i]];
        //     subProof.isPending = false;
        //     IMessageReceiver messageReceiver = IMessageReceiver(
        //         circuitEndpoints[subProof.circitId].contractAddress
        //     );
        //     require(
        //         messageReceiver.getAggregator() == address(this),
        //         "not authorized by receiver"
        //     );
        //     messageReceiver.receiveMessage();
        // }
    }

    function get_status(uint256 proofId) public view returns (bool status) {
        require(proofId < proofNum, "proofId out of bound");
        status = proofs[proofId].isPending;
    }

}

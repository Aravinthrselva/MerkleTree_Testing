// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Whitelist {
    bytes32 public merkleRoot;

//we are not storing the address of each user in the contract, instead, we are only storing the root of the merkle tree which gets initialized in the constructor.

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

function checkInWhitelist(bytes32[] calldata proof, uint64 maxAllowanceToMint) view public returns(bool) {

// maxAllowanceToMint keeps track of the number of NFT's a given address can mint.  
//The value we are actually storing in the Merkle Tree, for this use case, is storing the address of the user along with how many NFTs they are allowed to mint

// The hash of the leaf node on which this address exists can be computed by 
// first encoding the address of the sender and the maxAllowanceToMint into a bytes string
// which further gets passed down to the keccak256 hash function which requires the hash string to generate the hash.  

    bytes32 leaf = keccak256(abi.encode(msg.sender, maxAllowanceToMint));


//we use the OpenZeppelin's MerkleProof library to verify that the proof sent by the user is indeed valid    
    bool verified = MerkleProof.verify(proof, merkleRoot, leaf);
    return verified;
}


}


const {expect} = require ('chai');
const keccak256 = require('keccak256');
const {MerkleTree} = require('merkletreejs');

function encodeLeaf(address, spots) {


  // Same as `abi.encodePacked` in Solidity
  return ethers.utils.defaultAbiCoder.encode(        
    ["address", "uint64"],                            // The datatypes of arguments to encode
    [address, spots]                                  // The actual values
  )
}

describe("Merkle Trees", function() {
  it("should be able to verify if address is in whitelist or not" , async function() {

    // Get a bunch of test addresses
    // Hardhat returns 10 signers when running in a test environment    
    const testAddresses = await ethers.getSigners();

    // Create an array of ABI-encoded elements to put in the Merkle Tree

    const list = [
      encodeLeaf(testAddresses[0].address, 2),
      encodeLeaf(testAddresses[1].address, 2),
      encodeLeaf(testAddresses[2].address, 2),
      encodeLeaf(testAddresses[3].address, 2),
      encodeLeaf(testAddresses[4].address, 2),
      encodeLeaf(testAddresses[5].address, 2),
    ];    

    
    // Using keccak256 as the hashing algorithm, create a Merkle Tree
    // We use keccak256 because Solidity supports it
    // We can use keccak256 directly in smart contracts for verification
    // Make sure to sort the tree so it can be reproduced deterministically each time
  
    const merkleTree = new MerkleTree(list, keccak256, {
      hashLeaves: true, // Hash each leaf using keccak256 to make them fixed-size
      sortPairs: true, // Sort the tree for determinstic output
      sortLeaves: true,
    });

    // Compute the Merkle Root in Hexadecimal
    const root = merkleTree.getHexRoot();

    // Deploy the Whitelist Contract
    const whitelist = await ethers.getContractFactory("Whitelist");
    const whitelistContract = await whitelist.deploy(root);
    await whitelistContract.deployed();

    // Check for valid addresses
    for (let i = 0; i < 6 ; i++) {
    
    // Compute the Merkle Proof for `testAddresses[i]`
    const leaf = keccak256(list[i]);                   // The hash of the node
    const proof = merkleTree.getHexProof(leaf);        // Get the Merkle Proof

    // Connect the current address being tested to the Whitelist contract as the 'caller'.
    // So the contract's `msg.sender` value is equal to the value being checked
    // This is done because our contract uses `msg.sender` as the 'original value' for the address when verifying the Merkle Proof
    
    const connectedWhitelist = await whitelistContract.connect(testAddresses[i]);

    // Verify that the contract can verify the presence of this address
    // in the Merkle Tree using just the Root provided to it

    // By giving it the Merkle Proof and the original values
    // It calculates `address` using `msg.sender`, 
    // and we provide it the number of NFTs that the address can mint ourselves

    const verified = await connectedWhitelist.checkInWhitelist(proof,2);
    expect(verified).to.equal(true);

    }

    // Check for invalid addresses
    const verifiedInvalid = await whitelistContract.checkInWhitelist([], 2);
    expect(verifiedInvalid).to.equal(false);  
  }) 
})

/* 
1. First, we fetch a list of signers from Hardhat - which returns us 10 random addresses by default. 

2. Then we create a list of nodes which are all converted into byte strings using the ethers.utils.defaultAbiCoder.encode, 
which is the equivalent of abi.encodePacked in Solidity to maintain equivalence with the contract we wrote earlier. 

3.  Using the MerkleTree class from merkletreejs we input our list, 
specify our hashing function which is going to be keccak256, 
and set the sorting of nodes to true.
This library takes care of hashing each node and building up a tree structure for us.

4. After we create the Merkle Tree, we get its root by calling the getHexRoot function.

5. We use this root to deploy our Whitelist contract. 

6. After our contract is verified, we can call our checkInWhitelist by providing the proof. 
 We do so for every address we provided in the Merkle Tree, and ensure that the contract is able to verify it

7.This proof is then sent in checkInWhitelist as an argument that further returns a value of true to signify that (owner.address, 2) exists.

*/
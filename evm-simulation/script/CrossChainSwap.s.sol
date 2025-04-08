// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";

import {TEEescrow} from "../src/TEEescrow.sol";
import {DummyERC20} from "../src/DummyERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract CrossChainSwapScript is Script {

    // --- Configuration --- 
    // Replace with actual RPC URLs when running Anvil instances
    string public constant RPC_URL_CHAIN_A = "http://localhost:8545"; // e.g., ETH
    string public constant RPC_URL_CHAIN_B = "http://localhost:8546"; // e.g., OP

    // User Private Keys (replace with actual keys or load from env)
    uint256 public userAPrivateKey = 0x9b2391031a7612fc7003c8fa79b50982471c694892bdc273dd9c379631751a59;
    // Public Key: 0xF38cA7A356584B8ede96615fd09E130A02b8b8c6
    uint256 public userBPrivateKey = 0x5fa022c5fd19412b85af918ea35c48c86e17f5ad55ad275e9336b2d8eeb07ba0; 
    // Public Key: 0x60B162Ba495Ce3E498E805B49f439D0246FC0c07

    // TEE Committee (Use slightly more robust keys)
    uint256 public committeeMember1Pk = 0x100; 
    uint256 public committeeMember2Pk = 0x200;
    uint256 public committeeMember3Pk = 0x300;
    uint256 public threshold = 2;

    // Contract Addresses (will be populated after deployment)
    address public tokenAddrA;
    address public escrowAddrA;
    address public tokenAddrB;
    address public escrowAddrB;

    // Swap Details
    uint256 public constant SWAP_AMOUNT = 100;
    bytes32 public swapId; // Will be generated

    // --- Helper: Get Packed Signature --- 
    // (Duplicated from test for script use - could be moved to a library)
    function _getPackedSignature(uint256 privateKey, bytes32 messageHash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        if (v < 27) { v += 27; }
        return abi.encodePacked(r, s, v);
    }

    // --- Main Script Logic --- 
    function run() external {
        console.log("Starting Cross-Chain Swap Simulation...");

        // == Get Addresses ==
        address userA = vm.addr(userAPrivateKey);
        address userB = vm.addr(userBPrivateKey); // Recipient on Chain B
        address derivedAddr1 = vm.addr(committeeMember1Pk);
        address derivedAddr2 = vm.addr(committeeMember2Pk);
        address derivedAddr3 = vm.addr(committeeMember3Pk);
        address[] memory committee = new address[](3);
        committee[0] = derivedAddr1;
        committee[1] = derivedAddr2;
        committee[2] = derivedAddr3;

        // == Get Actual Chain IDs == 
        // We will use block.chainid after selecting the fork
        // uint256 actualChainAId = vm.rpcUrlChainId(RPC_URL_CHAIN_A); // REMOVED
        // uint256 actualChainBId = vm.rpcUrlChainId(RPC_URL_CHAIN_B); // REMOVED
        // console.log("Detected Chain A ID:", actualChainAId); // REMOVED
        // console.log("Detected Chain B ID:", actualChainBId); // REMOVED

        // == Chain A Setup ==
        console.log("\n--- Setting up Chain A (%s) ---", RPC_URL_CHAIN_A);
        uint256 chainAId = vm.createSelectFork(RPC_URL_CHAIN_A); // Fork ID, might differ from actual ID
        // Ensure the fork's actual ID matches our detected ID (sanity check)
        // require(vm.chainId() == actualChainAId, "Fork Chain A ID mismatch"); // REMOVED
        // uint256 initialActualChainAId = vm.chainId(); // REMOVED
        // console.log("Fork Chain A Actual ID:", initialActualChainAId); // REMOVED

        vm.startBroadcast(userAPrivateKey); // Deployer/User A pays gas on Chain A
        
        console.log("Deploying DummyERC20 on Chain A...");
        tokenAddrA = address(new DummyERC20("TokenA", "TKA", 1_000_000));
        console.log("Token A deployed at:", tokenAddrA);

        console.log("Deploying TEEescrow on Chain A...");
        escrowAddrA = address(new TEEescrow(committee, threshold));
        console.log("Escrow A deployed at:", escrowAddrA);

        // Approve escrow
        DummyERC20(tokenAddrA).approve(escrowAddrA, SWAP_AMOUNT * (10**18)); // Assuming 18 decimals

        vm.stopBroadcast();

        // == Chain B Setup ==
        console.log("\n--- Setting up Chain B (%s) ---", RPC_URL_CHAIN_B);
        uint256 chainBId = vm.createSelectFork(RPC_URL_CHAIN_B); // Fork ID
        // Ensure the fork's actual ID matches our detected ID (sanity check)
        // require(vm.chainId() == actualChainBId, "Fork Chain B ID mismatch"); // REMOVED
        // uint256 initialActualChainBId = vm.chainId(); // REMOVED
        // console.log("Fork Chain B Actual ID:", initialActualChainBId); // REMOVED

        // Use a different deployer/funder for Chain B if needed, or User A again?
        // For simplicity, let User A deploy, but User B will receive funds.
        vm.startBroadcast(userAPrivateKey); 

        console.log("Deploying DummyERC20 on Chain B...");
        tokenAddrB = address(new DummyERC20("TokenB", "TKB", 0)); // No initial supply needed for escrow target
        console.log("Token B deployed at:", tokenAddrB);
        
        console.log("Deploying TEEescrow on Chain B...");
        escrowAddrB = address(new TEEescrow(committee, threshold));
        console.log("Escrow B deployed at:", escrowAddrB);

        // --> Fund Escrow B with enough tokens for the release <--
        DummyERC20(tokenAddrB).mint(escrowAddrB, SWAP_AMOUNT * (10**18)); 
        console.log("Funded Escrow B with required tokens.");

        vm.stopBroadcast();

        // == Execute Swap ==
        console.log("\n--- Executing Swap --- ");
        
        // 1. User A locks tokens on Chain A
        console.log("User A locking funds on Chain A...");
        vm.selectFork(chainAId);
        vm.startBroadcast(userAPrivateKey);
        
        swapId = keccak256(abi.encodePacked("myCrossChainSwap", block.timestamp)); // Generate unique ID
        TEEescrow(escrowAddrA).lock(swapId, userB, tokenAddrA, SWAP_AMOUNT * (10**18), block.timestamp + 3600);
        console.logString("Lock successful on Chain A for swapId:");
        console.logBytes32(swapId);

        vm.stopBroadcast();

        // 2. Simulate TEEs observing and signing for Chain B release
        console.log("Simulating TEE Observation and Signing for Chain B...");
        
        // Select Chain B fork *before* calculating hash
        vm.selectFork(chainBId);
        // uint256 actualChainBId = vm.chainId(); // REMOVED - Use block.chainid directly
        // console.log("Selected Chain B Actual ID (for hashing):", actualChainBId); // REMOVED

        // Note: Chain ID used in hash MUST match the target chain (Chain B)
        // Calculate the raw hash using block.chainid *after* selecting the fork
        // Include token, amount, recipient for RELEASE (sender is address(0))
        bytes32 rawMessageHashB = keccak256(
            abi.encodePacked(
                bytes("RELEASE:"), 
                swapId, 
                escrowAddrB, 
                block.chainid, 
                tokenAddrB, // Use Token B address
                SWAP_AMOUNT * (10**18), 
                userB, // Recipient
                address(0) // Placeholder for sender in RELEASE hash
            )
        );
        console.logString("Raw Hash Payload (Script):");
        console.logBytes32(rawMessageHashB);

        // Apply the standard Ethereum signed message prefix
        bytes32 prefixedMessageHashB = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rawMessageHashB));
        console.logString("Prefixed Hash (Script):");
        console.logBytes32(prefixedMessageHashB);

        // Sign the *prefixed* hash
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, prefixedMessageHashB);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, prefixedMessageHashB); // Need sig from member 2
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);

        // 3. Relayer (or User A/B) calls release on Chain B
        console.log("Relayer calling release on Chain B...");
        // vm.selectFork(chainBId); // No need to select again
        // Use a different key if simulating a separate relayer
        vm.startBroadcast(userAPrivateKey); 

        // Call release with all required parameters
        TEEescrow(escrowAddrB).release(
            swapId, 
            tokenAddrB, 
            SWAP_AMOUNT * (10**18), 
            userB, 
            combinedSigs
        );
        console.log("Release successful on Chain B.");

        vm.stopBroadcast();

        // == Verification ==
        console.log("\n--- Verifying Final State --- ");
        
        // Check Chain A balances
        vm.selectFork(chainAId);
        uint256 userABalanceA = IERC20(tokenAddrA).balanceOf(userA);
        uint256 escrowABalanceA = IERC20(tokenAddrA).balanceOf(escrowAddrA);
        console.log("Chain A - User A Balance:", userABalanceA / (10**18));
        console.log("Chain A - Escrow A Balance:", escrowABalanceA / (10**18));
        // Add assertions here

        // Check Chain B balances
        vm.selectFork(chainBId);
        uint256 userBBalanceB = IERC20(tokenAddrB).balanceOf(userB);
        uint256 escrowBBalanceB = IERC20(tokenAddrB).balanceOf(escrowAddrB);
        console.log("Chain B - User B Balance:", userBBalanceB / (10**18)); 
        console.log("Chain B - Escrow B Balance:", escrowBBalanceB / (10**18));
        // Add assertions here - User B should have SWAP_AMOUNT
        require(userBBalanceB == SWAP_AMOUNT * (10**18), "User B balance mismatch on Chain B");

        console.log("\nCross-Chain Swap Simulation Complete.");
    }
} 
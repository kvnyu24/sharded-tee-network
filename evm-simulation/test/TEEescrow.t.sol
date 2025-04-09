// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdError} from "forge-std/StdError.sol";

import {TEEescrow} from "../src/TEEescrow.sol";
import {DummyERC20} from "../src/DummyERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TEEescrowTest is Test {
    TEEescrow public escrow;
    DummyERC20 public token;

    address public user1 = vm.addr(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);
    address public user2 = makeAddr("user2"); // Represents recipient on the other "chain"

    // --- Use real Anvil keys --- 
    address public committeeMember1; // Address derived in setUp
    address public committeeMember2;
    address public committeeMember3;
    uint256 public committeeMember1Pk = 0x59c6995e998f97a5300194dc6916aa8c096e6d7d7f81a78f05791c43177926b8;
    uint256 public committeeMember2Pk = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 public committeeMember3Pk = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    address[] public committee; // Populated in setUp
    uint256 public threshold = 2;
    // ---

    uint256 public constant INITIAL_SUPPLY = 1_000_000;
    uint256 public constant LOCK_AMOUNT = 100;

    function setUp() public {
        // Deploy contracts
        token = new DummyERC20("Dummy Token", "DUM", INITIAL_SUPPLY);

        // Set up committee using addresses derived from real private keys
        committeeMember1 = vm.addr(committeeMember1Pk);
        committeeMember2 = vm.addr(committeeMember2Pk);
        committeeMember3 = vm.addr(committeeMember3Pk);
        committee.push(committeeMember1);
        committee.push(committeeMember2);
        committee.push(committeeMember3);

        // Deploy escrow with committee and threshold
        escrow = new TEEescrow(committee, threshold);

        // Mint initial supply to user1
        // The deployer of DummyERC20 (this test contract) gets the initial supply
        vm.startPrank(address(this));
        token.transfer(user1, token.balanceOf(address(this)));
        vm.stopPrank();

        console.log("User1 initial balance:", token.balanceOf(user1));
        assertEq(token.balanceOf(user1), INITIAL_SUPPLY * (10**token.decimals()));
    }

    function testLock() public {
        bytes32 swapId = keccak256(abi.encodePacked("testLockSwap", block.timestamp));

        // User1 approves escrow to spend tokens
        vm.startPrank(user1);
        token.approve(address(escrow), LOCK_AMOUNT * (10**token.decimals()));
        console.log("User1 approved escrow for:", token.allowance(user1, address(escrow)));

        // User1 locks tokens
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        vm.stopPrank();

        // Check balances
        assertEq(token.balanceOf(user1), (INITIAL_SUPPLY - LOCK_AMOUNT) * (10**token.decimals()));
        assertEq(token.balanceOf(address(escrow)), LOCK_AMOUNT * (10**token.decimals()));

        // Check lock state
        (bytes32 lockSwapId, address sender, address recipient, address tokenAddr, uint256 amount, uint256 unlockTime, bool released, bool aborted) = escrow.locks(swapId);
        assertEq(lockSwapId, swapId);
        assertEq(sender, user1);
        assertEq(recipient, user2);
        assertEq(tokenAddr, address(token));
        assertEq(amount, LOCK_AMOUNT * (10**token.decimals()));
        assertEq(released, false);
        assertEq(aborted, false);
    }

    // Helper function to reduce stack depth
    function _getPackedSignature(uint256 privateKey, bytes32 messageHash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        // Ensure v is 27 or 28
        if (v < 27) {
            v += 27;
        }
        return abi.encodePacked(r, s, v);
    }

    function testRelease() public {
        bytes32 swapId = keccak256(abi.encodePacked("testReleaseSwap", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());

        // --- Setup: Lock tokens first ---
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();
        // --- End Setup ---

        assertEq(token.balanceOf(user1), (INITIAL_SUPPLY - LOCK_AMOUNT) * (10**token.decimals()));
        assertEq(token.balanceOf(address(escrow)), lockAmountDecimals);
        assertEq(token.balanceOf(user2), 0);

        // --- Simulate TEE signing (need threshold=2 signatures) ---
        bytes32 messageHash = escrow._hashTEEDecisionMessage(
            swapId, 
            true, // commit = true for RELEASE
            address(token), 
            lockAmountDecimals, 
            user2, // recipient
            address(0) // sender N/A for RELEASE
        );

        // Get packed signatures using helper
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, messageHash);

        // Combine signatures
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);
        console.log("Combined sigs length (Release Test):", combinedSigs.length);
        // --- End Simulation ---

        escrow.release(
            swapId, 
            address(token), 
            lockAmountDecimals, 
            user2, // recipient
            combinedSigs
        );

        // Check balances after release
        assertEq(token.balanceOf(user1), (INITIAL_SUPPLY - LOCK_AMOUNT) * (10**token.decimals()));
        assertEq(token.balanceOf(address(escrow)), 0);
        assertEq(token.balanceOf(user2), lockAmountDecimals);

        // Check lock state via locks mapping (we expect released to be false here)
        (,,,,,, bool released, bool aborted) = escrow.locks(swapId);
        assertEq(released, false, "Lock struct 'released' flag should NOT be set by release fn");
        assertEq(aborted, false, "Lock should not be marked aborted");
        // Check finalized state via isFinalized mapping
        assertEq(escrow.isFinalized(swapId), true, "Swap should be finalized");
    }

    function testAbort() public {
        bytes32 swapId = keccak256(abi.encodePacked("testAbortSwap", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());

        // --- Setup: Lock tokens first ---
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();
        // --- End Setup ---

        assertEq(token.balanceOf(user1), (INITIAL_SUPPLY - LOCK_AMOUNT) * (10**token.decimals()));
        assertEq(token.balanceOf(address(escrow)), lockAmountDecimals);
        assertEq(token.balanceOf(user2), 0);

         // --- Simulate TEE signing (need threshold=2 signatures) ---
        bytes32 messageHash = escrow._hashTEEDecisionMessage(
            swapId, 
            false, // commit = false for ABORT
            address(token), 
            lockAmountDecimals, 
            address(0), // recipient N/A for ABORT
            user1 // sender
        );

        // Get packed signatures using helper
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, messageHash);

        // Combine signatures
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);
        console.log("Combined sigs length (Abort Test):", combinedSigs.length);
        // --- End Simulation ---

        escrow.abort(
            swapId, 
            address(token),
            lockAmountDecimals, 
            user1, // sender
            combinedSigs
        );

        // Check balances after abort
        assertEq(token.balanceOf(user1), INITIAL_SUPPLY * (10**token.decimals())); // Back to initial
        assertEq(token.balanceOf(address(escrow)), 0);
        assertEq(token.balanceOf(user2), 0);

        // Check lock state via locks mapping (8 fields in Lock struct)
        (,,,,,, bool released, bool aborted) = escrow.locks(swapId); // 6 commas for 8 fields
        assertEq(released, false, "Lock should not be marked released");
        assertEq(aborted, true, "Lock should be marked aborted");
        // Check finalized state via isFinalized mapping
        assertEq(escrow.isFinalized(swapId), true, "Swap should be finalized");
    }

    // --- Test Failure Cases ---

    function test_RevertIf_ReleaseAlreadyReleased() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailRelease1", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // First release needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs1);
        assertEq(escrow.isFinalized(swapId), true, "First release should finalize"); 

        // Use try/catch for debugging
        bool caughtExpectedRevert = false;
        try escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs1) {
            // If it didn't revert, fail the test
            fail();
        } catch Error(string memory reason) {
             // This shouldn't happen for custom errors
            console.log("Caught unexpected Error(string):", reason);
            fail();
        } catch Panic(uint256 /*errorCode*/) {
            // This shouldn't happen either
            fail();
        } catch (bytes memory lowLevelData) {
            // Check if the lowLevelData matches our expected custom error
            bytes4 expectedSelector = bytes4(keccak256("AlreadyFinalized()"));
            bytes4 actualSelector;
            
            // Check if lowLevelData is exactly 4 bytes (the selector)
            if (lowLevelData.length == 4) {
                // Directly convert the bytes to bytes4
                actualSelector = bytes4(lowLevelData);
            } else {
                // Handle cases where data might be longer or shorter (though typically just selector for simple errors)
                console.log("Caught lowLevelData with unexpected length:", lowLevelData.length, "Data:", vm.toString(lowLevelData));
                // You might choose to fail here or attempt extraction differently if needed
                // For now, set actualSelector to something that won't match
                actualSelector = bytes4(0x00000000);
            }
            
            if (actualSelector == expectedSelector) {
                console.log("Caught expected AlreadyFinalized() revert.");
                caughtExpectedRevert = true;
            } else {
                console.log("Caught unexpected selector:", vm.toString(abi.encodePacked(actualSelector)), "Expected:", vm.toString(abi.encodePacked(expectedSelector)));
                console.log("Raw lowLevelData:", vm.toString(lowLevelData));
                fail();
            }
        }
        assertTrue(caughtExpectedRevert, "Did not catch the expected AlreadyFinalized() revert");
    }

    function test_RevertIf_AbortAlreadyReleased() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailAbort1", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // First release needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs1);
        assertEq(escrow.isFinalized(swapId), true, "Release should finalize"); 

        // Prepare abort signatures (even though we expect revert before check)
        bytes32 messageHashAbort = escrow._hashTEEDecisionMessage(swapId, false, address(token), lockAmountDecimals, address(0), user1);
        bytes memory sigAbort1 = _getPackedSignature(committeeMember1Pk, messageHashAbort);
        bytes memory sigAbort2 = _getPackedSignature(committeeMember2Pk, messageHashAbort);
        bytes memory combinedSigsAbort = abi.encodePacked(sigAbort1, sigAbort2);

        bool caughtExpectedRevert = false;
        try escrow.abort(swapId, address(token), lockAmountDecimals, user1, combinedSigsAbort) {
            fail(); // Should have reverted
        } catch Error(string memory reason) {
            console.log("Caught unexpected Error(string):", reason);
            fail();
        } catch Panic(uint256 /*errorCode*/) {
            fail();
        } catch (bytes memory lowLevelData) {
            bytes4 expectedSelector = bytes4(keccak256("AlreadyFinalized()"));
            bytes4 actualSelector;
            if (lowLevelData.length == 4) {
                actualSelector = bytes4(lowLevelData);
            } else {
                console.log("Caught lowLevelData with unexpected length:", lowLevelData.length, "Data:", vm.toString(lowLevelData));
                actualSelector = bytes4(0x00000000);
            }
            if (actualSelector == expectedSelector) {
                console.log("Caught expected AlreadyFinalized() revert.");
                caughtExpectedRevert = true;
            } else {
                console.log("Caught unexpected selector:", vm.toString(abi.encodePacked(actualSelector)), "Expected:", vm.toString(abi.encodePacked(expectedSelector)));
                console.log("Raw lowLevelData:", vm.toString(lowLevelData));
                fail();
            }
        }
        assertTrue(caughtExpectedRevert, "Did not catch the expected AlreadyFinalized() revert");
    }

    function test_RevertIf_ReleaseAlreadyAborted() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailRelease2", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // First abort needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, false, address(token), lockAmountDecimals, address(0), user1);
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.abort(swapId, address(token), lockAmountDecimals, user1, combinedSigs1);
        assertEq(escrow.isFinalized(swapId), true, "Abort should finalize");

        // Prepare release signatures
        bytes32 messageHashRelease = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sigRelease1 = _getPackedSignature(committeeMember1Pk, messageHashRelease);
        bytes memory sigRelease2 = _getPackedSignature(committeeMember2Pk, messageHashRelease);
        bytes memory combinedSigsRelease = abi.encodePacked(sigRelease1, sigRelease2);

        bool caughtExpectedRevert = false;
        try escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigsRelease) {
            fail(); // Should have reverted
        } catch Error(string memory reason) {
            console.log("Caught unexpected Error(string):", reason);
            fail();
        } catch Panic(uint256 /*errorCode*/) {
            fail();
        } catch (bytes memory lowLevelData) {
            bytes4 expectedSelector = bytes4(keccak256("AlreadyFinalized()"));
            bytes4 actualSelector;
            if (lowLevelData.length == 4) {
                actualSelector = bytes4(lowLevelData);
            } else {
                console.log("Caught lowLevelData with unexpected length:", lowLevelData.length, "Data:", vm.toString(lowLevelData));
                actualSelector = bytes4(0x00000000);
            }
            if (actualSelector == expectedSelector) {
                console.log("Caught expected AlreadyFinalized() revert.");
                caughtExpectedRevert = true;
            } else {
                console.log("Caught unexpected selector:", vm.toString(abi.encodePacked(actualSelector)), "Expected:", vm.toString(abi.encodePacked(expectedSelector)));
                console.log("Raw lowLevelData:", vm.toString(lowLevelData));
                fail();
            }
        }
         assertTrue(caughtExpectedRevert, "Did not catch the expected AlreadyFinalized() revert");
    }

     function test_RevertIf_AbortAlreadyAborted() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailAbort2", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // First abort needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, false, address(token), lockAmountDecimals, address(0), user1);
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.abort(swapId, address(token), lockAmountDecimals, user1, combinedSigs1);
        assertEq(escrow.isFinalized(swapId), true, "First abort should finalize"); 

        bool caughtExpectedRevert = false;
        try escrow.abort(swapId, address(token), lockAmountDecimals, user1, combinedSigs1) {
            fail(); // Should have reverted
        } catch Error(string memory reason) {
            console.log("Caught unexpected Error(string):", reason);
            fail();
        } catch Panic(uint256 /*errorCode*/) {
            fail();
        } catch (bytes memory lowLevelData) {
            bytes4 expectedSelector = bytes4(keccak256("AlreadyFinalized()"));
            bytes4 actualSelector;
            if (lowLevelData.length == 4) {
                actualSelector = bytes4(lowLevelData);
            } else {
                console.log("Caught lowLevelData with unexpected length:", lowLevelData.length, "Data:", vm.toString(lowLevelData));
                actualSelector = bytes4(0x00000000);
            }
            if (actualSelector == expectedSelector) {
                console.log("Caught expected AlreadyFinalized() revert.");
                caughtExpectedRevert = true;
            } else {
                console.log("Caught unexpected selector:", vm.toString(abi.encodePacked(actualSelector)), "Expected:", vm.toString(abi.encodePacked(expectedSelector)));
                console.log("Raw lowLevelData:", vm.toString(lowLevelData));
                fail();
            }
        }
        assertTrue(caughtExpectedRevert, "Did not catch the expected AlreadyFinalized() revert");
    }

     function test_RevertIf_LockSwapIdExists() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailLock1", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), 2 * LOCK_AMOUNT * (10**token.decimals())); // Approve enough
        // First lock succeeds
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);

        bool caughtCorrectError_LSIE = false;
        try escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600) {
            fail(); // Should have reverted
        } catch Error(string memory reason) {
            // Check if the reason matches the expected require string
            // Use the EXACT string from the contract
            if (keccak256(bytes(reason)) == keccak256(bytes("Swap ID already used for lock on this chain"))) { 
                 caughtCorrectError_LSIE = true;
            } else {
                console.log("test_RevertIf_LockSwapIdExists: Caught unexpected string revert:", reason);
                fail();
            }
        } catch (bytes memory /* lowLevelData */) {
            // Should not catch a custom error here
            fail();
        }
        assertTrue(caughtCorrectError_LSIE, "Did not catch correct require string");
        vm.stopPrank();
    }

     function test_RevertIf_LockInsufficientAllowance() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailLock2", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), (LOCK_AMOUNT - 1) * (10**token.decimals())); // Approve less than needed

        // Expect revert due to transferFrom failing using try...catch
        // vm.expectRevert(); // Catch any revert from deeper call (transferFrom)
        // escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        bool caughtRevert_LIA = false;
        try escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600) {
            fail(); // Should have reverted
        } catch {
            // Any revert caught here is considered success for this test
            caughtRevert_LIA = true;
        }
        assertTrue(caughtRevert_LIA, "Expected revert from transferFrom but none occurred");
        vm.stopPrank();
    }

    // --- New Tests for Signature Verification (Phase 3, Step 6) ---

    function test_RevertIf_ReleaseInsufficientSignatures() public {
        bytes32 swapId = keccak256(abi.encodePacked("testInsuffSigRel", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        // Setup: Lock
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // Generate only 1 signature (threshold is 2)
        bytes32 messageHash = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        // Note: combinedSigs only contains sig1
        bytes memory combinedSigs = sig1;

        // Expect revert due to insufficient valid signatures
        // The require message in release() is "Invalid TEE signature for RELEASE"
        vm.expectRevert(bytes("Invalid TEE signature for RELEASE"));
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs);
    }

    function test_RevertIf_ReleaseInvalidSignature_WrongMessage() public {
        bytes32 swapId = keccak256(abi.encodePacked("testWrongMsgRel", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        // Setup: Lock
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // Generate signatures for a *different* message (e.g., wrong swapId)
        bytes32 wrongSwapId = keccak256("wrongSwapId");
        bytes32 wrongMessageHash = escrow._hashTEEDecisionMessage(wrongSwapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, wrongMessageHash);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, wrongMessageHash);
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);

        // Expect revert because signatures don't match the *correct* message for the release call
        vm.expectRevert(bytes("Invalid TEE signature for RELEASE"));
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs);
    }

    function test_RevertIf_ReleaseInvalidSignature_NonMember() public {
        bytes32 swapId = keccak256(abi.encodePacked("testNonMemberRel", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        // Setup: Lock
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // Generate 1 valid sig + 1 sig from a non-member
        bytes32 messageHash = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        uint256 nonMemberPk = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        address nonMemberAddr = vm.addr(nonMemberPk);
        assertFalse(escrow.isCommitteeMemberAddress(nonMemberAddr), "Addr should not be committee member"); // Use getter
        bytes memory sigNonMember = _getPackedSignature(nonMemberPk, messageHash);
        bytes memory combinedSigs = abi.encodePacked(sig1, sigNonMember);

        // Expect revert because only 1 valid signature is provided (threshold 2)
        vm.expectRevert(bytes("Invalid TEE signature for RELEASE"));
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs);
    }

     function test_RevertIf_ReleaseDuplicateSignatures() public {
        bytes32 swapId = keccak256(abi.encodePacked("testDupSigRel", block.timestamp));
        uint256 lockAmountDecimals = LOCK_AMOUNT * (10**token.decimals());
        // Setup: Lock
        vm.startPrank(user1);
        token.approve(address(escrow), lockAmountDecimals);
        escrow.lock(swapId, user2, address(token), lockAmountDecimals, block.timestamp + 3600);
        vm.stopPrank();

        // Generate 1 valid signature and duplicate it
        bytes32 messageHash = escrow._hashTEEDecisionMessage(swapId, true, address(token), lockAmountDecimals, user2, address(0));
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        bytes memory combinedSigs = abi.encodePacked(sig1, sig1); // Duplicate sig1

        // Expect revert because only 1 unique valid signature is provided
        vm.expectRevert(bytes("Invalid TEE signature for RELEASE"));
        escrow.release(swapId, address(token), lockAmountDecimals, user2, combinedSigs);
    }
} 
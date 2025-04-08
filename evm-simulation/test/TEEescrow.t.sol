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

    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2"); // Represents recipient on the other "chain"

    // --- Dummy TEE Committee Setup ---
    address public committeeMember1 = makeAddr("committee1");
    address public committeeMember2 = makeAddr("committee2");
    address public committeeMember3 = makeAddr("committee3");
    uint256 public committeeMember1Pk = 0x123;
    uint256 public committeeMember2Pk = 0x456; // Add key for member 2
    uint256 public committeeMember3Pk = 0x789; // Add key for member 3
    address[] public committee;
    uint256 public threshold = 2;
    // ---

    uint256 public constant INITIAL_SUPPLY = 1_000_000;
    uint256 public constant LOCK_AMOUNT = 100;

    function setUp() public {
        // Deploy contracts
        token = new DummyERC20("Dummy Token", "DUM", INITIAL_SUPPLY);

        // Set up committee using addresses derived from private keys
        address derivedAddr1 = vm.addr(committeeMember1Pk);
        address derivedAddr2 = vm.addr(committeeMember2Pk);
        address derivedAddr3 = vm.addr(committeeMember3Pk);
        committee.push(derivedAddr1);
        committee.push(derivedAddr2);
        committee.push(derivedAddr3);

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
        bytes32 messageHash = escrow._hashTEEDecisionMessage(swapId, true);

        // Get packed signatures using helper
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, messageHash);

        // Combine signatures
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);
        console.log("Combined sigs length (Release Test):", combinedSigs.length);
        // --- End Simulation ---

        escrow.release(swapId, combinedSigs);

        // Check balances after release
        assertEq(token.balanceOf(user1), (INITIAL_SUPPLY - LOCK_AMOUNT) * (10**token.decimals()));
        assertEq(token.balanceOf(address(escrow)), 0);
        assertEq(token.balanceOf(user2), lockAmountDecimals);

        // Check lock state
        (, , , , , , bool released, bool aborted) = escrow.locks(swapId); // Only need released/aborted state here
        assertEq(released, true);
        assertEq(aborted, false);
        assertEq(escrow.teeDecisions(swapId), true); // Check TEE decision state
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
        bytes32 messageHash = escrow._hashTEEDecisionMessage(swapId, false); // false for ABORT

        // Get packed signatures using helper
        bytes memory sig1 = _getPackedSignature(committeeMember1Pk, messageHash);
        bytes memory sig2 = _getPackedSignature(committeeMember2Pk, messageHash);

        // Combine signatures
        bytes memory combinedSigs = abi.encodePacked(sig1, sig2);
        console.log("Combined sigs length (Abort Test):", combinedSigs.length);
        // --- End Simulation ---

        escrow.abort(swapId, combinedSigs);

        // Check balances after abort
        assertEq(token.balanceOf(user1), INITIAL_SUPPLY * (10**token.decimals())); // Back to initial
        assertEq(token.balanceOf(address(escrow)), 0);
        assertEq(token.balanceOf(user2), 0);

        // Check lock state
        (, , , , , , bool released, bool aborted) = escrow.locks(swapId); // Only need released/aborted state here
        assertEq(released, false);
        assertEq(aborted, true);
        assertEq(escrow.teeDecisions(swapId), false); // Check TEE decision state
    }

    // --- Test Failure Cases ---

    function test_RevertIf_ReleaseAlreadyReleased() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailRelease1", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), LOCK_AMOUNT * (10**token.decimals()));
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        vm.stopPrank();

        // First release needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, true);
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.release(swapId, combinedSigs1);

        // Revert back to vm.expectRevert
        vm.expectRevert(TEEescrow.AlreadyDecided.selector);
        escrow.release(swapId, combinedSigs1); // Pass same sigs again, check should hit first
    }

    function test_RevertIf_AbortAlreadyReleased() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailAbort1", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), LOCK_AMOUNT * (10**token.decimals()));
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        vm.stopPrank();

        // First release needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, true);
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.release(swapId, combinedSigs1);

        // Revert back to vm.expectRevert
         vm.expectRevert(TEEescrow.AlreadyDecided.selector);
         escrow.abort(swapId, combinedSigs1); // Pass same sigs again, check should hit first
    }

    function test_RevertIf_ReleaseAlreadyAborted() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailRelease2", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), LOCK_AMOUNT * (10**token.decimals()));
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        vm.stopPrank();

        // First abort needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, false); // false for abort
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.abort(swapId, combinedSigs1);

        // Revert back to vm.expectRevert
        vm.expectRevert(TEEescrow.AlreadyDecided.selector);
        escrow.release(swapId, combinedSigs1); // Pass same sigs again, check should hit first
    }

     function test_RevertIf_AbortAlreadyAborted() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailAbort2", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), LOCK_AMOUNT * (10**token.decimals()));
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        vm.stopPrank();

        // First abort needs valid signatures
        bytes32 messageHash1 = escrow._hashTEEDecisionMessage(swapId, false); // false for abort
        bytes memory sig1_1 = _getPackedSignature(committeeMember1Pk, messageHash1);
        bytes memory sig1_2 = _getPackedSignature(committeeMember2Pk, messageHash1);
        bytes memory combinedSigs1 = abi.encodePacked(sig1_1, sig1_2);
        escrow.abort(swapId, combinedSigs1);

        // Revert back to vm.expectRevert
        vm.expectRevert(TEEescrow.AlreadyDecided.selector);
        escrow.abort(swapId, combinedSigs1); // Pass same sigs again, check should hit first
    }

     function test_RevertIf_LockSwapIdExists() public {
        bytes32 swapId = keccak256(abi.encodePacked("testFailLock1", block.timestamp));
        vm.startPrank(user1);
        token.approve(address(escrow), 2 * LOCK_AMOUNT * (10**token.decimals())); // Approve enough
        // First lock succeeds
        escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);

        // Expect revert on second lock with same ID using try...catch
        // vm.expectRevert(stdError.assertionError);
        // escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600);
        bool caughtCorrectError_LSIE = false;
        try escrow.lock(swapId, user2, address(token), LOCK_AMOUNT * (10**token.decimals()), block.timestamp + 3600) {
            fail(); // Should have reverted
        } catch Error(string memory reason) {
            // Check if the reason matches the expected require string
            if (keccak256(bytes(reason)) == keccak256(bytes("Swap ID already used"))) {
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
} 
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {console} from "forge-std/console.sol";

/**
 * @title TEEescrow
 * @notice Escrow contract managed by TEE threshold signatures.
 * Allows locking on one chain and releasing/aborting on another based on TEE decision.
 */
contract TEEescrow {
    // --- Original Lock Struct (Only relevant on the locking chain) ---
    struct Lock {
        bytes32 swapId; // Unique identifier for the swap
        address sender;
        address recipient;
        address token;
        uint256 amount;
        uint256 unlockTime; // Placeholder for timeout logic
        bool released; // Only relevant on the locking chain
        bool aborted; // Only relevant on the locking chain
    }

    // Mapping from swap ID to the lock details (only populated on locking chain)
    mapping(bytes32 => Lock) public locks;

    // Explicitly track if a swap ID has been used for a lock *on this chain*
    mapping(bytes32 => bool) public swapLockedOnThisChain;

    // --- State relevant for cross-chain release/abort ---
    // Tracks if a swap has been finalized (released or aborted) *on this chain*
    mapping(bytes32 => bool) public isFinalized;
    // Tracks which TEE members signed which decision *for this chain*
    mapping(bytes32 => mapping(address => bool)) private signedReleaseOnThisChain;
    mapping(bytes32 => mapping(address => bool)) private signedAbortOnThisChain;


    // --- TEE Committee Info ---
    address[] public committeeAddresses;
    uint256 public immutable signatureThreshold;
    mapping(address => bool) internal isCommitteeMember; // For efficient lookup
    // Removed per-swap signer tracking from here, moved into release/abort logic specific maps


    event Locked(bytes32 indexed swapId, address indexed sender, address indexed recipient, address token, uint256 amount);
    event Released(bytes32 indexed swapId, address indexed recipient, address token, uint256 amount); // Added token
    event Aborted(bytes32 indexed swapId, address indexed sender, address token, uint256 amount); // Added token

    error InvalidTEESignature();
    error SwapNotFoundOnThisChain(); // More specific error for lock-related checks
    error AlreadyFinalized(); // Changed from AlreadyDecided
    error AlreadySigned();
    error InvalidSignatureData();

    constructor(address[] memory _committeeAddresses, uint256 _signatureThreshold) {
        require(_committeeAddresses.length >= _signatureThreshold, "Threshold > committee size");
        require(_signatureThreshold > 0, "Threshold cannot be 0");

        committeeAddresses = _committeeAddresses;
        signatureThreshold = _signatureThreshold;
        for (uint i = 0; i < _committeeAddresses.length; i++) {
            require(_committeeAddresses[i] != address(0), "Committee member cannot be zero address");
            require(!isCommitteeMember[_committeeAddresses[i]], "Duplicate committee member");
            isCommitteeMember[_committeeAddresses[i]] = true;
        }
    }

    // --- Getter Functions ---
    
    /**
     * @notice Checks if a given address is part of the TEE committee.
     */
    function isCommitteeMemberAddress(address _addr) public view returns (bool) {
        return isCommitteeMember[_addr];
    }

    // --- Core Logic ---

    /**
     * @notice Locks tokens for a swap *on this chain*.
     * @dev This is called on the source chain. Sender must approve this contract.
     */
    function lock(bytes32 swapId, address recipient, address token, uint256 amount, uint256 unlockTime) public {
        require(!swapLockedOnThisChain[swapId], "Swap ID already used for lock on this chain");

        IERC20 tokenContract = IERC20(token);
        require(tokenContract.transferFrom(msg.sender, address(this), amount), "Token transfer failed");

        locks[swapId] = Lock({
            swapId: swapId,
            sender: msg.sender,
            recipient: recipient,
            token: token,
            amount: amount,
            unlockTime: unlockTime,
            released: false,
            aborted: false
        });

        swapLockedOnThisChain[swapId] = true; // Mark swap as locked *on this chain*

        emit Locked(swapId, msg.sender, recipient, token, amount);
    }

   /**
     * @notice Releases tokens *on this chain* based on a TEE threshold signature.
     * @dev Called on the destination chain. Does not require a prior lock *on this chain*.
     * @param swapId The unique swap ID.
     * @param token The address of the token to release.
     * @param amount The amount of the token to release.
     * @param recipient The address to receive the released tokens.
     * @param teeSignatures Tightly packed threshold signatures from TEE committee members.
     */
    function release(
        bytes32 swapId,
        address token,
        uint256 amount,
        address recipient,
        bytes memory teeSignatures
    ) public {
        // Check if this swap has already been finalized (released or aborted) on *this chain*
        if (isFinalized[swapId]) {
            revert AlreadyFinalized();
        }

        // --- TEE Signature Verification ---
        require(
            _verifyTEESignature(swapId, true, token, amount, recipient, address(0), teeSignatures),
            "Invalid TEE signature for RELEASE"
        );
        // --- End Verification ---

        // Mark as finalized *on this chain*
        isFinalized[swapId] = true;

        // Perform the token transfer
        IERC20 tokenContract = IERC20(token);
        // Note: This contract instance needs to hold the tokens being released.
        // In a real scenario, this might be a mint call if it's a wrapped token,
        // or a transfer from a pool managed by this contract.
        // For simulation with DummyERC20, we assume this contract was pre-funded or can mint.
        // --> We need to adjust the script to pre-fund Escrow B or use mintable token <--
        require(tokenContract.transfer(recipient, amount), "Token release transfer failed");

        emit Released(swapId, recipient, token, amount);
    }

    /**
     * @notice Aborts a swap *on this chain* and returns tokens to the sender based on a TEE threshold signature.
     * @dev Called on the source chain after a failure/timeout. Does require a prior lock *on this chain* to know where to return funds.
     * @param swapId The unique swap ID.
     * @param token The address of the token involved (must match lock).
     * @param amount The amount of the token involved (must match lock).
     * @param sender The original sender to return tokens to (must match lock).
     * @param teeSignatures Tightly packed threshold signatures from TEE committee members.
     */
      function abort(
        bytes32 swapId,
        address token,
        uint256 amount,
        address sender,
        bytes memory teeSignatures
    ) public {
        // Abort typically happens on the *source* chain where the lock exists.
        // Check if the lock exists *on this chain*.
        if (!swapLockedOnThisChain[swapId]) {
            revert SwapNotFoundOnThisChain(); // Cannot abort if never locked here
        }
        Lock storage currentLock = locks[swapId];

        // Check if already finalized *on this chain* (either released locally or aborted)
        // Also check the lock struct's status just in case (belt and suspenders)
        if (isFinalized[swapId] || currentLock.released || currentLock.aborted) {
            revert AlreadyFinalized();
        }

        // Validate that the parameters match the original lock
        require(currentLock.token == token, "Abort: Token mismatch");
        require(currentLock.amount == amount, "Abort: Amount mismatch");
        require(currentLock.sender == sender, "Abort: Sender mismatch");

        // --- TEE Signature Verification ---
        // Note: recipient address is not relevant for ABORT hash/verification
        require(
            _verifyTEESignature(swapId, false, token, amount, address(0), sender, teeSignatures),
             "Invalid TEE signature for ABORT"
        );
        // --- End Verification ---

        // Mark as finalized *on this chain*
        isFinalized[swapId] = true;
        currentLock.aborted = true; // Also update the lock struct status

        // Perform the token transfer back to the original sender
        IERC20 tokenContract = IERC20(token);
        require(tokenContract.transfer(sender, amount), "Token abort transfer failed");

        emit Aborted(swapId, sender, token, amount);
    }


    /**
     * @notice Verifies the TEE threshold signature for a given decision.
     * @dev Recovers signers from packed signatures and checks against committee and threshold.
     * @param _swapId The swap ID being decided.
     * @param _commit True for RELEASE, false for ABORT.
     * @param _token The token address involved.
     * @param _amount The amount involved.
     * @param _recipient The recipient address (for RELEASE).
     * @param _sender The sender address (for ABORT).
     * @param _signatures The aggregated signature payload (tightly packed 65-byte ECDSA signatures).
     * @return bool True if the signature threshold is met by valid committee members.
     */
    function _verifyTEESignature(
        bytes32 _swapId,
        bool _commit,
        address _token,
        uint256 _amount,
        address _recipient, // Only relevant for RELEASE hash
        address _sender,    // Only relevant for ABORT hash
        bytes memory _signatures
    ) internal view returns (bool) { // Remains view as it doesn't modify *storage*
        bytes32 messageHash = _hashTEEDecisionMessage(_swapId, _commit, _token, _amount, _recipient, _sender);
        console.logString("Verifying Hash:"); console.logBytes32(messageHash);

        uint256 requiredSigs = signatureThreshold;
        uint256 validSigCount = 0;
        uint256 signaturesLen = _signatures.length;

        if (signaturesLen == 0 || signaturesLen % 65 != 0) {
            revert InvalidSignatureData();
        }
        uint256 numSigsProvided = signaturesLen / 65;

        // Use a memory array to track signers counted *within this specific call*
        address[] memory countedSignersInThisCall = new address[](numSigsProvided); // Max size needed
        uint countedSignerIndex = 0; // Keep track of actual count

        for (uint i = 0; i < numSigsProvided; i++) {
            bytes memory sig = new bytes(65);
            for (uint j = 0; j < 65; j++) {
                sig[j] = _signatures[i * 65 + j];
            }

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(sig, 0x20))
                s := mload(add(sig, 0x40))
                v := byte(0, mload(add(sig, 0x60)))
            }
            if (v < 27) { v += 27; }
            if (v != 27 && v != 28) { continue; } 

            address signer = ecrecover(messageHash, v, r, s);
            bool isMember = isCommitteeMember[signer];

            console.logString(" Signer:"); console.logAddress(signer);
            console.logString(" IsMember:"); console.logBool(isMember);

            if (signer != address(0) && isMember) {
                // Check if this signer has already been counted in *this call*
                bool alreadyCounted = false;
                for (uint k = 0; k < countedSignerIndex; k++) { // Only check up to the current index
                    if (countedSignersInThisCall[k] == signer) {
                        alreadyCounted = true;
                        break;
                    }
                }

                console.logString(" AlreadyCountedLocally:"); console.logBool(alreadyCounted);

                if (!alreadyCounted) {
                    // Add to our temporary list for this call
                    countedSignersInThisCall[countedSignerIndex] = signer;
                    countedSignerIndex++;
                    
                    // Increment the valid count
                    validSigCount++;

                    if (validSigCount >= requiredSigs) {
                        return true; // Threshold reached
                    }
                }
            } 
        }
        console.logString("Threshold check: Valid="); console.logUint(validSigCount); console.logString("Required="); console.logUint(requiredSigs);
        return false; // Threshold not reached
    }

     /**
     * @notice Hashes the TEE decision message including all relevant parameters.
     * @dev Ensures TEEs sign over the exact details of the action.
     */
    function _hashTEEDecisionMessage(
        bytes32 _swapId,
        bool _commit,
        address _token,
        uint256 _amount,
        address _recipient, // Use address(0) if N/A
        address _sender     // Use address(0) if N/A
    ) public view returns (bytes32) {
        bytes memory prefix = _commit ? bytes("RELEASE:") : bytes("ABORT:");
        bytes32 payloadHash = keccak256(
                abi.encodePacked(prefix, _swapId, address(this), block.chainid, _token, _amount, _recipient, _sender)
            );

        // Log components inside contract for debugging
        // console.log("--- Contract Hash Components ---");
        // console.logBytes(prefix);
        // console.logBytes32(_swapId);
        // console.logAddress(address(this));
        // console.logUint(block.chainid);
        // console.logAddress(_token);
        // console.logUint(_amount);
        // console.logAddress(_recipient);
        // console.logAddress(_sender);
        // console.logBytes32(payloadHash); // Log hash before prefix

        // Apply the standard Ethereum signed message prefix
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
        // console.logBytes32(prefixedHash); // Log hash after prefix
        // console.log("------------------------------");

        return prefixedHash;
    }
} 
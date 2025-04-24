// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/ResourceLock.sol";
import "../contracts/WETH.sol";
import "../contracts/USDT.sol";
import "../contracts/XETH.sol";

/// Ethereum deployment script
contract Deploy is Script {
    function run() external {
        uint256 sk = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        vm.startBroadcast(sk);
        ResourceLock rl = new ResourceLock();
        WETH weth = new WETH();
        USDT usdt = new USDT();

        address alice = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        address bob = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

        weth.transfer(address(rl), 300e18);
        weth.transfer(address(rl), 300e18);
        usdt.transfer(address(rl), 300e8);

        rl.setBalance(address(weth), alice, 300e18);
        rl.setBalance(address(usdt), bob, 300e8);
        vm.stopBroadcast();
    }
}

/// Solana deployment script
contract Deploy2 is Script {
    function run() external {
        uint256 sk = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        vm.startBroadcast(sk);
        ResourceLock rl = new ResourceLock();
        XETH xeth = new XETH();

        // Random private key during initialization
        address vault = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;

        xeth.transfer(address(rl), 300e18);
        rl.setBalance(address(xeth), vault, 300e18);
        vm.stopBroadcast();
    }
}

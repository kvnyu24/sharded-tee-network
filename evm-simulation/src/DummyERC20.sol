// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title DummyERC20
 * @notice Basic ERC20 token for testing purposes.
 */
contract DummyERC20 is ERC20 {
    constructor(string memory name, string memory symbol, uint256 initialSupply) ERC20(name, symbol) {
        _mint(msg.sender, initialSupply * (10**decimals()));
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
} 
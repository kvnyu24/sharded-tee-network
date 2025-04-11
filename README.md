# Teeshard Network

## Overview

This repository contains the implementation of the Teeshard Network protocol, a system designed for secure and potentially decentralized operations, likely involving cross-chain interactions, leveraging Trusted Execution Environments (TEEs) and consensus mechanisms. The system integrates off-chain protocol logic (Rust) with on-chain smart contracts (Solidity/EVM).

The core components include:

*   **Teeshard Protocol:** The main Rust implementation handling TEE logic (simulated), Raft consensus, networking, sharding, and on-chain interactions.
*   **EVM Simulation:** Solidity smart contracts (e.g., `TEEescrow`, `DummyERC20`) for on-chain state management and interaction points, developed using the Foundry framework.
*   **Experiments:** A Rust crate likely used for running simulations, benchmarks, and end-to-end tests of the integrated system.

## Repository Structure

```
.
├── Cargo.lock          # Rust workspace lock file
├── Cargo.toml          # Rust workspace definition
├── README.md           # This file
├── evm-simulation/     # Foundry project for EVM smart contracts
│   ├── src/            # Solidity contract source (.sol)
│   ├── test/           # Solidity tests (.t.sol)
│   ├── script/         # Solidity scripts (.s.sol)
│   ├── foundry.toml    # Foundry configuration
│   └── ...
├── experiments/        # Rust crate for running simulations/tests
│   ├── src/            # Experiment source code (main.rs)
│   ├── Cargo.toml      # Experiment dependencies
│   └── ...
├── foundry.toml        # Workspace-level Foundry config (if any)
├── target/             # Rust build artifacts (ignored)
├── teeshard-protocol/  # Core Rust protocol implementation
│   ├── src/            # Rust library source code
│   │   ├── raft/       # Raft consensus implementation
│   │   ├── tee_logic/  # TEE-related logic (signing, proofs, crypto sim)
│   │   ├── onchain/    # On-chain interaction logic (EvmRelayer)
│   │   ├── network/    # P2P networking simulation
│   │   ├── liveness/   # Node liveness detection (challenger/aggregator)
│   │   ├── simulation/ # Simulation framework components (runtime, nodes)
│   │   ├── shard_manager.rs # Sharding logic
│   │   └── ...
│   ├── tests/          # Rust integration tests
│   └── Cargo.toml      # Protocol library dependencies
└── ...                 # Git config, etc.
```

## Prerequisites

Before building or testing, ensure you have the following installed:

*   **Rust & Cargo:** Follow the official installation guide: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
*   **Foundry:** Required for Solidity contract compilation, testing, and scripting. Follow the installation guide: [https://book.getfoundry.sh/getting-started/installation](https://book.getfoundry.sh/getting-started/installation)
    *   This includes `forge`, `cast`, and `anvil`.
*   **Git:** For cloning the repository and managing potential submodules.

## Building

*   **Rust Components:** Build the entire workspace or individual crates using Cargo:
    ```bash
    # Build the entire workspace (including teeshard-protocol and experiments)
    cargo build

    # Build only the teeshard-protocol library
    cargo build -p teeshard-protocol

    # Build only the experiments executable
    cargo build -p experiments
    ```
*   **Solidity Contracts:** Build the smart contracts using Foundry:
    ```bash
    cd evm-simulation
    forge build
    cd ..
    ```

## Running Tests

*   **Rust Unit & Integration Tests:** Run tests for specific crates:
    ```bash
    # Run tests for the teeshard-protocol crate
    cargo test -p teeshard-protocol

    # Run tests for the experiments crate (if any defined)
    cargo test -p experiments
    ```
*   **Solidity Contract Tests:** Run Forge tests:
    ```bash
    cd evm-simulation
    forge test
    cd ..
    ```
*   **End-to-End Tests (Requires Anvil):** The tests within `teeshard-protocol/tests/` (like `full_protocol_e2e_test.rs`, `e2e_swap_test.rs`) require running local Anvil instances.
    1.  **Start Anvil Instances:** Open two separate terminals and run:
        ```bash
        # Terminal 1 (Chain A)
        anvil --port 8545 --chain-id 1

        # Terminal 2 (Chain B)
        anvil --port 8546 --chain-id 10
        ```
    2.  **Run Specific E2E Test:** Execute the desired test using `cargo test`. Ensure the test uses the correct RPC URLs (e.g., `http://localhost:8545`, `http://localhost:8546`).
        ```bash
        # Example: Run the full E2E test
        cargo test -p teeshard-protocol --test full_protocol_e2e_test -- --nocapture

        # Example: Run the coordinator-relayer swap test
        cargo test -p teeshard-protocol --test e2e_swap_test -- --nocapture
        ```
        *(Note: `-- --nocapture` allows viewing `println!` output from tests.)*

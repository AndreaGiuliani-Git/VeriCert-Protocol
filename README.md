# VeriCert Protocol
## Overview

**VeriCert Protocol** explores the integration of **Self-Sovereign Identity (SSI)** principles into the **Public Key Infrastructure (PKI)** to enhance security, transparency, and privacy in digital identity management.

The protocol combines:
- **Decentralized Identifiers (DIDs)**
- **Smart Contracts**
- **Blockchain Technology**

to provide a decentralized and auditable framework for managing digital identities and certificates, with a specific focus on **Certificate Transparency** and **Verifiable Presentations (VPs)** during the TLS handshake.

## Architecture & Concepts

- **DIDs** follow the W3C specification in the format:  
  `did:ethr:<identifier>`
- **DID lifecycle and resolution** are handled via:
  - A custom DID resolver based on `did-resolver`
  - Smart contract `SSLBlockchainReg.sol`
- **Blockchain layer**:
  - Ethereum-compatible
  - Used to ensure transparency and integrity of certificate-related operations
- **Performance evaluation**:
  - Measurement of VP exchange and verification overhead during TLS handshakes between client and server

## Technologies Used

- JavaScript
- Solidity
- Node.js (tested with **Node.js 17**)
- Truffle
- Ganache
- Ethereum
- Decentralized Identity Foundation (DIF) libraries:
  - `did-resolver`
  - `did-jwt`
  - `did-jwt-vc`

## Prerequisites

Make sure the following tools are installed:

- Node.js v17
- npm
- Truffle
- Ganache

Install project dependencies:

```bash
npm install
```
## Installation & Local Testing
This project is intended for local experimentation and performance evaluation.
- Start a Local Blockchain
  - Launch a Ganache instance.
- Deploy Smart Contracts
  - Update deployment configuration:
    ```bash
    workdir/truffle-config.js
    ```
  - Deploy the contracts:
    ```bash
      truffle migrate
    ```
- Configure the Application
  - Edit the configuration file:
    ```bash
      workdir/config.json
    ```
  - Update:
    Smart contract address
    Mnemonic
    Provider URL
    Paths for performance CSV files under perfFiles
- Run the Experiment
Open two separate terminals.
  - Terminal 1 – Server:
    ```bash
    node ./scr/appServer.js VP
    ```
  - Terminal 2 – Client:
    ```bash
    node ./scr/appClient.js VP
    ```
The scripts simulate VP exchange during the TLS handshake and store performance metrics in CSV format.

## Performance Metrics
The following metrics are collected:
- VP generation time
- VP verification time
- End-to-end TLS handshake latency
- Cryptographic operation overhead
- Communication delay
Results are saved as CSV files for offline analysis.

## Use Cases
- Research on SSI–PKI integration
- Academic experiments on decentralized identity
- Performance benchmarking of VC/VP systems
- Certificate Transparency via blockchain
- Secure digital identity management

## Limitations & Future Work
Currently tested only in a local Ganache environment
- Not optimized for production-scale deployments
- No formal security proofs included
- Future work may include:
  - Deployment on public Ethereum networks
  - Advanced credential revocation mechanisms
  - Hardware-backed key management
  - Formal security and performance analysis

## License
This project is licensed under the MIT License.
See the `LICENSE` file for more information.


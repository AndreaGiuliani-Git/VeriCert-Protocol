# VeriCert Protocol

## Overview
The VeriCert Protocol explores the integration of Self-Sovereign Identity (SSI) principles into the Public Key Infrastructure (PKI) to enhance security and privacy in digital identity management. This protocol leverages decentralized identifiers (DIDs), smart contracts, and blockchain technology to provide a robust and transparent framework for managing digital identities and certificates.

### Prerequisites
This software is written in JavaScript and Solidity. For the smart contract, it can be run using Node.js 17. The project complies with other standard libraries of the Decentralized-Identity Foundation DIF ([GitHub](https://github.com/decentralized-identity)) such as did-resolver, did-jwt, did-jwt-vc.
DIDs used in this project are managed by the contract `SSLBlockchainReg.sol`, a smart contract designed for deployment in the Ethereum blockchain to provide Certificate Transparency for clients in the digital domain. DIDs are compliant with the W3C specification for decentralized identifiers in the format "did:ethr:identifier". DID resolution is implemented via a custom module based on the did-resolver library.
1. Install *Node.js*, *Truffle* and *Ganache* from npm.
2. Run **npm install** from the working directory to install project dependencies.

### Installation
The provided code primarily aims to acquire performance metrics of Verifiable Presentations (VPs) exchange and verification between a web server and a client during the TLS handshake. Below is the guide for local testing with Ganache:
1. Generate an instance of Ganache blockchain.
2. Deploy the smart contract on this blockchain by modifying values in `workdir/truffle-config.js` and executing the command **truffle migrate**.
3. In `workdir/config.json`, update values regarding contract address, mnemonic, and provider URL for your development environment.
4. Create CSV files to store performance metrics, following path names specified in `workdir/config.json` under *perfFiles*.
5. Execute in two different shells **node ./scr/appServer.js VP** and **node ./scr/appClient.js VP** from the workdir.

### License
Distributed under the MIT License. See LICENSE for more information.

### Contact
- **Author:** AndreaGiuliani-Git
- **Email:** andregiuliani986@gmail.com
- **Date:** 2024-05-30

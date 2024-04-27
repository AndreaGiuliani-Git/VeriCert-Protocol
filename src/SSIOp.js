/* 
 * -------------------------------------------------------
 * Core operations module for the SSIprotocol, It must
 * be imported by both client and server. There are 
 * functions to handle the contract, the provider 
 * and the DID generation.
 * -------------------------------------------------------
*/
const myResolver = require("./ethr-did-resolver.js")
const config = require('../config.json')
const { ec } = require('elliptic') // ECDSA
const ecCurve = new ec('secp256k1')
const {ethers} = require("ethers")
const Web3HttpProvider = require('web3-providers-http')
const contractABI = require("../build/contracts/SSLBlockchainReg.json").abi
const hdkey = require('hdkey')
const bip39 = require('bip39')
const fs = require('fs').promises
const fsConst = require('fs').constants
const crypto = require('crypto')
const { keccak256 } = require('ethereumjs-util')
const { exec } = require('child_process')
const { Network, Alchemy, Utils, Contract, Wallet } = require('alchemy-sdk')

let contract = null
let provider = null
const mnemonic = config.ganache.mnemonic
let wallets = []
let pubKeyRA = null

class DIDSubject {
    constructor(did, id, wallet, revkWallet) {
        this.did = did
        this.identifier = id
        this.wallet = wallet
        this.revkWallet = revkWallet
    }
}

async function initGanache() {
    try {
        //Setup provider
        const web3provider = await new Web3HttpProvider(config.ganache.providerURL)
        provider = new ethers.providers.Web3Provider(web3provider)

        //Truffle private keys import
        for (let i = 0; i < 10; i++) {
            const ganachePrivateKey = await getTrufflePrivateKey(mnemonic, i)
            wallets[i] = new ethers.Wallet(ganachePrivateKey, provider)
        }

        //Setup contract, resolver and Registration Authority public key
        contract = new ethers.Contract(config.ganache.registry, contractABI, provider)
        myResolver.setContProv(contract, provider);
        resolverEthr = myResolver.getResolver().ethr;
        pubKeyRA = ecCurve.keyFromPublic(await fs.readFile(config.settings.pubKeyRAPath, 'utf-8'), 'hex')
        
        return Promise.resolve()
    } catch (error) {
        return Promise.reject(error)
    }
}

async function initSepolia() {
    try {
        //Setup provider
        const settings = {
            apiKey: "",
            network: Network.ETH_SEPOLIA,
        };

        provider = new Alchemy(settings);
        
        //----------------------------------WALLETS FOR CLIENT-SERVER TEST----------------------------
        // wallets[0] = new Wallet(config.sepolia.privKey1, provider) //Server1 wallet
        // wallets[1] = new Wallet(config.sepolia.privKey2, provider)
        // wallets[2] = new Wallet(config.sepolia.privKey3, provider) //Server2 wallet 

        //----------------------------------WALLETS FOR REVOKE TEST-----------------------------------
        wallets[0] = new Wallet(config.sepolia.privKey1, provider)
        wallets[1] = new Wallet(config.sepolia.privKey2, provider)
        wallets[2] = new Wallet(config.sepolia.privKey3, provider)
        wallets[3] = new Wallet(config.sepolia.privKey4, provider)
        wallets[4] = new Wallet(config.sepolia.privKey5, provider)
        wallets[5] = new Wallet(config.sepolia.privKey6, provider)
        wallets[6] = new Wallet(config.sepolia.privKey7, provider)
        wallets[7] = new Wallet(config.sepolia.privKey8, provider)
        wallets[8] = new Wallet(config.sepolia.privKey9, provider)
        wallets[9] = new Wallet(config.sepolia.privKey10, provider)
        
        //Setup contract, resolver and Registration Authority public key
        contract = new Contract(config.sepolia.registry, contractABI, wallets[1])
        
        myResolver.setContProv(contract, provider);
        resolverEthr = myResolver.getResolver().ethr;
        pubKeyRA = ecCurve.keyFromPublic(await fs.readFile(config.settings.pubKeyRAPath, 'utf-8'), 'hex')
        
        return Promise.resolve()
    } catch (error) {
        return Promise.reject(error)
    }
}

async function getTrufflePrivateKey(mnemonic, index) {
    if (index < 0 || index > 9) throw new Error('please provide correct truffle account index')
    try {
        const seed = await bip39.mnemonicToSeed(mnemonic)
        const hdk = hdkey.fromMasterSeed(seed)
        const addr_node = hdk.derive(`m/44'/60'/0'/0/${index}`)
        return addr_node.privateKey
    } catch (error) {
        return console.log('getTrufflePrivateKey ERROR : ' + error)
    }
}

async function getWallet(index) {
    return wallets[index]
}

function getRApubKey() {
    return pubKeyRA
}

function getContractInstance() {
    return contract
}

function getProviderInstance() {
    return provider
}

async function createDID(mainWallet, revkWallet) {
    
    const id = mainWallet._signingKey().compressedPublicKey
    const did = `did:ethr:${config.sepolia.net}:${id}`
    return new DIDSubject(did, id, mainWallet, revkWallet)
}

async function newEntry(DIDObj, secretHash) {
    try {
        const startTime = performance.now();
        const tx = await contract.connect(DIDObj.wallet).newDID(DIDObj.identifier, secretHash, DIDObj.revkWallet.address)
        const receipt = await tx.wait()
        const newEntryTime = parseFloat((performance.now() - startTime).toFixed(2))

        const cost = ethers.utils.formatEther(receipt.gasUsed.mul(receipt.effectiveGasPrice))
        const csvRow = `${newEntryTime},${cost}\n`
        fs.appendFile(config.perfFiles.newEntryPerf, csvRow)

    } catch (error) {
        console.log("Error:", error);
    }
}


/*Function to update registry entry in multiple conditions, represented by command value:
 *1. CERT --> it updates only the certificate hash value in the registry
 *2. RA_SIGNATURE --> it updates only the RA signature in the registry
*/
async function updateEntry(command, DIDObj, certHash, dsRA) {
    try {
        switch (command) {
            case 'CERT':
                if(certHash.length > 1) {
                    const startTime = performance.now();
                    const tx = await contract.connect(DIDObj.wallet).updateEntry(DIDObj.identifier, certHash, [])
                    const receipt = await tx.wait()
                    const updTime = parseFloat((performance.now() - startTime).toFixed(2))

                    const cost = ethers.utils.formatEther(receipt.gasUsed.mul(receipt.effectiveGasPrice))
                    const csvRow = `${"CERTIFICATE"},${updTime},${cost}\n`
                    fs.appendFile(config.perfFiles.updEntryPerf, csvRow)
                    break;
                }
                throw new Error('CERT command without certificate hash value')
            case 'RA_SIGNATURE':
                if(dsRA.length > 1) {
                    const startTime = performance.now();
                    const tx = await contract.connect(DIDObj.wallet).updateEntry(DIDObj.identifier, [], dsRA)
                    const receipt = await tx.wait()
                    const updTime = parseFloat((performance.now() - startTime).toFixed(2))

                    const cost = ethers.utils.formatEther(receipt.gasUsed.mul(receipt.effectiveGasPrice))
                    const csvRow = `${"RA_SIGNATURE"},${updTime},${cost}\n`
                    fs.appendFile(config.perfFiles.updEntryPerf, csvRow)
                    break;
                }
                throw new Error('RA_SIGNATURE command without signature value')
            default:
                throw new Error('Invalid command')
        }
    } catch (error) {
        console.log("Error:", error)
    }
}

async function revokeDID(DIDObj, oldSecret) {
    try {
        const startTime = performance.now();
        const tx = await contract.connect(DIDObj.revkWallet).revokeDID(DIDObj.identifier, oldSecret)
        const receipt = await tx.wait()
        const revokeTime = performance.now() - startTime;

        const cost = ethers.utils.formatEther(receipt.gasUsed.mul(receipt.effectiveGasPrice))
        console.log("Time for revoke:" + revokeTime + "-------> ETHs spent:" + cost)
    } catch (error) {
        console.log("Error:", error)
    }
}

function requestSignatureRA(commName, DIDObj) {
    return new Promise(async (resolve, reject) => {
        try {
            let imporPrivKey = await fs.readFile(config.settings.privKeyRAPath, 'utf-8')
            let privKeyRA = ecCurve.keyFromPrivate(imporPrivKey, 'hex')
            let signature = privKeyRA.sign(commName + DIDObj.did)
            resolve(signature)
        } catch(error) {
            reject(error)
        }
    })
}

async function crtVerify() {

    return new Promise((resolve, reject) => {
        const opensslCommand = `openssl verify -CAfile ./certChain.pem ./certServer.pem`;
        exec(opensslCommand, async (error, stdout, stderr) => {
            if (stderr) {
                console.log(stderr)
                const regex = /lookup:(.*?)\n/
                const match = regex.exec(stderr)
                if(match){
                const substring = match[1].trim()
                reject(new Error(substring))
                } else {
                    reject(new Error(stderr))
                }
            } else {
                if (stdout.includes('OK')) {
                    resolve(true)
                } else {
                    resolve(false)
                }
            }
        });
    });
}

async function getSecret(path) {
    const fileName = 'secret.txt'
    return new Promise(async (resolve, reject) => {
        try {
            await fs.access(path + fileName, fsConst.F_OK)
            const hextString = await fs.readFile(path + fileName, 'utf-8')
            const secretHash = '0x' + keccak256(Buffer.from(hextString, 'hex')).toString('hex')
            resolve([hextString, secretHash])
        } catch (error) {
            //No file, creating one
            if (error.code === 'ENOENT') {
    
                const byteLength = Math.ceil(32)
                const randomBuffer = crypto.randomBytes(byteLength)
                const tmpStr = randomBuffer.toString('hex')
                const hexString = tmpStr.slice(0, 64)
                await fs.writeFile(path + fileName, hexString)
                const secretHash = '0x' + keccak256(Buffer.from(hexString, 'hex')).toString('hex')
                resolve([hexString, secretHash])
            } else {
                console.error('Error:', error.message);
                reject(error);
            }
        }
    });
}


/* 
 * ---------------------------------------------
 * PERFORMANCE EVALUATION FUNCTIONS
 * ---------------------------------------------
*/

const writePerf = (flag, CertCommName, verifyVPTime, resultVP, verifyCRTime, resultCRT, RAsignVerTime, verifyCrtTrTime, numInterCA, crtSizeInKB, CRTchainSizeInKB, VPSizeInKB, type) => {
    console.log(CertCommName + " VP checked...")
    if(type == "VP") {
        //CSV row
        try {
            const csvRow = `${flag},${CertCommName},${verifyVPTime},${resultVP},${verifyCRTime},${resultCRT},${RAsignVerTime},${verifyCrtTrTime},${numInterCA},${crtSizeInKB},${CRTchainSizeInKB},${VPSizeInKB}\n`
            fs.appendFile(config.perfFiles.verifyVP, csvRow)
        }catch(error) {
            console.error("Error during performance writing:" + error)
        }
    } else {
        //CSV row
        try{
            const csvRow = `${flag},${CertCommName},${verifyCRTime},${resultCRT},${numInterCA},${crtSizeInKB},${CRTchainSizeInKB}\n`
            fs.appendFile(config.perfFiles.verifyCRT, csvRow)
        }catch(error){
            console.error("Error during performance writing:" + error)
        }
    }
}

module.exports = {
    createDID,
    newEntry,
    updateEntry,
    revokeDID,
    initGanache,
    initSepolia,
    requestSignatureRA,
    crtVerify,
    getSecret,
    getWallet,
    writePerf,
    getRApubKey,
    getContractInstance,
    getProviderInstance
}

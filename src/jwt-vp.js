
const ethr = require('./ethr-did-resolver.js')
const {Resolver} = require('did-resolver')
const didJWT = require('did-jwt')
const { createVerifiablePresentationJwt, verifyPresentation} = require('did-jwt-vc')
const { performance } = require('perf_hooks')
const fs = require('fs').promises
const config = require('../config.json')

class EthrDID {
    constructor(DIDObj) {
        this.did = DIDObj.did;
        this.address = DIDObj.wallet.address;
        this.signer = didJWT.ES256KSigner(Buffer.from(DIDObj.wallet._signingKey().privateKey.slice(2), 'hex'), true)
        this.alg = 'ES256K-R';
        this.controller = DIDObj.did;
    }
}

function createVPayload(DIDObj, X509CertChain, commName) {
    const VPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        sub: DIDObj.did,
        vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            credentialSubject: {
                id: commName,
                TLSCertChain: X509CertChain.toString(),
            }
        }
    }
    return VPayload
}

async function verifyPresentationJwtES256Perf(token) {
  return new Promise(async (resolve, reject) => {
    try {
        
        const ethrResolver = ethr.getResolver()
        const MyResolver = new Resolver(ethrResolver)
        
        let start = performance.now()
        const response = await verifyPresentation(token, MyResolver,{})
        let end = performance.now()
        let verifyVPTime = parseFloat((end - start).toFixed(2))
        
        //VP size
        const tokenLengthInBytes = Buffer.byteLength(token, 'utf-8');
        const tokenSizeInKB = parseFloat((tokenLengthInBytes / 1024).toFixed(2));
        
        resolve([response.didResolutionResult.didDocument.id, response.verified, verifyVPTime, tokenSizeInKB, response.payload.vc.credentialSubject])
    } catch(error) {
        console.log(error)
        reject('Error during JWT verification:' + error)
    }
  })
}


async function createPresentationJwtES256Perf(payload, DIDObj) {
    return new Promise(async (resolve, reject) => {
        try {
            const options = {		
                header: {
                    "typ": "JWT",
                    "alg": "ES256K-R"
                },
            }

            let issuer = new EthrDID(DIDObj)
            
            let start = performance.now()
            const vpJwt = await createVerifiablePresentationJwt(payload, issuer, options)
            let end = performance.now()
            let createVPTime = parseFloat((end - start).toFixed(2))

            //JWT size
            const jwtLengthInBytes = Buffer.byteLength(vpJwt, 'utf-8');
            const jwtSizeInKB = parseFloat((jwtLengthInBytes / 1024).toFixed(2));
            
            //CSV row
            const csvRow = `${jwtSizeInKB},${createVPTime}\n`
            fs.appendFile(config.perfFiles.createVP, csvRow)
           
            resolve(vpJwt)
        } catch(error) {
            console.error('Error during JWT generation:', error.message)
        }
    })
}


module.exports = {
    createVPayload,
    verifyPresentationJwtES256Perf,
    createPresentationJwtES256Perf,
}
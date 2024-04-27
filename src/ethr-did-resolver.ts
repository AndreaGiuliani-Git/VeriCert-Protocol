import { DIDDocument, DIDResolutionResult, DIDResolver} from 'did-resolver';
import * as fs from "fs/promises";
const config = require('../config.json')

let contractInstance: {
  [x: string]: any; resolutionDID: (arg0: string) => any 
}

export function getResolver(): Record<string, DIDResolver> {
  async function resolve(did: string): Promise<DIDResolutionResult> {
    let err = null
   
    const startTime = performance.now()
    const tx = await contractInstance.resolutionDID(did.split(":")[3])
    const resolutionTime = parseFloat((performance.now() - startTime).toFixed(2))

    const csvRow = `${resolutionTime}\n`
    fs.appendFile(config.perfFiles.DIDresolutionPerf, csvRow)

    let DID = `did:ethr:${config.sepolia.net}:${tx[0]}`
    let ethrAccount = tx[1]
    const didDocumentMetadata = {}
    let didDocument: DIDDocument | null = null

    do {
      didDocument = {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/secp256k1recovery-2020/v2'
        ],
        id: DID,
        verificationMethod: [
          {
            id: DID + '#controller',
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: DID,
            blockchainAccountId: ethrAccount
          }
        ],
        authentication: [
          DID + '#controller',
        ],
      }

      // TODO: this excludes the use of query params
      const docIdMatchesDid = didDocument?.id === did
      if (!docIdMatchesDid) {
        err = 'resolver_error: DID document id does not match requested did'
        break // uncomment this when adding more checks
      }
      // eslint-disable-next-line no-constant-condition
    } while (false)

    const contentType =
      typeof didDocument?.['@context'] !== 'undefined' ? 'application/did+ld+json' : 'application/did+json'

    if (err) {
      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: {
          error: 'notFound',
          message: err,
        },
      }
    } else {
      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: { contentType },
      }
    }
  }

  return { ethr: resolve }
}

export function setContProv(contract: any, provider: any) {
  contractInstance = contract
}
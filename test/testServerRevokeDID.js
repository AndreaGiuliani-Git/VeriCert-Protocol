/*
 * Testing module for REVOKE DID functionality. It is 
 * mandatory to have at least 5 available accounts on
 * the tested blockchain. 
*/
const { Network, Alchemy, Utils, Contract, Wallet } = require('alchemy-sdk')
const SSIOp = require('../src/SSIOp.js')
let secretArr = []; //Array with secret and secretHash
let servers = [];

(async () => {

    //Init phase for provider
    //await SSIOp.initGanache()
    await SSIOp.initSepolia()
    
    secretArr = await SSIOp.getSecret('../src/secretServer/')
    let contract = await SSIOp.getContractInstance()
    let provider = await SSIOp.getProviderInstance()

    
    //All possible DIDs
    let serverDID0 = await SSIOp.createDID(await SSIOp.getWallet(0), await SSIOp.getWallet(1))
    //servers.push(serverDID0)


    //--------------------------Gas used estimation--------------------------------------------------

    // let RA_sign = await SSIOp.requestSignatureRA("www.google.com", serverDID0)
    // let RA_signStr = "0x" + Buffer.from(RA_sign.toDER()).toString('hex')
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.connect(serverDID0.wallet).newDID("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f", secretArr[1], "0x343183D833F7702A29fB971D64dc7e2E4D355fCa")))
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.connect(serverDID0.wallet).updateEntry("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f", [], RA_signStr)))
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.connect(serverDID0.wallet).updateEntry("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f", "0x9e081b25914c8b88d4c0a83e68b894b61522287a1dde9cc12bd89f6c3b9e11c2", [])))
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.infoCT("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f")))
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.resolutionDID("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f")))
    //console.log(await (await provider.config.getProvider()).estimateGas(await contract.connect(serverDID0.revkWallet).revokeDID("0x0203ae4a97e838de04a8995b79da3a3086f201ffb84274a481989dba29415a0a8f", "0x" + secretArr[0])))
    


    //-----------------------------------Revocation measurments---------------------------------------------
    //await SSIOp.newEntry(serverDID0, secretArr[1])
    // let serverDID1 = await SSIOp.createDID(await SSIOp.getWallet(2), await SSIOp.getWallet(3))
    // servers.push(serverDID1)
    // //await SSIOp.newEntry(serverDID1, secretArr[1])
    // let serverDID2 = await SSIOp.createDID(await SSIOp.getWallet(4), await SSIOp.getWallet(5))
    // servers.push(serverDID2)
    // //await SSIOp.newEntry(serverDID2, secretArr[1])
    // let serverDID3 = await SSIOp.createDID(await SSIOp.getWallet(6), await SSIOp.getWallet(7))
    // servers.push(serverDID3)
    // //await SSIOp.newEntry(serverDID3, secretArr[1])
    // let serverDID4 = await SSIOp.createDID(await SSIOp.getWallet(8), await SSIOp.getWallet(9))
    // servers.push(serverDID4)
    //await SSIOp.newEntry(serverDID4, secretArr[1])

    // await SSIOp.revokeDID(servers[0], "0x" + secretArr[0])
    // await SSIOp.revokeDID(servers[1], "0x" + secretArr[0])
    // await SSIOp.revokeDID(servers[2], "0x" + secretArr[0])
    // await SSIOp.revokeDID(servers[3], "0x" + secretArr[0])
    // await SSIOp.revokeDID(servers[4], "0x" + secretArr[0])


    // await (await provider.config.getProvider()).on("rvkDID", async (revkAddr, id) => {console.log(revkAddr)});
    // let key = false
    // let i = 0
    // while(!key) {
    //     key = true
    //     console.log("------------------------------------------------------------------------------------------")

    //     async function createHandler(DIDObj, oldSecret) {
    //         return async function(event) {
    //             console.log("Attacco intercettato - RECOVERY TX")
    //             await SSIOp.revokeDID(DIDObj, oldSecret)
    //             i++
    //             key = false
    //         }
    //     };

    //     const handler = await createHandler(servers[i], "0x" + secretArr[0], secretArr[1]);
    //     await (await provider.config.getProvider()).once("updDsRA", handler);

    //     //DID COMPROMISED PROTECTION
    //     await SSIOp.updateEntry('RA_SIGNATURE', servers[i], "", '0xffffffffff')
    //     //await new Promise(resolve => setTimeout(resolve, 80000));
    // }
})();





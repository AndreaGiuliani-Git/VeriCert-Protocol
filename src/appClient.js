const net = require('net')
const jwtVP = require('./jwt-vp.js')
const SSIOp = require('./SSIOp.js')
const fs = require('fs').promises
const config = require('../config.json')
const { X509Certificate } = require('node:crypto')
const { performance } = require('perf_hooks')
const { ec } = require('elliptic') // ECDSA
const ecCurve1 = new ec('secp256k1')

const args = process.argv.slice(2)
let contractInstance = null

if(args.length > 0) {
  switch(args[0]){
    case 'VP':

      SSIOp.initSepolia().then(() => {
        contractInstance = SSIOp.getContractInstance();
      });

      let clientVP = new net.Socket()
      clientVP.connect(config.server.portSSI, config.server.ipAddrSSI, () => {
        console.log('Connect to the server... ');
        clientVP.write('TLS-VP request');
      });

      //Management VP from server
      clientVP.on('data', async (data) => {
        
        let verifyVPTime = null
        let resultVP = null
        let VPsizeInKB = null
        let commName = null
        let resultCRT = null

        try {
          /*
          * ---------------------------------------------------------
          *     JWT VP VERIFICATION + PERFORMANCE (DID RESOLUTION)
          * ---------------------------------------------------------
          */
          const token = await JSON.parse(data.toString())
          const res = await jwtVP.verifyPresentationJwtES256Perf(token)
          let serverDID = await res[0]
          resultVP = await res[1]
          verifyVPTime = await res[2]
          VPsizeInKB = await res[3]
          
          if(resultVP) {
            /*
            * --------------------------------------------------------
            *     CT VERIFICATION + PERFORMANCE (TX SMART CONTRACT)
            * --------------------------------------------------------
            */
            let start = performance.now()

            //Transaction for certificate hash and RA signature
            const tx = await contractInstance.infoCT(serverDID.split(":")[3])
            let end0 = performance.now()
            
            const crtChain = res[4].TLSCertChain.split(',')
            const X509Cert = new X509Certificate(crtChain[0])
            const CertHash_BC = tx[0]                     
            let CertHash_VP = "0x" + X509Cert.fingerprint256.replace(/:/g, '').toLowerCase()
            let end1 = performance.now()

            let verifyCrtTrTime = parseFloat((end1 - start).toFixed(2))
            let infoCT_Time = parseFloat((end0 - start).toFixed(2))

            const csvRow = `${infoCT_Time}\n`
            fs.appendFile(config.perfFiles.infoCTPerf, csvRow)

            if(CertHash_VP == CertHash_BC) {
              /*
                * ---------------------------------------------------
                *       RA SIGNATURE VERIFICATION + PERFORMANCE
                * ---------------------------------------------------
              */
              const RAsign_BC = tx[1]
              commName = res[4].id
              const regex = /CN=([^,]+)/
              const matches = X509Cert.subject.match(regex)

              if(!(matches && matches.length > 1)) {
                throw new Error("NO COMMON NAME FOUND")
              }
              
              if(commName != matches[1]) {
                throw new Error("Id credential different from X509-CommonName")
              }

              let key = ecCurve1.keyFromPublic(SSIOp.getRApubKey())
              let start = performance.now()
              let resultRAsign = key.verify(commName + serverDID, Buffer.from(RAsign_BC.slice(2), 'hex'))     
              let end = performance.now()
              let RAsignVerTime = parseFloat((end - start).toFixed(2))
              
              if(resultRAsign) {
                /*
                * -------------------------------------------
                *       OPENSSL VERIFICATION + PERFORMANCE
                * -------------------------------------------
                */
                //Create server certificate file
                await fs.writeFile('./certServer.pem', crtChain[0]);
    
                //Create inter CAs certificates file
                const crtIntArr = crtChain.slice(1);
                const crtIntStr = crtIntArr.join(',').replace(/,/g, "\n");
                await fs.writeFile('./certChain.pem', crtIntStr);

                //OpenSSL certificate check
                let start = performance.now()
                resultCRT = await SSIOp.crtVerify()
                let end = performance.now()
                let crtVerTime = parseFloat((end - start).toFixed(2))

                //CRT size
                const crtLengthInBytes = Buffer.byteLength(crtChain[0], 'utf-8');
                const crtSizeInKB = parseFloat((crtLengthInBytes / 1024).toFixed(2));

                //Trust chain size
                const chainLengthInBytes = Buffer.byteLength(crtIntStr, 'utf-8');
                const chainSizeInKB = parseFloat((chainLengthInBytes / 1024).toFixed(2));

                //Number of inter CAs
                const numInterCA = crtIntStr.split('-----BEGIN CERTIFICATE-----').length - 1;
                
                SSIOp.writePerf('OK', commName, verifyVPTime, resultVP, crtVerTime, resultCRT, RAsignVerTime, verifyCrtTrTime, numInterCA, crtSizeInKB, chainSizeInKB, VPsizeInKB, "VP")
            
              } else {
                console.log('RA SIGNATURE INVALID');
                SSIOp.writePerf('RA-SIGN-INVALID', '', verifyVPTime, resultVP, '', '', RAsignVerTime, verifyCrtTrTime, '', '','', VPsizeInKB, "VP")
              }

            } else {
              console.log('CRT HASH IN VP DIFFERENT FROM CRT HASH IN BLOCKCHAIN');
              SSIOp.writePerf('CRT-TR-INVALID', '', verifyVPTime, resultVP, '', '', verifyCrtTrTime,'', '','', '', VPsizeInKB, "VP")
            }
          } else {
            console.log("INVALID VP")
            SSIOp.writePerf('VP-INVALID', '', verifyVPTime, resultVP, '','', '','', '', '', '', VPsizeInKB, "VP")
          }
        } catch (error) {
          resultCRT = false
          SSIOp.writePerf(error.message, commName, verifyVPTime, resultVP, '',resultCRT, '','', '', '', '', VPsizeInKB, "VP")
          console.error("VERIFICATION FAILURE:" + error)
        }
        clientVP.write('TLS-VP request')
      })
      break

    case 'CRT':

      let clientCRT = new net.Socket()

      clientCRT.connect(config.server.portCRT, config.server.ipAddrCRT, () => {
          console.log('Connect to the server... ');
          clientCRT.write('CRT request');
      });

      clientCRT.on('data', async (data) => {
        let commName = null
        let result = null       
        try {
          /*
           * ------------------------------------------
           *       OPENSSL VERIFICATION + PERFORMANCE
           * ------------------------------------------
          */
          const crtArray = data.toString().split(',');

          //Create server certificate file
          let X509Cert = new X509Certificate(crtArray[0])
          const regex = /CN=([^,]+)/
          const matches = X509Cert.subject.match(regex)

          if (!(matches && matches.length > 1)) {
              throw new Error("NO COMMON NAME FOUND")
          }
          commName = matches[1]
          await fs.writeFile('./certServer.pem', crtArray[0])

          //Create inter CAs certificates file
          const crtChainArr = crtArray.slice(1);
          const crtChainStr = crtChainArr.join(',').replace(/,/g, "\n");
          await fs.writeFile('./certChain.pem', crtChainStr);

          //OpenSSL certificate check
          let start = performance.now() //Start time openssl certificate check

          result = await SSIOp.crtVerify()

          let end = performance.now() //End time openssl certificate check
          let verifyCRTime = parseFloat((end - start).toFixed(2))

          //CRT size
          const crtLengthInBytes = Buffer.byteLength(crtArray[0], 'utf-8');
          const crtSizeInKB = parseFloat((crtLengthInBytes / 1024).toFixed(2));

          //Trust chain size
          const chainLengthInBytes = Buffer.byteLength(crtChainStr, 'utf-8');
          const chainSizeInKB = parseFloat((chainLengthInBytes / 1024).toFixed(2));

          //Number of inter CAs
          let numInterCA = crtChainStr.split('-----BEGIN CERTIFICATE-----').length - 1;

          SSIOp.writePerf('OK', commName, '', '', verifyCRTime, result, '', '', numInterCA, crtSizeInKB, chainSizeInKB, '', "CRT")
          
        } catch (error) {
          result = false
          SSIOp.writePerf(error.message, commName, '', '', '',result, '','', '', '', '', '', "CRT")
          console.error("CRT CHECK ERROR:" + error);
        }
        clientCRT.write('CRT request')
      });
      clientCRT.on('close', () => {
        console.log('CONNECTION CLOSED');
      });
      break   
    default:
      console.log('INVALID CLIENT TYPE')
  }
} else {
    console.log('ADD CLIENT TYPE LIKE: VP or CRT')
}
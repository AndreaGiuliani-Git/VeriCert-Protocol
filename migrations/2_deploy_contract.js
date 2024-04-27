var MyContract = artifacts.require("../contracts/SSLBlockchainReg.sol");

module.exports = function(deployer) {
    // deployment steps
    deployer.deploy(MyContract);
  };
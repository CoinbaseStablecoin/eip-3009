const fs = require("fs");
const path = require("path");
const Token = artifacts.require("Token");

let tokenName = "";
let tokenVersion = "";
let tokenSymbol = "";
let tokenDecimals = -1;
let tokenTotalSupply = "";

// Read config file if it exists
if (fs.existsSync(path.join(__dirname, "..", "config.js"))) {
  ({
    TOKEN_NAME: tokenName,
    TOKEN_VERSION: tokenVersion,
    TOKEN_SYMBOL: tokenSymbol,
    TOKEN_DECIMALS: tokenDecimals,
    TOKEN_TOTAL_SUPPLY: tokenTotalSupply,
  } = require("../config.js"));
}

module.exports = async (deployer, _network) => {
  console.log(`Name:          ${tokenName}`);
  console.log(`Version:       ${tokenVersion}`);
  console.log(`Symbol:        ${tokenSymbol}`);
  console.log(`Decimals:      ${tokenDecimals}`);
  console.log(`Total Supply:  ${tokenTotalSupply}`);

  if (
    !tokenName ||
    !tokenVersion ||
    !tokenSymbol ||
    tokenDecimals < 0 ||
    !tokenTotalSupply
  ) {
    throw new Error(
      "TOKEN_NAME, TOKEN_VERSION, TOKEN_SYMBOL, TOKEN_DECIMALS, and TOKEN_TOTAL_SUPPLY must be provided in config.js"
    );
  }

  console.log("Deploying token contract...");
  await deployer.deploy(
    Token,
    tokenName,
    tokenVersion,
    tokenSymbol,
    tokenDecimals,
    tokenTotalSupply
  );
  const token = await Token.deployed();
  console.log("Deployed token contract at", token.address);
};

import { expect } from "chai";

const Token = artifacts.require("Token");

contract("Dummy test", (_accounts) => {
  it("works", async () => {
    const token = await Token.deployed();
    expect(await token.name()).to.equal("My Awesome Token");
  });
});

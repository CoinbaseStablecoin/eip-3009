# EIP-0000

An ERC20 token contract that implements EIP-0000 and EIP-2612

## Setup

Requirements:

- Node >= v12
- Yarn

```
$ git clone git@github.com:CoinbaseStablecoin/eip-0000.git
$ cd eip-0000
$ npm i -g yarn       # Install yarn if you don't already have it
$ yarn install        # Install dependencies
$ yarn setup          # Setup Git hooks
```

## Deployment

# Deployment

1. Create `config.js` by copying `config.js.example`.
2. Edit `config.js` with the desired configuration.
3. Run Truffle migrations.

```
$ yarn migrate --network goerli
```

---

[MIT License](./LICENSE)

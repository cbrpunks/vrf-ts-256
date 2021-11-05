[![https://nodei.co/npm/vrf-ts-256.png?downloads=true&downloadRank=true&stars=true](https://nodei.co/npm/vrf-ts-256.png?downloads=true&downloadRank=true&stars=true)](https://www.npmjs.com/package/YOUR-MODULE-NAME)

# vrf-ts-256
## ECVRF-SECP256K1-SHA256-TAI (draft-irtf-cfrg-vrf-04)

### Remastering of [this](https://github.com/icepeng/ecvrf) reference for full compability with [witnet/vrf-solidity](https://github.com/witnet/vrf-solidity)

## Usage

```javascript
const ecvrf = require('vrf-ts-256')

const keypair = ecvrf.keygen()
const proof = ecvrf.prove(keypair.secret_key, '73616d706c65')
const beta = ecvrf.verify(keypair.public_key.key, proof.pi, '73616d706c65');

/*
Using with truffle-contract for vrf-solidity
*/
const vrfContractInstance = await VRF.deployed()
await vrfContractInstance.verify(
    [keypair.public_key.x, keypair.public_key.y],
    [proof.decoded.gammaX, proof.decoded.gammaY, proof.decoded.c, proof.decoded.s]
    '73616d706c65'
)
```

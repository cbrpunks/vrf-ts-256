import { prove, proof_to_hash, verify, keygen, validate_key } from './index';

// From vrf-solidity data.json
// const secret_key =
//   '1';
//const public_key =
//   '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

const { public_key, secret_key, compressed } = keygen();
console.log(compressed.public_key)
validate_key(public_key)
const alpha = '73616d706c65';
const pi = prove(secret_key, alpha);
const beta = proof_to_hash(pi);
const res = verify(public_key, pi, alpha);
console.log(pi);
console.log(beta);
console.log(res);

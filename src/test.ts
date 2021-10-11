import { prove, proof_to_hash, verify, keygen, validate_key } from './index';

// From vrf-solidity data.json
// const secret_key =
//   '1';
//const public_key =
//   '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

const { public_key, secret_key } = keygen('0x440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428');
console.log(public_key)
validate_key(public_key.key)
const alpha = '73616d706c65';
const pi = prove(secret_key, alpha);
const beta = proof_to_hash(pi.pi);
const res = verify(public_key.key, pi.pi, alpha);
console.log(pi);
console.log(beta);
console.log(res);

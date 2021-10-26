/*
https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04.pdf
ECVRF-SECP256K1-SHA256-TAI
*/

import BN from 'bn.js';
import { sha256 } from 'js-sha256';
import * as elliptic from 'elliptic';
import * as utils from 'minimalistic-crypto-utils';

type Point = elliptic.curve.base.BasePoint;

const EC = new elliptic.ec('secp256k1');
const suite = [0xFE];

function string_to_point(s: number[]): Point | 'INVALID' {
  try {
    return EC.curve.decodePoint(s);
  } catch {
    return 'INVALID';
  }
}

function encode_point(p: Point): number[] {
  const prefix = new BN(2).add((p.getY().mod(new BN(2))));
  return [...prefix.toArray(), ...p.getX().toArray()]
}

function append_leading_zeroes(p: number[], qlen: number): number[] {
  const p2 = [...p];
  while(p2.length < qlen) {
    p2.unshift(0)
  }
  return p2;
}

function arbitrary_string_to_point(s: number[]): Point | 'INVALID' {
  if (s.length !== 32) {
    throw new Error('s should be 32 byte');
  }
  return string_to_point([0x02, ...s]);
}

function is_on_curve(point: Point): boolean {
  const x = point.getX();
  const y = point.getY();
  if (
    x.isZero()        ||
    x.gte(EC.curve.p) ||
    y.isZero()        ||
    y.gte(EC.curve.p)
  ) {
    return false;
  }
  //let lhs = (y.mul(y)).mod(EC.curve.p)
  //let rhs = x.mul((x.mul(x)).mod(EC.curve.p)).mod(EC.curve.p)

  let lhs = (y.mul(y)).mod(EC.curve.p)
  let rhs = ((x.mul(x).mod(EC.curve.p)).mul(x)).mod(EC.curve.p)

  // a == 0 for secp256k1
  // b == 7 for secp256k1
  rhs = (rhs.add(EC.curve.b)).mod(EC.curve.p)
  return lhs.eq(rhs);
}

function hash_to_curve(public_key: Point, alpha: number[]) {
  let hash: Point | 'INVALID' = 'INVALID';
  let ctr = 0;
  while ((hash == 'INVALID' || hash.isInfinity() || !is_on_curve(hash)) && ctr < 256) {
    const hash_string = sha256
      .create()
      .update(suite)
      .update([0x01])
      .update(encode_point(public_key))
      .update(alpha)
      .update([ctr])
      .digest();
    hash = arbitrary_string_to_point(hash_string); // cofactor = 1, skip multiply
    ctr += 1;
  }
  if (hash == 'INVALID') {
    throw new Error('hash_to_curve failed');
  }
  return hash;
}

function nonce_generation(secret_key: BN, h_string: number[]) {
  const h1 = sha256.array(h_string);
  let K = new Array(32)
    .fill(0)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  let V = new Array(32)
    .fill(1)
    .map((b) => b.toString(16).padStart(2, '1'))
    .join('');
  K = sha256.hmac
    .create(K)
    .update(V)
    .update([0x00])
    .update(append_leading_zeroes(secret_key.toArray(), 32))
    .update(append_leading_zeroes(h1, 32))
    .hex();
  V = sha256.hmac.create(K).update(V).hex();
  K = sha256.hmac
    .create(K)
    .update(V)
    .update([0x01])
    .update(append_leading_zeroes(secret_key.toArray(), 32))
    .update(append_leading_zeroes(h1, 32))
    .hex();
  V = sha256.hmac.create(K).update(V).hex();
  V = sha256.hmac.create(K).update(V).hex(); // qLen = hLen = 32, skip loop
  return new BN(V, 'hex');
}

function hash_points(...points: Point[]) {
  const str = [...suite, 0x02];
  for (const point of points) {
    str.push(...encode_point(point));
  }

  const c_string = sha256.digest(str);
  const truncated_c_string = c_string.slice(0, 16);
  const c = new BN(truncated_c_string);

  return c;
}

function decode_proof(pi: number[]) {
  const gamma_string = pi.slice(0, 33);
  const c_string = pi.slice(33, 33 + 16);
  const s_string = pi.slice(33 + 16, 33 + 16 + 32);
  const Gamma = string_to_point(gamma_string);
  if (Gamma == 'INVALID') {
    return 'INVALID';
  }

  const c = new BN(c_string);
  const s = new BN(s_string);

  return {
    Gamma,
    c,
    s,
  };
}

function _prove(secret_key: BN, alpha: number[]): number[] {
  const public_key = EC.keyFromPrivate(secret_key.toArray()).getPublic();
  const H = hash_to_curve(public_key, alpha);
  const h_string = encode_point(H);
  const Gamma = H.mul(secret_key);
  const k = nonce_generation(secret_key, h_string);
  const c = hash_points(H, Gamma, EC.g.mul(k), H.mul(k));
  const s = k.add(c.mul(secret_key)).umod(EC.n);
  const pi = [
    ...encode_point(Gamma),
    ...c.toArray('be', 16),
    ...s.toArray('be', 32),
  ];
  return pi;
}

function _proof_to_hash(pi: number[]): number[] {
  const D = decode_proof(pi);
  if (D == 'INVALID') {
    throw new Error('Invalid proof');
  }
  const { Gamma } = D;
  const beta = sha256
    .create()
    .update(suite)
    .update([0x03])
    .update(encode_point(Gamma))
    .digest();

  return beta;
}

function _verify(public_key: Point, pi: number[], alpha: number[]) {
  const D = decode_proof(pi);
  if (D == 'INVALID') {
    throw new Error('Invalid proof');
  }
  const { Gamma, c, s } = D;
  const H = hash_to_curve(public_key, alpha);
  const U = EC.g.mul(s).add(public_key.mul(c).neg());
  const V = H.mul(s).add(Gamma.mul(c).neg());
  const c2 = hash_points(H, Gamma, U, V);
  if (!c.eq(c2)) {
    throw new Error('Invalid proof');
  }
  return _proof_to_hash(pi);
}

function _validate_key(public_key_string: number[]) {
  const public_key = string_to_point(public_key_string);
  if (public_key == 'INVALID' || public_key.isInfinity()) {
    throw new Error('Invalid public key');
  }
  return public_key;
}

export function keygen(entropy?: string) {
  const keypair = entropy ? EC.genKeyPair({ entropy }) : EC.genKeyPair()
  const secret_key = keypair.getPrivate('hex');
  const public_key = keypair.getPublic('hex');
  return {
    secret_key,
    public_key: {
      key: public_key,
      compressed: keypair.getPublic(true, 'hex'),
      x: keypair.getPublic().getX(),
      y: keypair.getPublic().getY()
    }
  };
}

export function prove(secret_key: string, alpha: string) {
  const pi = _prove(new BN(secret_key, 'hex'), utils.toArray(alpha, 'hex'));
  const D = decode_proof(pi);
  if (D == 'INVALID') {
    throw new Error('Invalid proof');
  }
  const { Gamma, c, s } = D;
  return {
    pi: utils.toHex(pi),
    decoded: {
      gammaX: Gamma.getX(),
      gammaY: Gamma.getY(),
      c,
      s
    }
  }
}

export function proof_to_hash(pi: string): string {
  const beta = _proof_to_hash(utils.toArray(pi, 'hex'));
  return utils.toHex(beta);
}

export function verify(public_key: string, pi: string, alpha: string): string {
  const beta = _verify(
    EC.curve.decodePoint(public_key, 'hex'),
    utils.toArray(pi, 'hex'),
    utils.toArray(alpha, 'hex')
  );
  return utils.toHex(beta);
}

export function validate_key(public_key: string) {
  _validate_key(utils.toArray(public_key, 'hex'));
  return;
}

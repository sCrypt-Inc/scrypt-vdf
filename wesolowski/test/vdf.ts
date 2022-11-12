import * as crypto from "crypto";
import BN from 'bn.js';

import { E, exp, find_q, mulE, newE, randE, toBytes } from './rsa';

const MILLER_RABIN_ROUNDS = 15;
const DST = '0x';
const MAX_NONCE = 65536;   


export interface Challenge {
  l: E;
  nonce: number;
}

export interface Proof {
  challenge: Challenge;
  pi: E;
  y: E;
  q: E;
}

export function hash(g: E, y: E, nonce: number): E {
  const gHex = toBytes(g, 256);
  const yHex = toBytes(y, 256);
  const nonceBN = new BN(nonce);
  const nonceHex = nonceBN.toBuffer("be", 32).toString('hex');
  return newE("0x" + crypto.createHash('sha256').update(Buffer.from(gHex.slice(2,) + yHex.slice(2,) + nonceHex, 'hex')).digest('hex'));
}

export function hashToPrime(g: E, y: E): Challenge | null {
  for (let i = 0; i < 1 << 16; i++) {
    let candidate = hash(g, y, i);
    if (candidate.and(1).eq(0)) {
      candidate = candidate.add(1);
    }
    if (isProbablePrime(candidate)) {
      return { l: candidate, nonce: i };
    }
  }
  return null;
}

export function randPrime() {
  let i = 0;
  let candidate = randE(32);
  if (candidate.and(1).eq(0)) {
    candidate = candidate.add(1);
  }
  while (true) {
    if (isProbablePrime(candidate)) {
      return candidate;
    }
    candidate = candidate.add(2);
  }
}

export function isProbablePrime(n: E): boolean {
  if (n.lt(3)) {
    return false;
  }
  if (!n.and(1).eq(1)) {
    return false;
  }
  let d = n.sub(1);
  let r = 0;
  while (d.and(1).eq(0)) {
    d = d.shr(1);
    r += 1;
  }

  for (let i = 0; i < MILLER_RABIN_ROUNDS; i++) {
    let a = newE(10); //randBelow(n.sub(3)).add(2);
    let x = exp(a, d, n);
    if (x.eq(1) || x.eq(n.sub(1))) {
      continue;
    }
    let passed = false;
    for (let j = 1; j < r; j++) {
      x = x.mul(x).mod(n);
      if (x.eq(n.sub(1))) {
        passed = true;
        break;
      }
    }
    if (!passed) {
      return false;
    }
  }

  return true;
}

export function evaluate(g: E, t: number): Proof {
  const e = newE(1).shl(t);
  const y = exp(g, e);
  const challenge = hashToPrime(g, y)!;

  let z = e;
  let r = newE(1);
  let pi = newE(1);

  while (!z.eq(0)) {
    const r2 = r.mul(2);
    const b = r2.div(challenge.l);
    r = r2.mod(challenge.l);
    const gb = exp(g, b);
    pi = mulE(pi, pi);
    pi = mulE(pi, gb);
    z = z.sub(1);
  }

  // some extra work for helper value
  const u1 = exp(pi, challenge.l);
  const u2 = exp(g, e);
  const q = find_q(u1, u2);
  return { pi, challenge, y, q };
}

export function verify(g: E, t: number, proof: Proof): boolean {
  let l = hash(g, proof.y, proof.challenge.nonce)!;
  if (l.and(1).eq(0)) {
    l = l.add(1);
  }
  if (!l.eq(proof.challenge.l)) {
    return false;
  }
  if (!isProbablePrime(l)) {
    return false;
  }

  const r = newE(1).shl(t).mod(MAX_NONCE);
  const u1 = exp(proof.pi, proof.challenge.l);
  const u2 = exp(g, r);
  return mulE(u1, u2).eq(proof.y);
}

// const g = randE();
// const t = 4;
// const proof = evaluate(g, t);
// console.log('must verify', verify(g, t, proof));

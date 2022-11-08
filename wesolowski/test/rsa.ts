import { BigNumber } from '@ethersproject/bignumber';
import { hexlify, zeroPad } from '@ethersproject/bytes';
import { randomBytes } from '@ethersproject/random';
import BN from 'bn.js';

export type E = BigNumber;

const RSA_MODULUS_STR =
  '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357';
export const RSA_MODULUS = BigNumber.from(RSA_MODULUS_STR);
export const RSA_MODULUS_BYTES = to256Bytes(RSA_MODULUS);

export function randE(n: number = 256): E {
  return BigNumber.from(randomBytes(n)).mod(RSA_MODULUS);
}

export function randBigNumber(n: number): E {
  return BigNumber.from(randomBytes(32));
}

export function newE(n: string | number = 0): E {
  return BigNumber.from(n);
}

export function to256Bytes(input: E): string {
  return hexlify(zeroPad(input.toHexString(), 256));
}

export function to512Bytes(input: E): string {
  return hexlify(zeroPad(input.toHexString(), 512));
}

export function toBytes(input: E, n: number): string {
  return hexlify(zeroPad(input.toHexString(), n));
}

export function mulE(a: E, b: E, modulus: E = RSA_MODULUS): E {
  return a.mul(b).mod(modulus);
}

export function find_q(a: E, b: E, modulus: E = RSA_MODULUS): E {
  return a.mul(b).div(modulus);
}

export function addE(a: E, b: E, modulus: E = RSA_MODULUS): E {
  return a.add(b).mod(modulus);
}

export function exp(a: E, e: E, modulus: E = RSA_MODULUS): E {
  const ctx = BN.red(new BN(modulus.toString()));
  const aBN = new BN(a.toString());
  const eBN = new BN(e.toString());
  let redBN = aBN.toRed(ctx);
  redBN = redBN.redPow(eBN);
  const resBN = redBN.fromRed();
  return BigNumber.from(resBN.toString());
}

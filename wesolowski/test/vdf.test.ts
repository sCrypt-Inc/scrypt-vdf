import path = require("path");
const fs = require("fs");
import { describe, before, it } from 'mocha';
import { expect, use } from 'chai';

import * as crypto from "crypto";
import BN from 'bn.js';

import { randE, exp, toBytes, randBigNumber } from './rsa';
import { evaluate, isProbablePrime, randPrime, verify } from './vdf';

import {
    buildContractClass, buildTypeClasses, compileContract
} from "scryptlib";
import { BigNumber } from "@ethersproject/bignumber";


describe('VDF', function () {
  this.timeout(1000 * 1000 * 10);
  
  let ContractTypes: any;
  let testVDFVerfifier: any;

  before(async function () {
    let filePath = path.join(__dirname, '..', 'contracts', 'test.scrypt');  
    let out = path.join(__dirname, '..', 'out-scrypt');
    if (!fs.existsSync(out)) {
        fs.mkdirSync(out);
    }
    let result = compileContract(filePath, { out: out, desc: true });
    if (result.errors.length > 0) {
        console.log(`Compile contract ${filePath} failed: `, result.errors);
        throw result.errors;
    }
    const TestVDFVerfifier = buildContractClass(result);

    //const desc = JSON.parse(fs.readFileSync(path.join(out, "test_desc.json")).toString());
    //const TestVDFVerfifier = buildContractClass(desc);

    ContractTypes = buildTypeClasses(TestVDFVerfifier);
    testVDFVerfifier = new TestVDFVerfifier();
  });

  it('modexp', async function () {
    const base = randBigNumber(0);
    const exponent = randBigNumber(0);
    const modulus = randBigNumber(0);
    
    const res = exp(base, exponent, modulus);

    const result = testVDFVerfifier.testModExp(
      BigInt(base._hex), BigInt(exponent._hex), BigInt(modulus._hex), BigInt(res._hex)
    ).verify();
    expect(result.success, result.error).to.be.true;

  });

  it('hash', async function () {
    const g = toBytes(randE(256), 256);
    const y = toBytes(randE(256), 256);
    const nonce = new BN(1);
    const nonceHex = nonce.toBuffer("be", 32).toString('hex');
    const hashRes = "0x" + crypto.createHash('sha256').update(Buffer.from(g.slice(2,) + y.slice(2,) + nonceHex, 'hex')).digest('hex');
    
    let hashResN = BigInt(hashRes)
    if ((hashResN & 1n) == 0n) {
        hashResN += 1n;
    }

    const result = testVDFVerfifier.testHashToPrime(
      BigInt(g), BigInt(y), BigInt(nonceHex), hashResN
    ).verify();
    expect(result.success, result.error).to.be.true;
  });

  it('primalityTest', async function () {
    const n = randPrime();
    const result = testVDFVerfifier.testMillerRabinPrimalityTest(
      BigInt(n._hex), true
    ).verify();
    expect(result.success, result.error).to.be.true;
  });

  it('verify vdf', async function () {
    const g = randE();
    const t = 4;
    const proof = evaluate(g, t);
    
    const result = testVDFVerfifier.testVerify(
      BigInt(g._hex),
      BigInt(proof.pi._hex),
      BigInt(proof.y._hex),
      BigInt(proof.q._hex),
      proof.challenge.nonce,
      t,
      true
    ).verify();
    expect(result.success, result.error).to.be.true;
  });

});

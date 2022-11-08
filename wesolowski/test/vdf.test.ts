import path = require("path");
const fs = require("fs");
import { describe, before, it } from 'mocha';
import { expect, use } from 'chai';

import * as crypto from "crypto";
import BN from 'bn.js';

import { randE, to256Bytes, toBytes } from './rsa';
import { evaluate } from './vdf';

import {
    buildContractClass, buildTypeClasses, compileContract
} from "scryptlib";


describe('VDF', function () {
  
  let ContractTypes: any;
  let testVDFVerfifier: any;

  beforeEach(async function () {
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

    //const desc = JSON.parse(fs.readFileSync(path.join(out, "testvdfverifier_desc.json")).toString());
    //const TestVDFVerfifier = buildContractClass(desc);

    ContractTypes = buildTypeClasses(TestVDFVerfifier);
    testVDFVerfifier = new TestVDFVerfifier();
  });

  it('hash', async function () {
    const g = toBytes(randE(256), 256);
    const y = toBytes(randE(256), 256);
    const nonce = new BN(1);
    const nonceHex = nonce.toBuffer("be", 32).toString('hex');
    const res0 = "0x" + crypto.createHash('sha256').update(Buffer.from(g.slice(2,) + y.slice(2,) + nonceHex, 'hex')).digest('hex');

    const result = testVDFVerfifier.testHashToPrime(
      BigInt(g), BigInt(y), BigInt(nonceHex), BigInt(res0)
    ).verify();
    expect(result.success, result.error).to.be.true;
  });

  it('verify vdf', async function () {
    const g = randE();
    const t = 4;
    const proof = evaluate(g, t);

    // TODO: call pub fun
    //const res = await C.verify(
    //  to256Bytes(g),
    //  to256Bytes(proof.pi),
    //  to256Bytes(proof.y),
    //  to256Bytes(proof.q),
    //  '0x',
    //  proof.challenge.nonce,
    //  t
    //);
    //expect(res).true;
  });
});

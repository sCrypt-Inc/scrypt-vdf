# Delay Function Verification Smart Contract



VDFVerify.sol smart contract verifies Wesolowski VDF in 2048 bit RSA setting.

## Hash to Prime

We used the hash to prime variant defined in section 7 of [BBF19](https://eprint.iacr.org/2020/149.pdf)
where prover picks a nonce from small set and appends it to the transcript until they hit a prime number as hash result.
Prover sends the nonce along with the proof to the verifier so that verifier performs single primality test.


## References

The code is based on [an implementation for the EVM by kilic](https://github.com/kilic/evmvdf)

- [Efficient Verifiable Delay Functions](https://eprint.iacr.org/2018/623.pdf)
- [A Survey of Two Verifiable Delay Functions](https://eprint.iacr.org/2018/712.pdf)
- [Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains](https://eprint.iacr.org/2020/149.pdf)
- [EIP-2565](https://eips.ethereum.org/EIPS/eip-2565)
- [RSA bounty smart contract](https://github.com/dankrad/rsa-bounty)
- [Metamagic Mul512](https://medium.com/wicketh/mathemagic-full-multiply-27650fec525d)
- [rust-accumulators hash to prime function](https://github.com/dignifiedquire/rust-accumulators/blob/master/src/hash.rs)

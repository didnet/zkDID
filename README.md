# Hades
Hades is an practical decentralized identity system that supports privacy-preserving, full accountability and Fine-gained sybil-resistance.

## Structure

**contracts/manager.sol** is the Identity Contract can run on EVM-Powered chains.

**src/ca_client.rs** is a client for CA.

**src/committee_client.rs** is a client for the committee.

**src/user_client.rs** is a client for the users.

**circuits/xxx.circom** are zkp circuits written in Circom.

## How to build

### Installing dependency

```bash
sudo apt update
sudo apt install build-essential
```

### Installing Rust

Hades SDK is written in Rust. To have Rust available in your system, you can install rustup. If you’re using Linux or macOS, open a terminal and enter the following command:

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```
### Installing circom (can skip)

Hades zkp circuits are written in circom. To have circom available in your system, you can install circom:

```bash
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

### Building circom (can skip)

```bash
circom --r1cs --wasm circuits/pseudonym_check.circom
circom --r1cs --wasm circuits/sybil_check.circom
circom --r1cs --wasm circuits/pedersen_commit.circom
circom --r1cs --wasm circuits/tpke_single.circom
```

### Building rust

```bash
cargo build --release
```

## Test and Benchmark

Hades is implemented using Rust and Solidity. We have already attached the test data and test accounts; you can use the following commands for testing and benchmark:

```bash
cargo test --package hades --test contract -- bench_all --exact --nocapture
```

### Test and results:

```bash
running 1 test
1. Start setting up the committee: 
1. The committee has been set up.
2. Start setting up CA: 
2. CA has been set up.
3. Start setting up the identity contract:
tx_hash: 0x1942bb3d258c1cca263f8177751c20b9fe9a814080ccf58b66fd5a1d5c355f1e, Gas_used: Some(29364)
3. The identity contract has been set up.
4. Start updating the identity contract:
tx_hash: 0xe9153b33a1ebb8b86cd7c9f20a3b42c1b8bf4f52ec19a048305fd9b363e78358, Gas_used: Some(88943)
4. The identity contract has been updated.
5. Start requesting credential
Credential request proof time: 318 ms
5. Credential generated!
6. Start to generate psedonyms: Pseudonym register proof time: 1470 ms
tx_hash: 0x6a5d2672811b9cb1aa576725846948d0a3b92f444b3e88cb8c585a6e24445eaa, Gas_used: Some(337101)
6. pseudonym 1 generated.
Pseudonym register proof time: 1460 ms
test bench_all has been running for over 60 seconds
tx_hash: 0x7bc1356d11c4bdaa367587d1a748c75a20e13e69dd112243e3840ab9e2474506, Gas_used: Some(337089)
6. pseudonym 2 generated.
7. Start to response to Sybil-resistance: 
Sybil-resistance proof time: 324 ms
tx_hash: 0x79d3c4110a1a617a5f570dc3381da0d66e9baac322fe3293be3457d4d1252f3d, Gas_used: Some(249614)
7. proof accepted.
8. Start to prove identity attributes (Selective disclosure):
Identity proof time: 929 ms
tx_hash: 0x24319bb93fe2f490c953cd225c62889093ac51fcbc227a96864caddaec9703b0, Gas_used: Some(232596)
8. proof accepted.
9. Start to audit:
9. User info revealed
10. Start to trace user: 
10. all pseudonyms traced: [0x8181082017346679045203273291153336789837, 0x0056927037680436204345599445309492724824]
11. Start to revoke user:
11.1 Start to revoke credential:
tx_hash: 0x210c0715b063e7a88b6fe28a252d737d6270c38c655c1885bfdd5f0ae3c6489f, Gas_used: Some(88943)
11.1 Credential revoked!
11.2 Start to revoke pesudonyms:
tx_hash: 0x78e2d57b35e4257a0c454c86286b2fd7bf820dd0dcf2e059592d0bfd65afcf7e, Gas_used: Some(46617)
11.2 Pesudonyms revoked.
test bench_all ... ok
```

### Circuits  constraints

Credential generation:

```c
template instances: 19
non-linear constraints: 3907
linear constraints: 0
public inputs: 8
public outputs: 0
private inputs: 3
private outputs: 0
wires: 3910
labels: 28453
```c

Pseudonyms check:

```c
template instances: 333
non-linear constraints: 31951
linear constraints: 0
public inputs: 7
public outputs: 0
private inputs: 94
private outputs: 0
wires: 32004
labels: 144153
```

sybil-check:

```c
template instances: 93
non-linear constraints: 4291
linear constraints: 0
public inputs: 4
public outputs: 0
private inputs: 4
private outputs: 0
wires: 4288
labels: 19926
```

Selective disclosure

```c
template instances: 99
non-linear constraints: 16240
linear constraints: 0
public inputs: 18
public outputs: 0
private inputs: 10
private outputs: 0
wires: 16225
labels: 120331
```
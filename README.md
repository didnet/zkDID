# zk-DID
zk-DID (Hades) is a practical decentralized identity system that supports privacy-preserving, full accountability, and Fine-gained sybil-resistance.

## Components

There are four components in Hades: the **CA client**, the **committee client**, the **user client** and the **identity contract**.

- The CA client is responsible for authenticating user identity attributes and issuing certificates for users. Its functions include: verifying user requests, storing identity information, and providing information required for identity accountability. Its core functions are implemented in **src/ca_client.rs**.

- The Committee client is responsible for managing user identities, CAs, and identity contracts. Its functions include: auditing pseudonyms, tracing users, adding or removing CAs, revoking credentials and pseudonyms, adding or removing committee members, and updating identity contracts. Its core functions are implemented in **src/committee_client.rs**.

- The User client primarily assists users in identity management, including applying for credentials, storing credentials, registering pseudonyms, storing secret information, responding to Sybil attacks, and selectively disclosing identity attributes. Its core functions are implemented in **src/user_client.rs**.

- The identity contract is written in Solidity and can be deployed on any EVM-compatible blockchain. Its functions include processing pseudonym registration requests, logging the status of pseudonyms, recording pseudonym tracing data, verifying identity attribute assertions, and verifying non-Sybil proofs. Its core functions are implemented in **contracts/manager.sol**.

## Structure

**contracts/manager.sol** is the Identity Contract that can run on EVM-Powered chains.

**src/ca_client.rs** is a client for CA.

**src/committee_client.rs** is a client for the committee.

**src/user_client.rs** is a client for the users.

**src/tpke.rs** is the threshold public key encryption scheme.

**src/merkle_tree.rs** is the merkle tree scheme.

**circuits/merkle_tree.circom** is a Merkle tree zero-knowledge circuit written in Circom.

**circuits/pedersen_commit.circom** is a Pedersen commitment zero-knowledge circuit written in Circom.

**circuits/pseudonym_check.circom** is a zero-knowledge circuit written in Circom to verify whether the given pseudonym was registered using a valid credential.

**circuits/sybil_check.circom** is a zero-knowledge circuit written in Circom to verify whether the given access token is valid.

**circuits/tpke_dual.circom** is a zero-knowledge circuit written in Circom to verify threshold public key encryption for two points.

**circuits/tpke_single.circom** is a zero-knowledge circuit written in Circom to verify threshold public key encryption for single points.

## How to build

### Installing dependency

```bash
sudo apt update
sudo apt install build-essential
```

### Installing Rust and Cargo

Hades SDK is written in Rust. To have Rust available in your system, you can install rustup. If you’re using Linux or macOS, open a terminal and enter the following command:

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```

Note: Please ensure that the installed Rust compiler version is no lower than 1.70. Using older versions may lead to program crashes.

### Installing circom

Hades zkp circuits are written in circom. To have circom available in your system, you can install circom:

```bash
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

### Building circom

```bash
circom --r1cs --wasm circuits/pseudonym_check.circom
circom --r1cs --wasm circuits/sybil_check.circom
circom --r1cs --wasm circuits/pedersen_commit.circom
circom --r1cs --wasm circuits/tpke_single.circom
```

### Building Hades

```bash
https://github.com/didnet/Hades.git
cd Hades
cargo build --release
```



## Test and Benchmark

Hades is implemented using Rust and Solidity. 
To simplify the evaluation, we have consolidated all the processes into one test function and also provided some BSC Testnet accounts. 
The command listed below can be utilized to run the test.

```
cd Hades
cargo build --release
target/release/hades
```
OR
```bash
cargo test --package hades --test contract -- bench_all --exact --nocapture
```
Since the second method runs in debug mode, its evaluation results are not accurate (slower).

We evaluated the implementation on an Ubuntu 2204 instance, hosted via Windows Subsystem for Linux (WSL2) on a Microsoft Windows 11 operating system. The test machine was equipped with an Intel Core i9-13900K@3.0GHz 16-Core (8P+16E) CPU and 64 GB of RAM. The identity contract was deployed on BSC Testnet. 
Below are the test results (in release model), which are presented in Tables 1 and Table 2 of the paper.
Note that due to differences in CPU performance, the test results may vary across different running platforms.

In the aforementioned testing environment, the approximate resources used are '5min46s, 20GB of disk space' for compiling, '2min47s, 20GB of disk space' for bench (release mode) and '2min54s, 20GB of disk space' for bench (debug mode).

Note that part of the gas fee comes from the input data. The input data fee is the cost associated with the data sent, every zero-valued byte of data is worth 4 units of gas and every non-zero-valued byte of data is worth 16 units of gas. 
Zero-knowledge proof generation is random, leading to different proofs in each run. So, the gas cost required to transmit proofs in each run is different (because the number of zero-value bits is different). 
So, the gas cost for each transaction related to pseudonym registration, Sybil-resistance, and identity assertion proofs shows slight variations.
Due to the random nature of proof generation, there may be slight variations in the time it takes to generate a proof each time.

```bash
1. Start setting up the committee:
1. The committee has been set up.
2. Start setting up CA:
2.1 Start adding CA to trusted list:
2. CA has been set up.
3. Start setting up the identity contract:
tx_hash: 0x7f594106aff1e89b3b0c1b36e237d3145a791f485aea5a179d83423a3659614e, Gas_used: Some(29364)
3. The identity contract has been set up.
4. Start updating the identity contract:
tx_hash: 0x5a137940d5b6616ee5f4245df9fc78dffe2635dae035224eea12a650b8cad527, Gas_used: Some(88955)
4. The identity contract has been updated.
[credential generation] 5. Start requesting credential
Credential request proof time: 195 ms
5. Credential generated!
[pseudonym registration] 6. Start to generate psedonyms: 
Pseudonym register proof time: 614 ms
tx_hash: 0x053b1b843aa73e3cc0e70081c89ba54e10b29b9778133de03c8b225582a10cd0, Gas_used: Some(337101)
[pseudonym registration] 6. pseudonym 1 generated.
Pseudonym register proof time: 599 ms
tx_hash: 0x00ee54cd220a4f1016cff8a7105ccf02b2c88ffa8abd1b365aa019cfb9e419d9, Gas_used: Some(337137)
6. pseudonym 2 generated.
[Sybil-resistance] 7. Start to response to Sybil-resistance:
Sybil-resistance proof time: 245 ms
tx_hash: 0x43923732c81f68422ba8e5af1286204fc9ed6422cba7ec0e8b6af4f3355461d2, Gas_used: Some(249614)
7. proof accepted.
[selective disclosure] 8. Start to prove identity attributes (Selective disclosure):
Identity proof time: 564 ms
tx_hash: 0x87a6029c981c7306f2f1575c8c16ba86ea5be3f5952f2a810c6174d5eca642ff, Gas_used: Some(232644)
8. proof accepted.
9. Start to audit:
9. User info revealed
10. Start to trace user:
10. all pseudonyms traced: [0x8181082017346679045203273291153336789837, 0x0056927037680436204345599445309492724824]
11. Start to revoke user:
11.1 Start to revoke credential:
tx_hash: 0x19b9e54d61bb8b88f2e0b1d61e52f1830ea7a851e9f085039279272b99ed86bb, Gas_used: Some(88955)
11.1 Credential revoked!
[pseudonym revocation] 11.2 Start to revoke pesudonyms:
tx_hash: 0x9ee1f427493b4dafae2b062fbaa03a85fccbb49d27a4c9bee17470cc7ae20814, Gas_used: Some(46617)
11.2 Pesudonyms revoked.
```

### Circuits  constraints

Circuit constraint information can be accessed using the Circom compiler. Following are the specific commands and their associated output.
This data is presented in the first column of Table 1 in the paper.

**Credential generation:**

```bash
circom --r1cs --wasm circuits/tpke_single.circom

outputs:
template instances: 19
non-linear constraints: 3907
linear constraints: 0
public inputs: 8
public outputs: 0
private inputs: 3
private outputs: 0
wires: 3910
labels: 28453
```

**Pseudonyms registration:**

```bash
circom --r1cs --wasm circuits/pseudonym_check.circom

outputs:
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

**Sybil-resistance:**

```bash
circom --r1cs --wasm circuits/sybil_check.circom

outputs:
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

**Selective disclosure:**

```bash
circom --r1cs --wasm circuits/pedersen_commit.circom

outputs:
template instances: 99
non-linear constraints: 15856
linear constraints: 0
public inputs: 3
public outputs: 0
private inputs: 25
private outputs: 0
wires: 15841
labels: 118411
```

# Hades
Hades is an EVM-compatible decentralized identity system that supports privacy-preserving, accountability and application-level sybil-resistance.

Hades is implemented using Rust and Solidity. You can run it with:

```bash
cargo test --all
```

## Test results:

```c
running 1 test
test test_contract_saved has been running for over 60 seconds
start to set vk:
Set_derive_vk: 0x62e6d57611c4950534f9f4750afbb58908f8ad27d38b522210f21ddda03db163, Gas_used: Some(648420)
Set_appkey_vk: 0xe1d98ac785309aa5570dffc2ae6bd6ea043902a4f5eb7fb57883163bf9f84cb7, Gas_used: Some(523660)
Set_tpke_pub: 0x44ad4eb05239c52c4903136bd87018eddf4ffc58c65877fd204fcd86b4fab096, Gas_used: Some(63664)
start to set root:
Update_roots_hash: 0x7526c066d283da64b2af8db2391febd4f9e9722f536f41a3312737294c9905b7, Gas_used: Some(130207)
Init CA finish!
Credential proof time: 466 ms
Gen credential finish!
Register proof time: 1912 ms
Register: 0xd9e4b75b2bb2960242ab347b9c78140ab1aaab4f359485a036a21550cee0bed8, Gas_used: Some(354942)
Identity derive finish!
Appkey proof time: 468 ms
Set_appkey: 0x15c908e5d45ddd49ac801ab1b1f040bc34ccdfd96d7fc961e40fd005d20503eb, Gas_used: Some(248514)
Register proof time: 1873 ms
Register: 0xc32b3bb63c95fed992a7624f97f00fda49c7c5ab8b052f6b3a38718d58a4efe0, Gas_used: Some(339978)
Identity 2 derive finish!
Begin to revoke:
derived_address: [0x8181082017346679045203273291153336789837, 0x0056927037680436204345599445309492724824]
revoke_user: 0x26f8eb0ecbb4490ccd0ebafa026d0e21d3a01fc71bba7701f37d22f159230f24, Gas_used: Some(28486)
test test_contract_saved ... ok
```

## Circuits  constraints

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

Pseudonyms derivation:

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

Application key generation:

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
template instances: 14
non-linear constraints: 18778
linear constraints: 0
public inputs: 22
public outputs: 0
private inputs: 11
private outputs: 0
wires: 18759
labels: 141917
```
use baby_jub::{new_key, Point, PrivateKey};
use hades::ca_client::CA;
use hades::committee_client::Committee;
use hades::tpke::PublicKey;
use hades::user_client::Client;
use hades::convert;
use num_bigint::{BigInt, ToBigInt};
// use std::time::SystemTime;

#[test]
fn test_convert() {
    convert("./circuits/key_derive_js/key_derive.wasm", "./circuits/key_derive_js/key_derive.so");
    convert("./circuits/app_key_js/app_key.wasm", "./circuits/app_key_js/app_key.so");
    convert("./circuits/tpke_single_js/tpke_single.wasm", "./circuits/tpke_single_js/tpke_single.so");
}

#[test]
fn test_ca_serde() {
    let keys: Vec<PrivateKey> = (0..10).map(|_| new_key()).collect();
    let shards: Vec<Point> = keys.iter().map(|x| x.public()).collect();

    let tpke_key = PublicKey::new(shards.iter().map(|x| x).collect());
    let mut ca = CA::init(8, tpke_key.clone());
    let mut user = Client::new(tpke_key);

    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();

    let expiration = 31536000;

    let req = user.request_credential(attributes, expiration, &ca);

    let cred = ca.gen_credential(req).unwrap();

    user.fill_credential(cred);

    println!("start to save ca:");
    ca.save("./ca.tmp").unwrap();
    println!("start to load ca:");
    let ca2 = CA::load("./ca.tmp").unwrap();
    assert_eq!(ca.part1(), ca2.part1());
    assert_eq!(ca.zkp_params, ca2.zkp_params);

    println!("start to save user:");
    user.save("./user.tmp").unwrap();
    println!("start to load user:");
    let user2 = Client::load("./user.tmp").unwrap();
    assert_eq!(user, user2);
}

#[test]
fn test_committee_serde() {
    let mut cm1 = Committee::new();
    let tpke_key = PublicKey::new(vec![&cm1.tpke_shard(), &cm1.tpke_shard()]);
    cm1.update_tpke_key(tpke_key.clone());

    cm1.save("committee.tmp").unwrap();
    let cm2 = Committee::load("committee.tmp").unwrap();

    assert_eq!(cm1.part1(), cm2.part1());
    assert_eq!(cm1.app_params, cm2.app_params);
    assert_eq!(cm1.zkp_params, cm2.zkp_params);
}

use apdid::ca_client::CA;
use apdid::committee_client::Committee;
use apdid::tpke::PublicKey;
use apdid::user_client::Client;
use baby_jub::{new_key, Point, PrivateKey};
use num_bigint::{BigInt, ToBigInt};

use core::str::FromStr;

#[test]
fn test_credential_request() {
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
}

#[test]
fn test_key_derive() {
    // init commit
    let mut cm1 = Committee::new();
    let mut cm2 = cm1.clone();
    let tpke_key = PublicKey::new(vec![&cm1.tpke_shard(), &cm2.tpke_shard()]);
    cm1.update_tpke_key(tpke_key.clone());
    cm2.update_tpke_key(tpke_key.clone());
    cm2.update_zk_param(cm1.zkp_params.clone());

    println!("Init committee finish!");
    // create ca
    let mut ca = CA::init(8, tpke_key.clone());
    cm1.ca_tree.insert_nodes(vec![ca.pubkey().scalar_y()]);

    println!("Init CA finish!");

    // gen credential
    let mut user = Client::new(tpke_key);
    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();
    let expiration = 31536000;
    let req = user.request_credential(attributes, expiration, &ca);
    let cred = ca.gen_credential(req.clone()).unwrap();
    user.fill_credential(cred);

    println!("Gen credential finish!");

    // derive key
    let num = 10;
    let time_reserve = 1000;
    let address = BigInt::from_str("328659427551853837776595111020800456678649075473").unwrap();
    let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
    println!("Identity derive finish!");

    assert!(cm1.verify_key_request(&req2));
}

#[test]
fn test_app_key() {
    let mut cm1 = Committee::new();
    let mut cm2 = cm1.clone();
    let tpke_key = PublicKey::new(vec![&cm1.tpke_shard(), &cm2.tpke_shard()]);
    cm1.update_tpke_key(tpke_key.clone());
    cm2.update_tpke_key(tpke_key.clone());
    cm2.update_zk_param(cm1.zkp_params.clone());
    cm2.update_app_param(cm1.app_params.clone());

    println!("Init committee finish!");
    // create ca
    let mut ca = CA::init(8, tpke_key.clone());
    cm1.ca_tree.insert_nodes(vec![ca.pubkey().scalar_y()]);

    println!("Init CA finish!");

    // gen credential
    let mut user = Client::new(tpke_key);
    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();
    let expiration = 31536000;
    let req = user.request_credential(attributes, expiration, &ca);
    let cred = ca.gen_credential(req.clone()).unwrap();
    user.fill_credential(cred);

    println!("Gen credential finish!");

    // derive key
    let num = 10;
    let time_reserve = 1000;
    let address = BigInt::from_str("328659427551853837776595111020800456678649075473").unwrap();
    let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
    println!("Identity derive finish!");

    let appid = BigInt::from_str("628659427551853837776595111020800456678649075473").unwrap();
    let app_key = user.gen_appkey(&cm1, &req.master_key_g, &req2.sn, &appid);

    assert!(cm1.verify_app_key(&app_key));
}

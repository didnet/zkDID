// This is a test file, mainly used to test the application of credentials
// and pseudonym registration.

use baby_jub::{new_key, Point, PrivateKey};
use hades::ca_client::CA;
use hades::committee_client::Committee;
use hades::tpke::PublicKey;
use hades::user_client::Client;
use num_bigint::{BigInt, ToBigInt};
use baby_jub::G;

use core::str::FromStr;

#[test]
// Test the credential application.
fn test_credential_request() {
    // setup tpke
    let keys: Vec<PrivateKey> = (0..10).map(|_| new_key()).collect();
    let shards: Vec<Point> = keys.iter().map(|x| x.public()).collect();

    let tpke_key = PublicKey::new(shards.iter().map(|x| x).collect());
    // setup CA
    let mut ca = CA::init(8, tpke_key.clone());
    // setup user client
    let mut user = Client::new(tpke_key);

    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();

    let expiration = 31536000;
    
    // generate request
    let req = user.request_credential(attributes, expiration, &ca);
    // generate credential
    let cred = ca.gen_credential(req).unwrap();
    // save credential
    user.fill_credential(cred);
}

#[test]
// test pseudonym register
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

    // register the pseudonym
    let num = 10;
    let time_reserve = 1000;
    let address = BigInt::from_str("328659427551853837776595111020800456678649075473").unwrap();
    let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
    println!("Identity derive finish!");

    assert!(cm1.verify_key_request(&req2));
}

#[test]
// Test the response to sybil resistance.
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
    
    // application id
    let appid = BigInt::from_str("628659427551853837776595111020800456678649075473").unwrap();
    // generate proof
    let app_key = user.gen_appkey(&cm1, &req.master_key_g, &req2.sn, &appid);

    assert!(cm1.verify_app_key(&app_key));
}

#[test]
// Test the proof that identity attributes meet the assertion.
fn test_identity_proof() {
    // init a committee
    let mut cm1 = Committee::new();
    let mut cm2 = cm1.clone();
    let tpke_key = PublicKey::new(vec![&cm1.tpke_shard(), &cm2.tpke_shard()]);
    cm1.update_tpke_key(tpke_key.clone());
    cm2.update_tpke_key(tpke_key.clone());
    cm2.update_zk_param(cm1.zkp_params.clone());
    cm2.update_app_param(cm1.app_params.clone());

    println!("Init committee finish!");
    // create ca
    let mut ca = CA::load("./data/test_ca.bak").unwrap();
    ca.tpke_key = tpke_key.clone();
    for p in &ca.generators {
        println!("x: {:?}, y: {:?}", p.scalar_x(), p.scalar_y());
    }
    println!("x: {:?}, y: {:?}", G.scalar_x(), G.scalar_y());
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

    let (_a, _lrcm, proof, pub_inputs) = user.gen_identity_proof(
        &cm1, 
        &req.master_key_g, 
        &req2.sn,
        (0..8).map(|x| (x + 1).to_bigint().unwrap()).collect(),
        (0..8).map(|x| (x + 20).to_bigint().unwrap()).collect());
    assert!(cm1.verify_identity_proof(pub_inputs, &proof));
}
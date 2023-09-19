// This document is used to test the entire process of Hades and
// can also serve as an example to guide developers in using the
// components of Hades.
use color_eyre::Result;

use crate::ca_client::CA;
use crate::committee_client::Committee;
use crate::get_timestamp;
use crate::user_client::Client;
use num_bigint::{BigInt, ToBigInt};

use core::str::FromStr;

use ethers::{
    prelude::{LocalWallet, SignerMiddleware},
    providers::{Http, Provider},
    signers::Signer,
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

// bench function
pub async fn bench_all() -> Result<()> {
    // identity contract address
    let contract_address = "64228D9d16EC3E3dd88AF5d10984be801B1e84Dc";
    // launch the network
    let provider = Provider::<Http>::try_from("https://bsc-testnet.blockpi.network/v1/rpc/public")?
        .interval(Duration::from_millis(10u64));
    // the private key
    let wallet = "164c8c3b7e2b40c97e4a82d441fa6857288d3e61dbe6fe9c07e97c868b997c48"
        .parse::<LocalWallet>()?;

    // A client used to interact with the blockchain.
    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(97u64));
    let client = Arc::new(client);

    println!("1. Start setting up the committee: ");
    // load the committee data form file
    let mut cm1 = Committee::load("./data/test_cm1")?;
    let mut cm2 = Committee::load("./data/test_cm2")?;
    println!("1. The committee has been set up.");

    println!("2. Start setting up CA: ");
    // load the ca data from file
    let mut ca = CA::load("./data/test_ca.bak")?;
    ca.tpke_key = cm1.tpke_key.as_ref().unwrap().clone();
    println!("2.1 Start adding CA to trusted list: ");
    // add ca to the trusted list
    cm1.ca_tree.insert_nodes(vec![ca.pubkey().scalar_y()]);
    cm2.ca_tree.insert_nodes(vec![ca.pubkey().scalar_y()]);
    println!("2. CA has been set up.");

    println!("3. Start setting up the identity contract:");
    // Update the tpke public key to the identity contract.
    let _res = cm1.set_tpke_pub(contract_address, client.clone()).await?;
    println!("3. The identity contract has been set up.");

    println!("4. Start updating the identity contract:");
    // Update the roots to the identity contract.
    let _res = cm1
        .update_roots_hash(get_timestamp(), contract_address, client.clone())
        .await?;
    println!("4. The identity contract has been updated.");

    println!("5. Start requesting credential");
    // create an user client
    let mut user = Client::new(cm1.tpke_key.as_ref().unwrap().clone());
    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();
    let expiration = 31536000;
    // Make a credential request
    let req = user.request_credential(attributes, expiration, &ca);
    // Send the request to the CA, and get credential from the CA
    let cred = ca.gen_credential(req.clone()).unwrap();
    // The user save the credential
    user.fill_credential(cred);
    println!("5. Credential generated!");

    // register pseudonym
    print!("6. Start to generate pseudonyms: ");
    let time_reserve = 1000;
    // The blockchain address to be registered.
    let user_address =
        BigInt::from_str("739337313385053266296758871368793790953719109687").unwrap();
    // register the pseudonym
    let sn = user
        .register(
            &cm1,
            &req.master_key_g,
            time_reserve,
            &user_address,
            contract_address,
            client.clone(),
        )
        .await?;
    println!("6. pseudonym 1 generated.");

    // register another pseudonym
    let wallet2 = "227db26d4fdf8470567914916252422fa7a7a98499beca9f4bd85f4d25bc5cf6"
        .parse::<LocalWallet>()?;
    let client2 = SignerMiddleware::new(provider, wallet2.with_chain_id(97u64));
    let client2 = Arc::new(client2);
    // The blockchain address to be registered.
    let user_address2 = BigInt::from_str("1930620666092389790692418058692409015506454564").unwrap();
    let time_reserve = 100;
    // register the pseudonym
    let _sn2 = user
        .register(
            &cm1,
            &req.master_key_g,
            time_reserve,
            &user_address2,
            contract_address,
            client2.clone(),
        )
        .await?;
    println!("6. pseudonym 2 generated.");

    println!("7. Start to response to Sybil-resistance: ");
    // generate an application id
    let appid = BigInt::from_str("994862232198212916674956859767646391285724603386").unwrap();
    // generate a no-sybil proof, and send it to the identity contract
    let _res = user
        .send_appkey(
            &cm1,
            &req.master_key_g,
            &sn,
            &appid,
            contract_address,
            client.clone(),
        )
        .await?;
    println!("7. proof accepted.");

    println!("8. Start to prove identity attributes (Selective disclosure):");
    // generate an identity proof, and send it to the identity contract
    let _res = user
        .verify_identity(
            &cm1,
            &req.master_key_g,
            &sn,
            (0..8).map(|x| (x + 1).to_bigint().unwrap()).collect(),
            (0..8).map(|x| (x + 20).to_bigint().unwrap()).collect(),
            contract_address,
            client.clone(),
        )
        .await?;
    println!("8. proof accepted.");

    println!("9. Start to audit:");
    // get the cipher of corresponding user infomation for the CA
    let user_meta = cm1
        .get_user_meta(
            "8181082017346679045203273291153336789837",
            contract_address,
            client.clone(),
        )
        .await?
        .unwrap();
    let cipher1 = user_meta.to_cipher();
    // get decryption shard
    let k1 = cm1.decrypt_shard(&cipher1.c1);
    // get decryption shard
    let k2 = cm2.decrypt_shard(&cipher1.c1);
    // decrpt the ciphper
    let (m1, m2) = cipher1.decrypt(vec![&k1, &k2], &user_address);

    assert_eq!(m2, ca.pubkey());

    // get user info
    let user_info = ca.get_user_info(&m1).unwrap();
    println!("9. User info revealed");

    println!("10. Start to trace user: ");
    // get decryption shard
    let k2_1 = cm1.decrypt_shard(&user_info.cipher.c1);
    // get decryption shard
    let k2_2 = cm2.decrypt_shard(&user_info.cipher.c1);

    // decrtption and reveal the trap-door
    let beta = user_info.cipher.decrypt(vec![&k2_1, &k2_2]).scalar_y();

    // trace
    let derived_address = cm1
        .get_derived_address(&beta, contract_address, client.clone())
        .await?;
    println!("10. all pseudonyms traced: {:?}", derived_address);

    println!("11. Start to revoke user:");
    println!("11.1 Start to revoke credential:");
    // revoke the credential
    let _res = cm1
        .revoke_credential(get_timestamp(), vec![m1], contract_address, client.clone())
        .await?;
    println!("11.1 Credential revoked!");
    println!("11.2 Start to revoke pesudonyms:");
    // revoke the pesudonyms
    let _res = cm1
        .revoke_user(derived_address, contract_address, client.clone())
        .await?;
    println!("11.2 Pesudonyms revoked.");
    Ok(())
}

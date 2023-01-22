use color_eyre::Result;

use apdid::ca_client::CA;
use apdid::committee_client::Committee;
use apdid::tpke::PublicKey;
use apdid::user_client::Client;
use apdid::IdentityManager;
use num_bigint::{BigInt, Sign, ToBigInt};

use core::str::FromStr;

use ethers::{
    prelude::{LocalWallet, SignerMiddleware},
    providers::{Http, Provider},
    signers::Signer,
    types::{Address, H256, U256},
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

#[test]
fn test_convert() {
    let n1 = BigInt::from_str("739337313385053266296758871368793790953719109687").unwrap();
    let n2 = U256::from_little_endian(&n1.to_bytes_le().1);
    println!("{:?}", n1);
    println!("{:?}", n2);
    let mut le_bytes = vec![1u8; 32];
    n2.to_little_endian(&mut le_bytes);
    println!("{:?}", le_bytes);
    let n3 = BigInt::from_bytes_le(Sign::Plus, &le_bytes);
    assert_eq!(n1, n3);
}

#[test]
fn test_h256() {
    let n1 = BigInt::from_str("739337313385053266296758871368793790953719109687").unwrap();
    let mut res = [0u8; 32];
    let le_bytes = n1.to_bytes_be().1;
    let l = 32 - le_bytes.len();
    for i in 0..le_bytes.len() {
        res[l + i] = le_bytes[i];
    }

    let n2: H256 = res.into();

    println!("{:?}", n1);
    println!("{:?}", n2);
}

#[tokio::test]
async fn test_logs() -> Result<()> {
    let contract_address = "6bb57a2136360F111f98B570b6b6c6a7a62d2067".parse::<Address>()?;
    // launch the network & compile the verifier
    let provider = Provider::<Http>::try_from("https://rpc.ankr.com/fantom_testnet")?
        .interval(Duration::from_millis(10u64));

    let wallet = "164c8c3b7e2b40c97e4a82d441fa6857288d3e61dbe6fe9c07e97c868b997c48"
        .parse::<LocalWallet>()?;
    // let address = contract_address.parse::<Address>()?;

    let client = SignerMiddleware::new(provider, wallet.with_chain_id(4002u64));
    let client = Arc::new(client);

    let contract = IdentityManager::new(contract_address, client.clone());

    let user_address = "8181082017346679045203273291153336789837".parse::<Address>()?;

    let logs = contract
        .user_register_filter()
        .topic1(vec![user_address, contract_address])
        .from_block(13091295u64)
        .query()
        .await?;
    println!("{:?}", logs);

    Ok(())
}

#[tokio::test]
async fn test_contract() -> Result<()> {
    let contract_address = "5367Dd55bb17FBbB6ee3E67bfAbc4CAE12d476F7";
    // launch the network & compile the verifier
    let provider = Provider::<Http>::try_from("https://rpc.ankr.com/bsc_testnet_chapel")?
        .interval(Duration::from_millis(10u64));

    let wallet = "164c8c3b7e2b40c97e4a82d441fa6857288d3e61dbe6fe9c07e97c868b997c48"
        .parse::<LocalWallet>()?;
    // let address = contract_address.parse::<Address>()?;

    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(97u64));
    let client = Arc::new(client);

    let mut cm1 = Committee::new();
    let mut cm2 = cm1.clone();
    let tpke_key = PublicKey::new(vec![&cm1.tpke_shard(), &cm2.tpke_shard()]);
    cm1.update_tpke_key(tpke_key.clone());
    cm2.update_tpke_key(tpke_key.clone());
    cm2.update_zk_param(cm1.zkp_params.clone());
    cm2.update_app_param(cm1.app_params.clone());

    println!("start to set vk:");
    let _res = cm1.set_derive_vk(contract_address, client.clone()).await?;
    let _res = cm1.set_appkey_vk(contract_address, client.clone()).await?;
    let _res = cm1.set_tpke_pub(contract_address, client.clone()).await?;

    println!("Init committee finish!");
    // create ca
    let mut ca = CA::init(8, tpke_key.clone());
    cm1.ca_tree.insert_nodes(vec![ca.pubkey().scalar_y()]);

    println!("start to set root:");
    let _res = cm1
        .update_roots_hash(3, contract_address, client.clone())
        .await?;

    println!("Init CA finish!");
    
    // cm1.save("./cm1.tmp")?;
    // cm2.save("./cm2.tmp")?;
    // ca.save("./ca.tmp")?;
    
    // println!("Saved!");

    // gen credential
    let mut user = Client::new(tpke_key);
    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();
    let expiration = 31536000;
    let req = user.request_credential(attributes, expiration, &ca);
    let cred = ca.gen_credential(req.clone()).unwrap();
    user.fill_credential(cred);

    println!("Gen credential finish!");

    // derive key
    let time_reserve = 1000;
    let user_address =
        BigInt::from_str("739337313385053266296758871368793790953719109687").unwrap();
    // let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
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
    println!("Identity derive finish!");

    let appid = BigInt::from_str("994862232198212916674956859767646391285724603386").unwrap();
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
    
    let wallet2 = "227db26d4fdf8470567914916252422fa7a7a98499beca9f4bd85f4d25bc5cf6"
        .parse::<LocalWallet>()?;
    // let address = contract_address.parse::<Address>()?;

    let client2 = SignerMiddleware::new(provider, wallet2.with_chain_id(97u64));
    let client2 = Arc::new(client2);
    let user_address2 = BigInt::from_str("1930620666092389790692418058692409015506454564").unwrap();
    let time_reserve = 100;
    // let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
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
    println!("Identity 2 derive finish!");

    println!("Begin to revoke:");
    let user_meta = cm1.get_user_meta("8181082017346679045203273291153336789837", contract_address, client.clone()).await?.unwrap();
    let cipher1 = user_meta.to_cipher();
    let k1 = cm1.decrypt_shard(&cipher1.c1);
    let k2 = cm2.decrypt_shard(&cipher1.c1);

    let (m1, m2) = cipher1.decrypt(vec![&k1, &k2], &user_address);

    assert_eq!(m2, ca.pubkey());

    let user_info = ca.get_user_info(&m1).unwrap();

    let k2_1 = cm1.decrypt_shard(&user_info.cipher.c1);
    let k2_2 = cm2.decrypt_shard(&user_info.cipher.c1);

    let beta = user_info.cipher.decrypt(vec![&k2_1, &k2_2]).scalar_y();

    let derived_address = cm1.get_derived_address(&beta, contract_address, client.clone()).await?;
    println!("derived_address: {:?}", derived_address);

    let _res = cm1.revoke_user(derived_address, contract_address, client.clone()).await?;


    Ok(())
}

#[tokio::test]
async fn test_contract_saved() -> Result<()> {
    let contract_address = "15f2c8203856d3e66DdbBf6738Ae362CD0528691";
    // launch the network & compile the verifier
    let provider = Provider::<Http>::try_from("https://rpc.ankr.com/bsc_testnet_chapel")?
        .interval(Duration::from_millis(10u64));

    let wallet = "164c8c3b7e2b40c97e4a82d441fa6857288d3e61dbe6fe9c07e97c868b997c48"
        .parse::<LocalWallet>()?;
    // let address = contract_address.parse::<Address>()?;

    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(97u64));
    let client = Arc::new(client);

    let cm1 = Committee::load("./tcm1.tmp")?;
    // let cm2 = Committee::load("./tcm2.tmp")?;
    let cm2 = cm1.clone();
    let mut ca = CA::load("./tca.tmp")?;

    println!("start to set vk:");
    let _res = cm1.set_derive_vk(contract_address, client.clone()).await?;
    let _res = cm1.set_appkey_vk(contract_address, client.clone()).await?;
    let _res = cm1.set_tpke_pub(contract_address, client.clone()).await?;

    println!("start to set root:");
    let _res = cm1
        .update_roots_hash(3, contract_address, client.clone())
        .await?;

    println!("Init CA finish!");

    // gen credential
    let mut user = Client::new(cm1.tpke_key.as_ref().unwrap().clone());
    let attributes: Vec<BigInt> = (0..8).map(|x| (x + 10).to_bigint().unwrap()).collect();
    let expiration = 31536000;
    let req = user.request_credential(attributes, expiration, &ca);
    let cred = ca.gen_credential(req.clone()).unwrap();
    user.fill_credential(cred);

    println!("Gen credential finish!");

    // derive key
    let time_reserve = 1000;
    let user_address =
        BigInt::from_str("739337313385053266296758871368793790953719109687").unwrap();
    // let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
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
    println!("Identity derive finish!");

    let appid = BigInt::from_str("994862232198212916674956859767646391285724603386").unwrap();
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
    
    let wallet2 = "227db26d4fdf8470567914916252422fa7a7a98499beca9f4bd85f4d25bc5cf6"
        .parse::<LocalWallet>()?;
    // let address = contract_address.parse::<Address>()?;

    let client2 = SignerMiddleware::new(provider, wallet2.with_chain_id(97u64));
    let client2 = Arc::new(client2);
    let user_address2 = BigInt::from_str("1930620666092389790692418058692409015506454564").unwrap();
    let time_reserve = 100;
    // let req2 = user.derive_identity(&cm1, &req.master_key_g, time_reserve, &address, num);
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
    println!("Identity 2 derive finish!");

    println!("Begin to revoke:");
    let user_meta = cm1.get_user_meta("8181082017346679045203273291153336789837", contract_address, client.clone()).await?.unwrap();
    let cipher1 = user_meta.to_cipher();
    let k1 = cm1.decrypt_shard(&cipher1.c1);
    let k2 = cm2.decrypt_shard(&cipher1.c1);

    let (m1, m2) = cipher1.decrypt(vec![&k1, &k2], &user_address);

    assert_eq!(m2, ca.pubkey());

    let user_info = ca.get_user_info(&m1).unwrap();

    let k2_1 = cm1.decrypt_shard(&user_info.cipher.c1);
    let k2_2 = cm2.decrypt_shard(&user_info.cipher.c1);

    let beta = user_info.cipher.decrypt(vec![&k2_1, &k2_2]).scalar_y();

    let derived_address = cm1.get_derived_address(&beta, contract_address, client.clone()).await?;
    println!("derived_address: {:?}", derived_address);

    let _res = cm1.revoke_user(derived_address, contract_address, client.clone()).await?;


    Ok(())
}
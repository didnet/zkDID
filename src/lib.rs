// This file contains code for interacting with the on-chain identity contract,
// providing the capability to send transactions or query contracts.

use ark_circom::ethereum;
use baby_jub::Point;
use color_eyre::Result;
use ethers::prelude::abigen;
use ethers::providers::Middleware;
use ethers::types::U256;
use num_bigint::{BigInt, Sign};
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use ark_circom::WitnessCalculator;

pub mod ca_client;
pub mod committee_client;
pub mod merkle_tree;
pub mod tpke;
pub mod user_client;
pub mod bench;

pub fn get_timestamp() -> u64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

// convert r1cs 
pub fn convert(from: impl AsRef<std::path::Path>, to: impl AsRef<std::path::Path>) {
    WitnessCalculator::save(from, to).unwrap();
}

// gen contract abi
abigen!(IdentityManager, "./contracts/manager.json");
// use identity_manager::{G1Point, G2Point, Proof, VerifyingKey};
use tpke::CipherDual;

// struct convert
impl From<ethereum::G1> for G1Point {
    fn from(src: ethereum::G1) -> Self {
        Self { x: src.x, y: src.y }
    }
}

// struct convert
impl From<ethereum::G2> for G2Point {
    fn from(src: ethereum::G2) -> Self {
        // We should use the `.as_tuple()` method which handles converting
        // the G2 elements to have the second limb first
        let src = src.as_tuple();
        Self { x: src.0, y: src.1 }
    }
}

// struct convert
impl From<ethereum::Proof> for Proof {
    fn from(src: ethereum::Proof) -> Self {
        Self {
            a: src.a.into(),
            b: src.b.into(),
            c: src.c.into(),
        }
    }
}

// struct convert
impl From<ethereum::VerifyingKey> for VerifyingKey {
    fn from(src: ethereum::VerifyingKey) -> Self {
        Self {
            alfa_1: src.alpha1.into(),
            beta_2: src.beta2.into(),
            gamma_2: src.gamma2.into(),
            delta_2: src.delta2.into(),
            ic: src.ic.into_iter().map(|i| i.into()).collect(),
        }
    }
}

impl IdentityFullMeta {
    // Decompress onchain data
    pub fn to_cipher(&self) -> CipherDual {
        let mut le_bytes = vec![0u8; 32];
        self.c1.to_little_endian(&mut le_bytes);
        let c1y = BigInt::from_bytes_le(Sign::Plus, &le_bytes);
        self.c2.to_little_endian(&mut le_bytes);
        let c2y = BigInt::from_bytes_le(Sign::Plus, &le_bytes);
        self.c3.to_little_endian(&mut le_bytes);
        let c3y = BigInt::from_bytes_le(Sign::Plus, &le_bytes);
        let c1 = Point::from_y(&c1y, (self.ei & U256::one()) == U256::one()).unwrap();
        let c2 = Point::from_y(&c2y, ((self.ei >> 1) & U256::one()) == U256::one()).unwrap();
        let c3 = Point::from_y(&c3y, ((self.ei >> 2) & U256::one()) == U256::one()).unwrap();

        CipherDual { c1, c2, c3 }
    }
}

impl<M: Middleware + 'static> IdentityManager<M> {
    // register pseudonyms
    async fn do_register<I: Into<ethereum::Inputs>, P: Into<ethereum::Proof>>(
        &self,
        proof: P,
        inputs: I,
    ) -> Result<bool> {
        // convert into the expected format by the contract
        let proof = proof.into().into();
        let inputs = inputs.into().0.try_into().unwrap();

        // query the contract
        let _res = self.register(inputs, proof).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    
    // push zero-knowledge proof parameters to the identity contract.
    async fn do_set_appkey<P: Into<ethereum::Proof>>(
        &self,
        user: &BigInt,
        appkey: &BigInt,
        appid: &BigInt,
        proof: P,
    ) -> Result<bool> {
        // convert into the expected format by the contract
        let proof = proof.into().into();
        let user_e = U256::from_little_endian(&user.to_bytes_le().1);
        let appkey_e = U256::from_little_endian(&appkey.to_bytes_le().1);
        let appid_e = U256::from_little_endian(&appid.to_bytes_le().1);

        // send transactions
        let _res = self
            .set_appkey(user_e, appkey_e, appid_e, proof)
            .send()
            .await?
            .await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    
    // verify identitys on identity contract
    async fn do_veriy_identity<P: Into<ethereum::Proof>>(
        &self,
        ax: &BigInt,
        ay: &BigInt,
        lrcm: &BigInt,
        proof: P,
    ) -> Result<bool> {
        // convert into the expected format by the contract
        let proof = proof.into().into();
        let ax_e = U256::from_little_endian(&ax.to_bytes_le().1);
        let ay_e = U256::from_little_endian(&ay.to_bytes_le().1);
        let lrcm_e = U256::from_little_endian(&lrcm.to_bytes_le().1);

        // send transactions
        let _res = self
            .verify_identity(ax_e, ay_e, lrcm_e, proof)
            .send()
            .await?
            .await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    
    // push zero-knowledge proof parameters to the identity contract.
    async fn do_set_derive_vk<VK: Into<ethereum::VerifyingKey>>(&self, vk: VK) -> Result<bool> {
        // convert into the expected format by the contract
        let vk = vk.into().into();
        // println!("derive_vk: {:?}", vk);
        // query the contract
        let _res = self.set_derive_vk(vk).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    
    // push zero-knowledge proof parameters to the identity contract.
    async fn do_set_appkey_vk<VK: Into<ethereum::VerifyingKey>>(&self, vk: VK) -> Result<bool> {
        // convert into the expected format by the contract
        let vk = vk.into().into();
        // query the contract
        // println!("app: {:?}", vk);
        let _res = self.set_appkey_vk(vk).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
}

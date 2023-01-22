// extern crate curve25519_dalek;
use ark_circom::ethereum;
use baby_jub::Point;
use color_eyre::Result;
use ethers::prelude::abigen;
use ethers::providers::Middleware;
use ethers::types::U256;
use num_bigint::{BigInt, Sign};
use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::TryInto;

pub mod ca_client;
pub mod committee_client;
pub mod merkle_tree;
pub mod tpke;
pub mod user_client;

pub fn get_timestamp() -> u64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

abigen!(IdentityManager, "./contracts/manager.json");
use identity_manager::{G1Point, G2Point, Proof, VerifyingKey};
use tpke::CipherDual;

impl From<ethereum::G1> for G1Point {
    fn from(src: ethereum::G1) -> Self {
        Self { x: src.x, y: src.y }
    }
}
impl From<ethereum::G2> for G2Point {
    fn from(src: ethereum::G2) -> Self {
        // We should use the `.as_tuple()` method which handles converting
        // the G2 elements to have the second limb first
        let src = src.as_tuple();
        Self { x: src.0, y: src.1 }
    }
}
impl From<ethereum::Proof> for Proof {
    fn from(src: ethereum::Proof) -> Self {
        Self {
            a: src.a.into(),
            b: src.b.into(),
            c: src.c.into(),
        }
    }
}
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
            "Register: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }

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

        // query the contract
        let _res = self
            .set_appkey(user_e, appkey_e, appid_e, proof)
            .send()
            .await?
            .await?;
        let _res = _res.unwrap();
        println!(
            "Set_appkey: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    async fn do_set_derive_vk<VK: Into<ethereum::VerifyingKey>>(&self, vk: VK) -> Result<bool> {
        // convert into the expected format by the contract
        let vk = vk.into().into();

        // query the contract
        let _res = self.set_derive_vk(vk).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "Set_derive_vk: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
    async fn do_set_appkey_vk<VK: Into<ethereum::VerifyingKey>>(&self, vk: VK) -> Result<bool> {
        // convert into the expected format by the contract
        let vk = vk.into().into();
        // query the contract
        let _res = self.set_appkey_vk(vk).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "Set_appkey_vk: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(true)
    }
}

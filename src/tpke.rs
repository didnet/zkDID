use baby_jub::{poseidon_hash, Point, G, Q};
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(Point);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cipher {
    pub c1: Point,
    pub c2: Point,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CipherDual {
    pub c1: Point,
    pub c2: Point,
    pub c3: Point,
}

impl PublicKey {
    // TODO: use ss
    pub fn new(shards: Vec<&Point>) -> Self {
        let r = shards
            .into_iter()
            .fold(Point::identity(), |sum, val| sum + val);
        PublicKey(r)
    }

    pub fn encrypt(&self, msg: &Point) -> (Cipher, BigInt) {
        let mut rng = rand::thread_rng();
        let k = &(rng.gen_biguint(256).to_bigint().unwrap() % Q.clone());
        let c1 = k * G.clone();
        let c2 = k * &self.0 + msg;
        (Cipher { c1, c2 }, k.clone())
    }

    pub fn encrypt_dual(&self, msg1: &Point, msg2: &Point, salt: &BigInt) -> (CipherDual, BigInt) {
        let mut rng = rand::thread_rng();
        let k = &(rng.gen_biguint(256).to_bigint().unwrap() % Q.clone());
        let c1 = k * G.clone();
        let ky = k * &self.0;
        let c2 = &ky + msg1;
        let c3 =
            poseidon_hash(vec![&ky.scalar_x(), &ky.scalar_y(), salt]).unwrap() * G.clone() + msg2;
        (CipherDual { c1, c2, c3 }, k.clone())
    }

    pub fn encrypt_dual_with_nonce(
        &self,
        msg1: &Point,
        msg2: &Point,
        salt: &BigInt,
        k: &BigInt,
    ) -> CipherDual {
        let c1 = k * G.clone();
        let ky = k * &self.0;
        let c2 = &ky + msg1;
        let c3 =
            poseidon_hash(vec![&ky.scalar_x(), &ky.scalar_y(), salt]).unwrap() * G.clone() + msg2;
        CipherDual { c1, c2, c3 }
    }
}

impl Deref for PublicKey {
    type Target = Point;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Cipher {
    // TODO: use ss
    pub fn decrypt(&self, shards: Vec<&Point>) -> Point {
        let c = shards
            .into_iter()
            .fold(Point::identity(), |sum, val| sum + val);
        self.c2.clone() + c.negative()
    }
}

impl CipherDual {
    // TODO: use ss
    pub fn decrypt(&self, shards: Vec<&Point>, salt: &BigInt) -> (Point, Point) {
        let c = shards
            .into_iter()
            .fold(Point::identity(), |sum, val| sum + val);
        let res1 = self.c2.clone() + c.negative();
        let c3_1 = poseidon_hash(vec![&c.scalar_x(), &c.scalar_y(), salt]).unwrap() * G.clone();
        let res2 = self.c3.clone() + c3_1.negative();
        (res1, res2)
    }
}

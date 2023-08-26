use crate::merkle_tree::{DualTree, MerkleTree};
use crate::tpke::PublicKey;
use crate::user_client::{ApplicationKey, IdentityRequest};
use crate::{BabyPoint, IdentityFullMeta, IdentityManager};
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, KeySize};
use ark_serialize::*;
use baby_jub::{new_key, poseidon_hash, Point, G};
use color_eyre::Result;
use num_bigint::{BigInt, ToBigInt};
use postcard::{from_bytes, to_stdvec};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use ark_ff::bytes::ToBytes;
use std::io::{BufReader, BufWriter};
use std::time::SystemTime;

use ethers::{
    prelude::SignerMiddleware, providers::Middleware, signers::Signer, types::Address, types::U256,
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Committee {
    pub tpke_sec: BigInt,
    pub ca_tree: MerkleTree,
    pub block_tree: DualTree,
    pub zkp_cfg: CircomConfig<Bn254>,
    pub zkp_params: ProvingKey<Bn254>,
    pub app_cfg: CircomConfig<Bn254>,
    pub app_params: ProvingKey<Bn254>,
    pub tpke_key: Option<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitteePart1 {
    pub tpke_sec: BigInt,
    pub ca_tree: MerkleTree,
    pub block_tree: DualTree,
    pub tpke_key: Option<PublicKey>,
}

impl Committee {
    pub fn new() -> Self {
        let tpke_sec = new_key().scalar_key();

        //TODO: make trust setup
        let cfg = CircomConfig::<Bn254>::load(
            "./circuits/key_derive_js/key_derive.so",
            "./circuits/key_derive.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let builder = CircomBuilder::new(cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        println!("para_gen: {:?}", SystemTime::now());
        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();
        println!("para_gen_done: {:?}", SystemTime::now());

        let app_cfg = CircomConfig::<Bn254>::load(
            "./circuits/app_key_js/app_key.so",
            "./circuits/app_key.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let builder = CircomBuilder::new(app_cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        let app_params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        Self {
            tpke_sec,
            ca_tree: MerkleTree::new(20),
            block_tree: DualTree::new(32),
            zkp_cfg: cfg,
            zkp_params: params,
            app_cfg,
            app_params,
            tpke_key: None,
        }
    }

    pub fn part1(&self) -> CommitteePart1 {
        CommitteePart1 {
            tpke_sec: self.tpke_sec.clone(),
            ca_tree: self.ca_tree.clone(),
            block_tree: self.block_tree.clone(),
            tpke_key: self.tpke_key.clone(),
        }
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file1 = File::create(path.to_owned() + ".1")?;
        let file2 = File::create(path.to_owned() + ".2")?;
        let file3 = File::create(path.to_owned() + ".3")?;
        let file4 = File::create(path.to_owned() + ".4")?;
        let file5 = File::create(path.to_owned() + ".5")?;

        let p1_data = to_stdvec(&self.part1()).unwrap();
        file1.write_all(&p1_data)?;
        
        let w2 = BufWriter::new(file2);
        self.zkp_params.size().serialize_unchecked(w2).unwrap();
        let w3 = BufWriter::new(file3);
        self.app_params.size().serialize_unchecked(w3).unwrap();
        let w4 = BufWriter::new(file4);
        self.zkp_params.write(w4).unwrap();
        let w5 = BufWriter::new(file5);
        self.app_params.write(w5).unwrap();

        Ok(())
    }

    pub fn load(path: &str) -> std::io::Result<Self> {
        let p1_data = fs::read(path.to_owned() + ".1")?;
        let p1: CommitteePart1 = from_bytes(&p1_data).unwrap();
        println!("zkp_size: {:?}", SystemTime::now());
        let file2 = File::open(path.to_owned() + ".2")?;
        let reader2 = BufReader::new(file2);
        let zkp_size = KeySize::deserialize_unchecked(reader2).unwrap();
        let file3 = File::open(path.to_owned() + ".3")?;
        let reader3 = BufReader::new(file3);
        let app_size = KeySize::deserialize_unchecked(reader3).unwrap();
        
        println!("zkp_des: {:?}", SystemTime::now());
        let file4 = File::open(path.to_owned() + ".4")?;
        let reader4 = BufReader::new(file4);
        let zkp_params = ProvingKey::<Bn254>::read(reader4, &zkp_size);

        println!("app_des: {:?}", SystemTime::now());
        let file5 = File::open(path.to_owned() + ".5")?;
        let reader5 = BufReader::new(file5);
        let app_params = ProvingKey::<Bn254>::read(reader5, &app_size);
        println!("zkp_cfg: {:?}", SystemTime::now());
        let zkp_cfg = CircomConfig::<Bn254>::load(
            "./circuits/key_derive_js/key_derive.so",
            "./circuits/key_derive.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });
        println!("app_cfg: {:?}", SystemTime::now());
        let app_cfg = CircomConfig::<Bn254>::load(
            "./circuits/app_key_js/app_key.so",
            "./circuits/app_key.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });
        println!("done: {:?}", SystemTime::now());

        Ok(Committee {
            tpke_sec: p1.tpke_sec,
            ca_tree: p1.ca_tree,
            block_tree: p1.block_tree,
            zkp_cfg,
            zkp_params,
            app_cfg,
            app_params,
            tpke_key: p1.tpke_key,
        })
    }

    pub fn tpke_shard(&self) -> Point {
        &self.tpke_sec * G.clone()
    }

    pub fn update_tpke_key(&mut self, tpke_key: PublicKey) {
        self.tpke_key = Some(tpke_key);
    }

    pub fn update_zk_param(&mut self, zkp_params: ProvingKey<Bn254>) {
        self.zkp_params = zkp_params;
    }

    pub fn update_app_param(&mut self, app_params: ProvingKey<Bn254>) {
        self.app_params = app_params;
    }

    pub fn verify_key_request(&self, req: &IdentityRequest) -> bool {
        // verif proof
        let pvk = prepare_verifying_key(&self.zkp_params.vk);

        verify_proof(&pvk, &req.proof, &req.pub_inputs).unwrap()
    }

    pub fn verify_app_key(&self, appkey: &ApplicationKey) -> bool {
        let pvk = prepare_verifying_key(&self.app_params.vk);

        verify_proof(&pvk, &appkey.proof, &appkey.pub_inputs).unwrap()
    }

    pub fn decrypt_shard(&self, c1: &Point) -> Point {
        &self.tpke_sec * c1
    }

    pub async fn add_committee<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        cm: BigInt,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());

        let cm2 = U256::from_little_endian(&cm.to_bytes_le().1);
        // query the contract
        let _res = contract.add_committee(cm2.into()).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "Add_committee: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    pub async fn update_roots_hash<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        version: u64,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        let (root1, root2) = self.block_tree.roots();
        let root_ca = self.ca_tree.root();
        let y = self.tpke_key.as_deref().unwrap().scalar_y();

        let rh1 = poseidon_hash(vec![&root1, &root_ca, &y]).unwrap();
        let rh2 = poseidon_hash(vec![&root2, &root_ca, &y]).unwrap();
        let rh1: U256 = U256::from_little_endian(&rh1.to_bytes_le().1);
        let rh2: U256 = U256::from_little_endian(&rh2.to_bytes_le().1);

        let _res = contract
            .update_roots_hash(rh1, rh2, U256::from(version).into())
            .send()
            .await?
            .await?;
        let _res = _res.unwrap();
        println!(
            "Update_roots_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    pub async fn set_tpke_pub<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());

        let x = self.tpke_key.as_deref().unwrap().scalar_x();
        let y = self.tpke_key.as_deref().unwrap().scalar_y();
        let key = BabyPoint {
            x: U256::from_little_endian(&x.to_bytes_le().1).into(),
            y: U256::from_little_endian(&y.to_bytes_le().1).into(),
        };

        // query the contract
        let _res = contract.set_tpke_pub(key).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "Set_tpke_pub: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    pub async fn set_derive_vk<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        // query the contract
        let _res = contract
            .do_set_derive_vk(self.zkp_params.vk.clone())
            .await?;
        Ok(())
    }

    pub async fn set_appkey_vk<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        // query the contract
        let _res = contract
            .do_set_appkey_vk(self.app_params.vk.clone())
            .await?;
        Ok(())
    }

    pub async fn revoke_user<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        user_address: Vec<Address>,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        // query the contract
        let _res = contract.revoke(user_address).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "revoke_user: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    pub async fn get_user_meta<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        user_address: &str,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<Option<IdentityFullMeta>> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        let user_address = user_address.parse::<Address>()?;
        let bn = client.get_block_number().await?;
        // query the contract
        let logs = contract
            .user_register_filter()
            .topic1(vec![user_address])
            .from_block(bn - 500)
            .query()
            .await?;
        if logs.len() > 0 {
            Ok(Some(logs[logs.len() - 1].meta.clone()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_derived_address<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        beta: &BigInt,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<Vec<Address>> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        let n = contract.num_of_address().call().await?;
        let bn = client.get_block_number().await?;

        let c1ys: Vec<[u8; 32]> = (0u64..(n.as_u64()))
            .map(|id| {
                (poseidon_hash(vec![beta, &(id as usize).to_bigint().unwrap()]).unwrap()
                    * G.clone())
                .scalar_y()
            })
            .map(|bn| {
                let mut res = [0u8; 32];
                let be_bytes = bn.to_bytes_be().1;
                let l = 32 - be_bytes.len();
                for i in 0..be_bytes.len() {
                    res[l + i] = be_bytes[i];
                }
                res
            })
            .collect();

        // query the contract
        let logs = contract
            .user_marked_filter()
            .topic1(c1ys)
            .from_block(bn - 500) // for test
            .query()
            .await?;
        let address_all: Vec<Address> = logs.iter().map(|v| v.user).collect();

        Ok(address_all)
    }
}

// This file is used to run the committee client, containing all the functions
// required by the committee, including initialization, CA management, committee
// node management, identity contract management, and identity management (audit,
// trace, revoke, witch resistance, identity verification), etc.

use crate::merkle_tree::{DualTree, MerkleTree};
use crate::tpke::PublicKey;
use crate::user_client::{ApplicationKey, IdentityRequest};
use crate::{BabyPoint, IdentityFullMeta, IdentityManager};
use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ff::bytes::ToBytes;
use ark_groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, KeySize, Proof, ProvingKey,
};
use ark_serialize::*;
use baby_jub::{new_key, poseidon_hash, Point, G};
use color_eyre::Result;
use num_bigint::{BigInt, ToBigInt};
use postcard::{from_bytes, to_stdvec};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;

use std::io::{BufReader, BufWriter};

use ethers::{
    prelude::SignerMiddleware, providers::Middleware, signers::Signer, types::Address, types::U256,
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Committee {
    // Private key shard used in threshold public key encryption.
    pub tpke_sec: BigInt,
    // A Merkle tree used to store the list of CAs.
    pub ca_tree: MerkleTree,
    // A Merkle tree used to store the list of revoked credentials.
    pub block_tree: DualTree,
    // zero kownledge proofs
    pub zkp_cfg: CircomConfig<Bn254>,
    pub zkp_params: ProvingKey<Bn254>,
    pub app_cfg: CircomConfig<Bn254>,
    pub app_params: ProvingKey<Bn254>,
    pub pedersen_cfg: CircomConfig<Bn254>,
    pub pedersen_params: ProvingKey<Bn254>,
    // public key of tpke encryption
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
    // Initialize a committee node.
    pub fn new() -> Self {
        // generate shard of tpke private key
        let tpke_sec = new_key().scalar_key();

        // TODO: make trust setup
        //
        let cfg = CircomConfig::<Bn254>::load(
            "./circuits/pseudonym_check.so",
            "./circuits/pseudonym_check.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let builder = CircomBuilder::new(cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        let app_cfg =
            CircomConfig::<Bn254>::load("./circuits/sybil_check.so", "./circuits/sybil_check.r1cs")
                .unwrap_or_else(|error| {
                    panic!("{:?}", error);
                });

        let builder = CircomBuilder::new(app_cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        let app_params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        let pedersen_cfg = CircomConfig::<Bn254>::load(
            "./circuits/pedersen_commit.so",
            "./circuits/pedersen_commit.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let builder = CircomBuilder::new(pedersen_cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        let pedersen_params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        Self {
            tpke_sec,
            ca_tree: MerkleTree::new(31),  // 20
            block_tree: DualTree::new(41), // 32
            zkp_cfg: cfg,
            zkp_params: params,
            app_cfg,
            app_params,
            pedersen_cfg,
            pedersen_params,
            tpke_key: None,
        }
    }

    // part of committee, used in serialization
    pub fn part1(&self) -> CommitteePart1 {
        CommitteePart1 {
            tpke_sec: self.tpke_sec.clone(),
            ca_tree: self.ca_tree.clone(),
            block_tree: self.block_tree.clone(),
            tpke_key: self.tpke_key.clone(),
        }
    }

    // save committee data in a file
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file1 = File::create(path.to_owned() + ".dat")?;
        let file2 = File::create(path.to_owned() + ".s1")?;
        let file3 = File::create(path.to_owned() + ".s2")?;
        let file4 = File::create(path.to_owned() + ".s3")?;
        let file5 = File::create(path.to_owned() + ".p1")?;
        let file6 = File::create(path.to_owned() + ".p2")?;
        let file7 = File::create(path.to_owned() + ".p3")?;

        // save part 1
        let p1_data = to_stdvec(&self.part1()).unwrap();
        file1.write_all(&p1_data)?;

        let w2 = BufWriter::new(file2);
        self.zkp_params.size().serialize_unchecked(w2).unwrap();
        let w3 = BufWriter::new(file3);
        self.app_params.size().serialize_unchecked(w3).unwrap();
        let w4 = BufWriter::new(file4);
        self.pedersen_params.size().serialize_unchecked(w4).unwrap();
        let w5 = BufWriter::new(file5);
        self.zkp_params.write(w5).unwrap();
        let w6 = BufWriter::new(file6);
        self.app_params.write(w6).unwrap();
        let w7 = BufWriter::new(file7);
        self.pedersen_params.write(w7).unwrap();

        Ok(())
    }

    // load committee data from a file
    pub fn load(path: &str) -> std::io::Result<Self> {
        // load part 1
        let p1_data = fs::read(path.to_owned() + ".dat")?;
        let p1: CommitteePart1 = from_bytes(&p1_data).unwrap();

        let file2 = File::open(path.to_owned() + ".s1")?;
        let reader2 = BufReader::new(file2);
        let zkp_size = KeySize::deserialize_unchecked(reader2).unwrap();
        let file3 = File::open(path.to_owned() + ".s2")?;
        let reader3 = BufReader::new(file3);
        let app_size = KeySize::deserialize_unchecked(reader3).unwrap();
        let file4 = File::open(path.to_owned() + ".s3")?;
        let reader4 = BufReader::new(file4);
        let pedersen_size = KeySize::deserialize_unchecked(reader4).unwrap();

        let file5 = File::open(path.to_owned() + ".p1")?;
        let reader5 = BufReader::new(file5);
        let zkp_params = ProvingKey::<Bn254>::read(reader5, &zkp_size);

        let file6 = File::open(path.to_owned() + ".p2")?;
        let reader6 = BufReader::new(file6);
        let app_params = ProvingKey::<Bn254>::read(reader6, &app_size);

        let file7 = File::open(path.to_owned() + ".p3")?;
        let reader7 = BufReader::new(file7);
        let pedersen_params = ProvingKey::<Bn254>::read(reader7, &pedersen_size);

        let zkp_cfg = CircomConfig::<Bn254>::load(
            "./circuits/pseudonym_check.so",
            "./circuits/pseudonym_check.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let app_cfg =
            CircomConfig::<Bn254>::load("./circuits/sybil_check.so", "./circuits/sybil_check.r1cs")
                .unwrap_or_else(|error| {
                    panic!("{:?}", error);
                });

        let pedersen_cfg = CircomConfig::<Bn254>::load(
            "./circuits/pedersen_commit.so",
            "./circuits/pedersen_commit.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        Ok(Committee {
            tpke_sec: p1.tpke_sec,
            ca_tree: p1.ca_tree,
            block_tree: p1.block_tree,
            zkp_cfg,
            zkp_params,
            app_cfg,
            app_params,
            pedersen_cfg,
            pedersen_params,
            tpke_key: p1.tpke_key,
        })
    }

    // shard of tpke public key
    pub fn tpke_shard(&self) -> Point {
        &self.tpke_sec * G.clone()
    }

    // update tpke public key
    pub fn update_tpke_key(&mut self, tpke_key: PublicKey) {
        self.tpke_key = Some(tpke_key);
    }

    // Update the parameters of zero-knowledge proof.
    pub fn update_zk_param(&mut self, zkp_params: ProvingKey<Bn254>) {
        self.zkp_params = zkp_params;
    }

    // Update the parameters of zero-knowledge proof.
    pub fn update_app_param(&mut self, app_params: ProvingKey<Bn254>) {
        self.app_params = app_params;
    }

    // Update the parameters of zero-knowledge proof.
    pub fn update_pedersen_param(&mut self, pedersen_params: ProvingKey<Bn254>) {
        self.pedersen_params = pedersen_params;
    }

    // Verify the zero-knowledge proof for pseudonym registration.
    pub fn verify_key_request(&self, req: &IdentityRequest) -> bool {
        let pvk = prepare_verifying_key(&self.zkp_params.vk);

        verify_proof(&pvk, &req.proof, &req.pub_inputs).unwrap()
    }

    // Verify the zero-knowledge proof for sybil resistance
    pub fn verify_app_key(&self, appkey: &ApplicationKey) -> bool {
        let pvk = prepare_verifying_key(&self.app_params.vk);

        verify_proof(&pvk, &appkey.proof, &appkey.pub_inputs).unwrap()
    }

    // Verify the zero-knowledge proof for identity check
    pub fn verify_identity_proof(&self, public_inputs: Vec<Fr>, proof: &Proof<Bn254>) -> bool {
        let pvk = prepare_verifying_key(&self.pedersen_params.vk);

        verify_proof(&pvk, proof, &public_inputs).unwrap()
    }

    // get decryption shard of tpke decryption
    pub fn decrypt_shard(&self, c1: &Point) -> Point {
        &self.tpke_sec * c1
    }

    // Add a member to the committee.
    pub async fn add_committee<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        cm: BigInt,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());

        // address of new member
        let cm2 = U256::from_little_endian(&cm.to_bytes_le().1);
        // send transaction
        let _res = contract.add_committee(cm2.into()).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    // Update the latest Merkle tree root on the blockchain.
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

        // Calculate the hash of these tree roots.
        let rh1 = poseidon_hash(vec![&root1, &root_ca, &y]).unwrap();
        let rh2 = poseidon_hash(vec![&root2, &root_ca, &y]).unwrap();
        let rh1: U256 = U256::from_little_endian(&rh1.to_bytes_le().1);
        let rh2: U256 = U256::from_little_endian(&rh2.to_bytes_le().1);

        // send transaction
        let _res = contract
            .update_roots_hash(rh1, rh2, U256::from(version).into())
            .send()
            .await?
            .await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    // Update the tpke publickey on the blockchain.
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

        // send transaction
        let _res = contract.set_tpke_pub(key).send().await?.await?;
        let _res = _res.unwrap();
        println!(
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    // Push the zero-knowledge proof's validation key to the chain.
    pub async fn set_derive_vk<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        // send transaction
        let _res = contract
            .do_set_derive_vk(self.zkp_params.vk.clone())
            .await?;
        Ok(())
    }

    // Push the zero-knowledge proof's validation key to the chain.
    pub async fn set_appkey_vk<M: Middleware + 'static, S: Signer + 'static>(
        &self,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        // send transaction
        let _res = contract
            .do_set_appkey_vk(self.app_params.vk.clone())
            .await?;
        Ok(())
    }

    // Revoke the given user pseudonym (address).
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
            "tx_hash: {:?}, Gas_used: {:?}",
            _res.transaction_hash, _res.gas_used
        );
        Ok(())
    }

    // revoke the credential
    pub async fn revoke_credential<M: Middleware + 'static, S: Signer + 'static>(
        &mut self,
        version: u64,
        credentials: Vec<Point>,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        self.block_tree
            .insert_nodes(credentials.iter().map(|x| x.scalar_y()).collect());
        self.update_roots_hash(version, contract_address, client)
            .await?;
        Ok(())
    }

    // Fetch user metadata associated with the specified address from the identity contract.
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

    // Trace back all the pseudonyms.
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

        // Calculate all potential pseudonyms locally.
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

        // Cross-check with the blockchain records to identify the pseudonyms.
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

// This file offers a user client, through which users can interact with the Hades
// system. It includes functionalities like applying for credentials, registering
// pseudonyms, requesting credential revocation, responding to witch resistance,
// and storing identity information.

use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_circom::CircomBuilder;
use ark_groth16::{create_random_proof as prove, Proof};
use baby_jub::{new_key, poseidon_hash, Point, G, Q};
use color_eyre::Result;
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::ca_client::{Credential, CredentialRequest, CA};
use crate::committee_client::Committee;
use crate::tpke::{CipherDual, PublicKey};
use crate::IdentityManager;
use num_traits::One;
use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::Write;

use ethers::{prelude::SignerMiddleware, providers::Middleware, signers::Signer, types::Address};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Store the private key information of the pseudonym and other secret information.
pub struct KeyStore {
    // onchain address
    pub address: BigInt,
    // index of pseudonyms, used for tracing
    pub derive_index: u64,
    // nonce of pedersen commitment
    pub commit_nonce: BigInt,
    // expiration time of this pseudonym
    pub expiration: u64,
    // series number
    pub sn: BigInt,
    pub cipher: CipherDual,
    pub status: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Store the credential, the private key information, and other secret information.
pub struct CredentialStore {
    pub master_key: BigInt,
    pub beta: BigInt,
    pub attributes: Vec<BigInt>,
    pub credential: Option<Credential>,
    pub derived_keys: HashMap<BigInt, KeyStore>,
    pub ca_key: Point,
}

impl CredentialStore {
    // set up
    pub fn new(attributes: Vec<BigInt>, ca_key: Point) -> Self {
        let mut rng = rand::thread_rng();
        let master_key = rng.gen_biguint(256).to_bigint().unwrap() % Q.clone();
        let mut beta = rng.gen_biguint(256).to_bigint().unwrap() % Q.clone();
        loop {
            if Point::from_y(&beta, false).is_ok() {
                break;
            }
            beta = rng.gen_biguint(256).to_bigint().unwrap() % Q.clone();
        }

        CredentialStore {
            master_key,
            beta,
            attributes,
            credential: None,
            derived_keys: HashMap::new(),
            ca_key,
        }
    }
    
    // return the master public key of the credential
    pub fn master_key_g(&self) -> Point {
        &self.master_key * G.clone()
    }
    
    // the public key of the trapdoor
    pub fn beta_g(&self) -> Point {
        &self.beta * G.clone()
    }
    
    // update the credential
    pub fn update_credential(&mut self, cred: Credential) {
        self.credential = Some(cred);
    }
}

#[derive(Debug, Clone)]
// All the information required to register a pseudonym.
pub struct IdentityRequest {
    pub address: BigInt,
    pub sn: BigInt,
    pub cipher: CipherDual,
    // pedersen commitment of identity attributies
    pub attr_commit: Point,
    // The maximum allowable index.
    pub num: u64,
    pub expir: u64,
    pub proof: Proof<Bn254>,
    // public inputs of zero knowledge proof
    pub pub_inputs: Vec<Fr>,
}

#[derive(Debug, Clone)]
// All the information required to respond to a sybil resistance.
pub struct ApplicationKey {
    // application id
    pub appid: BigInt,
    // series number of access token
    pub appkey: BigInt,
    // series number of pseudonym
    pub sn: BigInt,
    // onchain address
    pub address: BigInt,
    pub cipher: CipherDual,
    // zero knowledge proof
    pub proof: Proof<Bn254>,
    pub pub_inputs: Vec<Fr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// User client, used to interact with CA and on-chain contracts, and to store user information.
pub struct Client {
    // the credentials
    pub credentials: HashMap<Point, CredentialStore>,
    pub tpke_key: PublicKey,
}

impl Client {
    // set up
    pub fn new(tpke_key: PublicKey) -> Self {
        Self {
            credentials: HashMap::new(),
            tpke_key,
        }
    }
    
    // save the client data to a file
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        let data = to_stdvec(&self).unwrap();
        file.write_all(&data)?;

        Ok(())
    }
    
    // load client data from a file
    pub fn load(path: &str) -> std::io::Result<Self> {
        let data = fs::read(path)?;
        let client: Self = from_bytes(&data).unwrap();

        Ok(client)
    }
    
    // request a credential from CA
    pub fn request_credential(
        &mut self,
        attributes: Vec<BigInt>,
        expiration: u64,
        ca: &CA,
    ) -> CredentialRequest {
        let raw_credential = CredentialStore::new(attributes.clone(), ca.pubkey());
        let beta_encode = Point::from_y(&raw_credential.beta, false).unwrap();
        // encrypt the trapdoor
        let (cipher, k) = self.tpke_key.encrypt(&beta_encode);

        let time_start = SystemTime::now();
        // generate proof
        let mut builder = CircomBuilder::new(ca.zkp_cfg.clone());

        builder.push_input("k", k);
        builder.push_input("Mx", beta_encode.scalar_x());
        builder.push_input("My", beta_encode.scalar_y());
        builder.push_input("C1x", cipher.c1.scalar_x());
        builder.push_input("C1y", cipher.c1.scalar_y());
        builder.push_input("C2x", cipher.c2.scalar_x());
        builder.push_input("C2y", cipher.c2.scalar_y());
        builder.push_input("Bx", raw_credential.beta_g().scalar_x());
        builder.push_input("By", raw_credential.beta_g().scalar_y());
        builder.push_input("PKx", self.tpke_key.scalar_x());
        builder.push_input("PKy", self.tpke_key.scalar_y());

        let mut rng = rand::thread_rng();

        let circom = builder.build().unwrap();
        let proof = prove(circom, &ca.zkp_params, &mut rng).unwrap();

        println!(
            "Credential request proof time: {:?} ms",
            time_start.elapsed().unwrap().as_millis()
        );

        let request = CredentialRequest {
            master_key_g: raw_credential.master_key_g(),
            beta_g: raw_credential.beta_g(),
            attributes,
            expiration,
            cipher,
            ca_key: ca.pubkey(),
            cipher_proof: proof,
        };

        self.credentials
            .insert(raw_credential.master_key_g(), raw_credential);
        request
    }
    
    // save the credential
    pub fn fill_credential(&mut self, credential: Credential) {
        self.credentials
            .entry(credential.master_key_g.clone())
            .and_modify(|cs| {
                cs.update_credential(credential);
            });
    }
    
    // register a pseudonyms
    pub fn derive_identity(
        &mut self,
        committee: &Committee,
        master_key: &Point,
        time_reserve: u64,
        address: &BigInt,
        n: u64,
    ) -> IdentityRequest {
        let time_start = SystemTime::now();
        // the credential
        let cs = self.credentials.get_mut(master_key).unwrap();
        let idx = cs.derived_keys.len();
        // generate series number
        let sn = poseidon_hash(vec![&cs.beta, &idx.to_bigint().unwrap()]).unwrap();
        // encrypt
        let cipher =
            self.tpke_key
                .encrypt_dual_with_nonce(&cs.master_key_g(), &cs.ca_key, address, &sn);
        let credential = cs.credential.as_ref().unwrap();
        let e = credential.expiration;
        // set expiration time
        let ei = e - time_reserve;
        // generate nonce of pedersen commitment
        let r = new_key().scalar_key();
        let attr_commit = &credential.attr_commit;
        // pedersen commitment
        let attr_blind = attr_commit + &r * G.clone();
        
        // merkle proof of CA in the trust list
        let proof1 = committee.ca_tree.gen_inproof(cs.ca_key.scalar_y()).unwrap();
        // merkle proof that the credential is not in the revocation list.
        let proof2 = committee
            .block_tree
            .gen_notinproof(credential.master_key_g.scalar_y())
            .unwrap();
        // root hash
        let rh = poseidon_hash(vec![
            &proof2.root,
            &committee.ca_tree.root(),
            &self.tpke_key.scalar_y(),
        ])
        .unwrap();
        // generate proof
        let mut builder = CircomBuilder::new(committee.zkp_cfg.clone());

        builder.push_input("addr", address.clone());
        builder.push_input("C1y", cipher.c1.scalar_y());
        builder.push_input("C2y", cipher.c2.scalar_y());
        builder.push_input("C3y", cipher.c3.scalar_y());
        builder.push_input("Aiy", attr_blind.scalar_y());
        let dd = (cipher.c1.scalar_x() & BigInt::one())
            + ((cipher.c2.scalar_x() & BigInt::one()) << 1)
            + ((cipher.c3.scalar_x() & BigInt::one()) << 2)
            + ((attr_blind.scalar_x() & BigInt::one()) << 3)
            + ((self.tpke_key.scalar_x() & BigInt::one()) << 4)
            + (ei.to_bigint().unwrap() << 5)
            + (n.to_bigint().unwrap() << 69);

        builder.push_input("dd", dd);
        builder.push_input("rh", rh);

        // private input
        builder.push_input("rc", committee.ca_tree.root());
        builder.push_input("rb", proof2.root.clone());
        builder.push_input("Yy", self.tpke_key.scalar_y());

        builder.push_input("C1x", cipher.c1.scalar_x());
        builder.push_input("C2x", cipher.c2.scalar_x());
        builder.push_input("C3x", cipher.c3.scalar_x());
        builder.push_input("Aix", attr_blind.scalar_x());
        builder.push_input("Yx", self.tpke_key.scalar_x());

        builder.push_input("Px", cs.ca_key.scalar_x());
        builder.push_input("Py", cs.ca_key.scalar_y());
        builder.push_input("s", credential.signature.s.clone());
        builder.push_input("R8x", credential.signature.r_b8.scalar_x());
        builder.push_input("R8y", credential.signature.r_b8.scalar_y());
        builder.push_input("k", sn.clone());
        builder.push_input("x", cs.master_key.clone());
        builder.push_input("e", e);
        builder.push_input("b", cs.beta.clone());
        builder.push_input("Ax", attr_commit.scalar_x());
        builder.push_input("Ay", attr_commit.scalar_y());
        builder.push_input("nonce", idx);
        builder.push_input("r", r.clone());

        builder.push_input("key1", proof1.key());
        for node in proof1.path {
            builder.push_input("path1", node);
        }

        builder.push_input("path2", proof2.siblings[0].clone());
        builder.push_input("key2", proof2.right_key());
        builder.push_input("value2", proof2.siblings[1].clone());
        for node in proof2.path {
            builder.push_input("path2", node);
        }

        let mut rng = rand::thread_rng();

        let circom = builder.build().unwrap();
        let pub_inputs = circom.get_public_inputs().unwrap();
        
        // the zero knowledge proof
        let proof = prove(circom, &committee.zkp_params, &mut rng).unwrap();
        
        println!(
            "Pseudonym register proof time: {:?} ms",
            time_start.elapsed().unwrap().as_millis()
        );
        
        // save the request
        cs.derived_keys.insert(
            sn.clone(),
            KeyStore {
                address: address.clone(),
                derive_index: idx as u64,
                commit_nonce: r,
                expiration: ei,
                sn: sn.clone(),
                cipher: cipher.clone(),
                status: 0,
            },
        );

        IdentityRequest {
            address: address.clone(),
            sn,
            cipher,
            attr_commit: attr_blind,
            num: n,
            expir: ei,
            proof,
            pub_inputs,
        }
    }
    
    // Generate the information required to respond to sybil resistance.
    pub fn gen_appkey(
        &self,
        committee: &Committee,
        master_key: &Point,
        sn: &BigInt,
        appid: &BigInt,
    ) -> ApplicationKey {
        // get credential information
        let cs = self.credentials.get(master_key).unwrap();
        // get pseudonyms information
        let ks = cs.derived_keys.get(sn).unwrap();
        // generate the series number
        let appkey = poseidon_hash(vec![&cs.master_key, appid]).unwrap();
        // generate proof
        let mut builder = CircomBuilder::new(committee.app_cfg.clone());
        let ss = (appid & ((BigInt::one() << 160) - BigInt::one()))
            + ((self.tpke_key.scalar_x() & BigInt::one()) << 160)
            + ((ks.cipher.c2.scalar_x() & BigInt::one()) << 161);
        builder.push_input("key", appkey.clone());
        builder.push_input("ss", ss);

        builder.push_input("Yy", self.tpke_key.scalar_y());
        builder.push_input("C2y", ks.cipher.c2.scalar_y());

        // private input
        builder.push_input("k", ks.sn.clone());
        builder.push_input("x", cs.master_key.clone());
        builder.push_input("Yx", self.tpke_key.scalar_x());
        builder.push_input("C2x", ks.cipher.c2.scalar_x());

        let mut rng = rand::thread_rng();

        let circom = builder.build().unwrap();
        let pub_inputs = circom.get_public_inputs().unwrap();
        // the proof
        let proof = prove(circom, &committee.app_params, &mut rng).unwrap();

        ApplicationKey {
            appid: appid.clone(),
            appkey,
            sn: sn.clone(),
            cipher: ks.cipher.clone(),
            proof,
            pub_inputs,
            address: ks.address.clone(),
        }
    }
    
    // Generate a proof that the identity information meets a certain assertion.
    pub fn gen_identity_proof(&self, committee: &Committee, master_key: &Point, sn: &BigInt, l_range: Vec<BigInt>, r_range: Vec<BigInt>) -> (Point, BigInt, Proof<Bn254>, Vec<Fr>) {
        // get credential information
        let cs = self.credentials.get(master_key).unwrap();
        // get pseudonyms information
        let ks = cs.derived_keys.get(sn).unwrap();
        // compute the hash of public inputs
        let hash1 = poseidon_hash(l_range.iter().take(6).collect()).unwrap();
        let hash2 = poseidon_hash(r_range.iter().take(6).collect()).unwrap();
        let lrcm = poseidon_hash(vec![&l_range[6], &l_range[7], &r_range[6], &r_range[7], &hash1, &hash2]).unwrap();
        
        let credential = cs.credential.as_ref().unwrap();
        // pedersen commitment
        let attr_blind =  &credential.attr_commit + &ks.commit_nonce * G.clone();

        let mut builder = CircomBuilder::new(committee.pedersen_cfg.clone());
        builder.push_input("Ax", attr_blind.scalar_x());
        builder.push_input("Ay", attr_blind.scalar_y());
        builder.push_input("lrcm", lrcm.clone());
        builder.push_input("k", ks.commit_nonce.clone());
        
        for a in &cs.attributes {
            builder.push_input("a", a.clone());
        } 

        for l in &l_range {
            builder.push_input("l", l.clone());
        }

        for r in &r_range {
            builder.push_input("r", r.clone());
        }

        let mut rng = rand::thread_rng();

        let circom = builder.build().unwrap();
        // public inputs
        let pub_inputs = circom.get_public_inputs().unwrap();
        // the proof
        let proof = prove(circom, &committee.pedersen_params, &mut rng).unwrap();

        (attr_blind, lrcm, proof, pub_inputs)

    }
    
    // register a pseudonym
    pub async fn register<M: Middleware + 'static, S: Signer + 'static>(
        &mut self,
        committee: &Committee,
        master_key: &Point,
        time_reserve: u64,
        user_address: &BigInt,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<BigInt> {
        // the contract address
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());
        
        // the number of address register in the identity contract
        let n = contract.num_of_address().call().await?;
        
        // request data
        let req = self.derive_identity(
            committee,
            master_key,
            time_reserve,
            user_address,
            n.as_u64(),
        );
        
        // public inputs
        let inputs = &req.pub_inputs[..6];
        // send transaction
        let _res = contract.do_register(req.proof, inputs).await?;
        Ok(req.sn)
    }
    
    // Respond to a sybil resistance instance on-chain.
    pub async fn send_appkey<M: Middleware + 'static, S: Signer + 'static>(
        &mut self,
        committee: &Committee,
        master_key: &Point,
        sn: &BigInt,
        appid: &BigInt,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());

        let time_start = SystemTime::now();
        // generate data
        let req = self.gen_appkey(committee, master_key, sn, appid);
        println!(
            "Sybil-resistance proof time: {:?} ms",
            time_start.elapsed().unwrap().as_millis()
        );
        
        // send transaction
        let _res = contract
            .do_set_appkey(&req.address, &req.appkey, appid, req.proof)
            .await?;
        Ok(())
    }
    
    // Verify that the identity attribute meets a certain assertion on-chain.
    pub async fn verify_identity<M: Middleware + 'static, S: Signer + 'static>(
        &mut self,
        committee: &Committee,
        master_key: &Point,
        sn: &BigInt,
        l_range: Vec<BigInt>, 
        r_range: Vec<BigInt>,
        contract_address: &str,
        client: Arc<SignerMiddleware<M, S>>,
    ) -> Result<()> {
        let address = contract_address.parse::<Address>()?;
        let contract = IdentityManager::new(address, client.clone());

        let time_start = SystemTime::now();
        // generate data
        let (a, lrcm, proof, _) = self.gen_identity_proof(committee, master_key, sn, l_range, r_range);
        println!(
            "Identity proof time: {:?} ms",
            time_start.elapsed().unwrap().as_millis()
        );
        
        // send transaction
        let _res = contract
            .do_veriy_identity(&a.scalar_x(), &a.scalar_y(), &lrcm, proof)
            .await?;
        Ok(())
    }
}

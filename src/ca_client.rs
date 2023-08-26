use crate::get_timestamp;
use crate::tpke::{Cipher, PublicKey};
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, Proof, ProvingKey, KeySize
};
use ark_serialize::*;
use baby_jub::{new_key, poseidon_hash, Point, PrivateKey, Signature, B8, H8};
use num_bigint::{BigInt, ToBigInt};
use postcard::{from_bytes, to_stdvec};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use ark_ff::bytes::ToBytes;
use std::io::{BufReader, BufWriter};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub attributes: Vec<BigInt>,
    pub cipher: Cipher,
    pub beta_g: Point,
}

#[derive(Debug, Clone)]
pub struct CA {
    pub attribute_num: usize,
    pub private_key: PrivateKey,
    pub generators: Vec<Point>,
    pub user_infos: HashMap<Point, UserInfo>,
    pub blacklist: Vec<Point>,
    pub zkp_cfg: CircomConfig<Bn254>,
    pub zkp_params: ProvingKey<Bn254>,
    pub tpke_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CAPart1 {
    pub attribute_num: usize,
    pub private_key: PrivateKey,
    pub generators: Vec<Point>,
    pub user_infos: HashMap<Point, UserInfo>,
    pub blacklist: Vec<Point>,
    pub tpke_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub signature: Signature,
    pub master_key_g: Point,
    pub beta_g: Point,
    pub attr_commit: Point,
    pub expiration: u64,
}

#[derive(Debug, Clone)]
pub struct CredentialRequest {
    pub master_key_g: Point,
    pub beta_g: Point,
    pub attributes: Vec<BigInt>,
    pub expiration: u64,
    pub cipher: Cipher,
    pub ca_key: Point,
    pub cipher_proof: Proof<Bn254>,
}

impl CA {
    pub fn init(attribute_num: usize, tpke_key: PublicKey) -> Self {
        let private_key = new_key();
        let k = private_key.scalar_key();
        //TODO: gen generators
        let generators: Vec<Point> = (0..attribute_num)
            .map(|i| {
                let g1 = poseidon_hash(vec![&k, &i.to_bigint().unwrap()]).unwrap() * B8.clone();
                let h1 = poseidon_hash(vec![&k, &(i + attribute_num).to_bigint().unwrap()])
                    .unwrap()
                    * H8.clone();
                g1 + h1
            })
            .collect();

        let cfg = CircomConfig::<Bn254>::load(
            "./circuits/tpke_single_js/tpke_single.so",
            "./circuits/tpke_single.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        let builder = CircomBuilder::new(cfg.clone());
        let circom = builder.setup();

        let mut rng = thread_rng();
        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        CA {
            attribute_num,
            private_key,
            generators,
            user_infos: HashMap::new(),
            blacklist: Vec::new(),
            zkp_cfg: cfg,
            zkp_params: params,
            tpke_key,
        }
    }

    pub fn pubkey(&self) -> Point {
        self.private_key.public()
    }

    pub fn part1(&self) -> CAPart1 {
        CAPart1 {
            attribute_num: self.attribute_num,
            private_key: self.private_key.clone(),
            generators: self.generators.clone(),
            user_infos: self.user_infos.clone(),
            blacklist: self.blacklist.clone(),
            tpke_key: self.tpke_key.clone(),
        }
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file1 = File::create(path.to_owned() + ".1")?;
        let file2 = File::create(path.to_owned() + ".2")?;
        let file3 = File::create(path.to_owned() + ".3")?;

        let p1_data = to_stdvec(&self.part1()).unwrap();
        file1.write_all(&p1_data)?;

        let w2 = BufWriter::new(file2);
        self.zkp_params.size().serialize_unchecked(w2).unwrap();
        let w3 = BufWriter::new(file3);
        self.zkp_params.write(w3).unwrap();

        Ok(())
    }

    pub fn load(path: &str) -> std::io::Result<Self> {
        let p1_data = fs::read(path.to_owned() + ".1")?;
        let ca1: CAPart1 = from_bytes(&p1_data).unwrap();

        let file2 = File::open(path.to_owned() + ".2")?;
        let reader2 = BufReader::new(file2);
        let zkp_size = KeySize::deserialize_unchecked(reader2).unwrap();
        
        let file3 = File::open(path.to_owned() + ".3")?;
        let reader3 = BufReader::new(file3);
        let zkp_params = ProvingKey::<Bn254>::read(reader3, &zkp_size);

        let cfg = CircomConfig::<Bn254>::load(
            "./circuits/tpke_single_js/tpke_single.so",
            "./circuits/tpke_single.r1cs",
        )
        .unwrap_or_else(|error| {
            panic!("{:?}", error);
        });

        Ok(CA {
            attribute_num: ca1.attribute_num,
            private_key: ca1.private_key,
            generators: ca1.generators,
            user_infos: ca1.user_infos,
            blacklist: ca1.blacklist,
            zkp_cfg: cfg,
            zkp_params,
            tpke_key: ca1.tpke_key,
        })
    }

    pub fn gen_credential(&mut self, req: CredentialRequest) -> Result<Credential, String> {
        if req.attributes.len() != self.attribute_num {
            return Err("Invalid number of attributes".to_string());
        }
        // verif proof
        let mut builder = CircomBuilder::new(self.zkp_cfg.clone());

        builder.push_input("C1x", req.cipher.c1.scalar_x());
        builder.push_input("C1y", req.cipher.c1.scalar_y());
        builder.push_input("C2x", req.cipher.c2.scalar_x());
        builder.push_input("C2y", req.cipher.c2.scalar_y());
        builder.push_input("Bx", req.beta_g.scalar_x());
        builder.push_input("By", req.beta_g.scalar_y());
        builder.push_input("PKx", self.tpke_key.scalar_x());
        builder.push_input("PKy", self.tpke_key.scalar_y());

        let circom = builder.build().unwrap();
        let inputs = circom.get_public_inputs().unwrap();
        let pvk = prepare_verifying_key(&self.zkp_params.vk);
        let verified = verify_proof(&pvk, &req.cipher_proof, &inputs).unwrap();
        if !verified {
            return Err("Invalid Cipher Proof".to_string());
        }

        let attr_commit: Point = req
            .attributes
            .iter()
            .zip(self.generators.iter())
            .fold(Point::identity(), |sum, val| sum + val.0 * val.1);
        let inputs: Vec<BigInt> = vec![req.master_key_g.scalar_x(), req.master_key_g.scalar_y()]
            .into_iter()
            .chain(vec![req.beta_g.scalar_x(), req.beta_g.scalar_y()].into_iter())
            .chain(vec![attr_commit.scalar_x(), attr_commit.scalar_y()].into_iter())
            .chain(vec![(get_timestamp() + req.expiration).to_bigint().unwrap()].into_iter())
            .collect();

        let msg_hash1 = poseidon_hash(inputs.iter().take(4).collect())?;
        let msg_hash = poseidon_hash(
            vec![msg_hash1]
                .iter()
                .chain(inputs.iter().skip(4))
                .collect(),
        )?;

        let signature = self.private_key.sign(msg_hash)?;

        self.user_infos.insert(
            req.master_key_g.clone(),
            UserInfo {
                attributes: req.attributes,
                cipher: req.cipher,
                beta_g: req.beta_g.clone(),
            },
        );
        Ok(Credential {
            signature,
            master_key_g: req.master_key_g,
            beta_g: req.beta_g,
            attr_commit,
            expiration: get_timestamp() + req.expiration,
        })
    }

    pub fn get_user_info(&self, key: &Point) -> Option<&UserInfo> {
        self.user_infos.get(key)
    }
}

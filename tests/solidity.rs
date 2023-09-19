// This is a test file, primarily used to test the Ethereum contract interaction functions.

use ark_circom::{ethereum, CircomBuilder, CircomConfig};
use color_eyre::Result;
use rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{create_random_proof as prove, generate_random_parameters};

use ethers::{
    prelude::{abigen, LocalWallet, SignerMiddleware},
    providers::{Http, Middleware, Provider},
    signers::Signer,
    types::Address,
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

#[tokio::test]
// Test the interaction with the zero-knowledge proof verification contract.
async fn solidity_verifier() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./circuits/circuit2_js/circuit2.wasm",
        "./circuits/circuit2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);
    builder.push_input("c", 33);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = prove(circom, &params, &mut rng)?;

    // launch the network & compile the verifier
    let provider = Provider::<Http>::try_from("https://rpc.ankr.com/fantom_testnet")?
        .interval(Duration::from_millis(10u64));

    let wallet = "164c8c3b7e2b40c97e4a82d441fa6857288d3e61dbe6fe9c07e97c868b997c48"
        .parse::<LocalWallet>()?;
    let address = "Af2e4a368CCF9d8B566CAa68b4C2D02AADf4C668".parse::<Address>()?;

    let client = SignerMiddleware::new(provider, wallet.with_chain_id(4002u64));
    let client = Arc::new(client);

    // deploy the verifier
    // let contract = Groth16Verifier::deploy(provider.clone(), ())?
    //     .send()
    //     .await?;

    let contract = Groth16Verifier::new(address, client.clone());

    println!("send:");
    // check the proof
    let verified = contract
        .check_proof(proof, params.vk, inputs.as_slice())
        .await?;
    print!("ok");
    assert!(verified);

    Ok(())
}

// We need to implement the conversion from the Ark-Circom's internal Ethereum types to
// the ones expected by the abigen'd types. Could we maybe provide a convenience
// macro for these, given that there's room for implementation error?
abigen!(Groth16Verifier, "./tests/verifier_artifact.json");
use groth_16_verifier::{G1Point, G2Point, Proof, VerifyingKey};
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

impl<M: Middleware + 'static> Groth16Verifier<M> {
    async fn check_proof<
        I: Into<ethereum::Inputs>,
        P: Into<ethereum::Proof>,
        VK: Into<ethereum::VerifyingKey>,
    >(
        &self,
        proof: P,
        vk: VK,
        inputs: I,
    ) -> Result<bool> {
        // convert into the expected format by the contract
        let proof = proof.into().into();
        let vk = vk.into().into();
        let inputs = inputs.into().0;

        // query the contract
        let _res = self.verify(inputs, proof, vk).send().await?.await?;
        println!("{:?}", _res);
        Ok(true)
    }
}

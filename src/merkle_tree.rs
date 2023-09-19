// This file implements a Merkle tree, which can support both 
// proofs of data existence and non-existence.

use std::vec;
use baby_jub::{poseidon_hash, Q};
use lazy_static::lazy_static;
use num_bigint::{BigInt, ToBigInt};
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref ZERO: BigInt = 0.to_bigint().unwrap();
    pub static ref BNMAX: BigInt = Q.clone() - 1.to_bigint().unwrap();
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Proof of (key,value) in the Merkle tree.
pub struct InProof {
    pub value: BigInt,
    pub path: Vec<BigInt>,
    pub flags: Vec<usize>,
}

impl InProof {
    // verify the proof
    pub fn verify(&self, root: &BigInt) -> bool {
        let r = self
            .path
            .iter()
            .zip(self.flags.iter())
            .fold(self.value.clone(), |state, pair| {
                if *pair.1 == 0 {
                    poseidon_hash(vec![&state, pair.0]).unwrap()
                } else {
                    poseidon_hash(vec![pair.0, &state]).unwrap()
                }
            });

        &r == root
    }
    
    // the key of (key,value)
    pub fn key(&self) -> BigInt {
        let mut k = 0.to_bigint().unwrap();
        let mut d = 1.to_bigint().unwrap();

        for f in &self.flags {
            if f == &1 {
                k = k + &d;
            }
            d <<= 1;
        }

        k
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Proof that (key,value) is not in the Merkle tree.
pub struct NotInProof {
    pub value: BigInt,
    pub siblings: [BigInt; 2],
    pub path: Vec<BigInt>,
    pub flags: Vec<usize>,
    pub root: BigInt,
}

impl NotInProof {
    // verify the proof
    pub fn verify(&self, root: [&BigInt; 2]) -> bool {
        if self.value <= self.siblings[0] || self.value >= self.siblings[1] {
            return false;
        }
        let r = self.path.iter().zip(self.flags.iter()).fold(
            poseidon_hash(self.siblings.iter().collect()).unwrap(),
            |state, pair| {
                if *pair.1 == 0 {
                    poseidon_hash(vec![&state, pair.0]).unwrap()
                } else {
                    poseidon_hash(vec![pair.0, &state]).unwrap()
                }
            },
        );

        &r == root[0] || &r == root[1]
    }
    
    // key of the left node
    pub fn left_key(&self) -> BigInt {
        let mut k = 0.to_bigint().unwrap();
        let mut d = 2.to_bigint().unwrap();

        for f in &self.flags {
            if f == &1 {
                k = k + &d;
            }
            d <<= 1;
        }

        k
    }
    
    // key of the right node
    pub fn right_key(&self) -> BigInt {
        let mut k = 1.to_bigint().unwrap();
        let mut d = 2.to_bigint().unwrap();

        for f in &self.flags {
            if f == &1 {
                k = k + &d;
            }
            d <<= 1;
        }

        k
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// A complete binary tree, where empty positions are filled with 0.
pub struct MerkleTree {
    // size of non-empty nodes
    pub len: usize,
    // layers of the tree
    pub tiers: usize,
    pub nodes: Vec<Vec<BigInt>>,
    pub empty_nodes: Vec<BigInt>,
}

impl MerkleTree {
    // Initialize the Merkle tree.
    pub fn new(tiers: usize) -> Self {
        // Calculate the value of empty nodes for each layer.
        let empty_nodes: Vec<BigInt> = (0..tiers)
            .scan(ZERO.clone(), |state, i| {
                if i == 0 {
                    Some(state.clone())
                } else {
                    *state = poseidon_hash(vec![state, state]).unwrap();
                    Some(state.clone())
                }
            })
            .collect();
        // nodes by layers
        let nodes = vec![Vec::new(); tiers];
        let tree = Self {
            len: 0,
            tiers,
            nodes,
            empty_nodes,
        };

        tree
    }
    
    // the root of merkle tree
    pub fn root(&self) -> BigInt {
        self.nodes[self.tiers - 1][0].clone()
    }
    
    // insert nodes
    pub fn insert_nodes(&mut self, nodes: Vec<BigInt>) {
        self.nodes[0].extend(nodes.into_iter());
        self.nodes[0].sort();
        self.len = self.nodes[0].len();

        for i in 0..(self.tiers - 1) {
            if self.nodes[i].len() % 2 != 0 {
                self.nodes[i].push(self.empty_nodes[i].clone());
            }
            self.nodes[i + 1] = self.nodes[i]
                .chunks(2)
                .map(|x| poseidon_hash(x.iter().collect()).unwrap())
                .collect();
        }

        self.nodes[0] = self.nodes[0][0..self.len].to_vec();
    }
    
    // Generate existence proof for the key.
    pub fn gen_inproof_raw(&self, mut idx: usize) -> InProof {
        let mut path = Vec::new();
        let mut flags = Vec::new();
        let value = self.nodes[0][idx].clone();
        for i in 0..(self.tiers - 1) {
            if idx % 2 == 0 {
                flags.push(0);
                let node = self.nodes[i].get(idx + 1).unwrap_or(&self.empty_nodes[i]);
                path.push(node.clone());
            } else {
                flags.push(1);
                path.push(self.nodes[i][idx - 1].clone());
            }
            idx >>= 1;
        }
        InProof { value, path, flags }
    }
    
    // Generate existence proof for the data.
    pub fn gen_inproof(&self, node: BigInt) -> Result<InProof, usize> {
        let idx = self.nodes[0].binary_search(&node)?;
        Ok(self.gen_inproof_raw(idx))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Merkle tree used for non-existence proof,
// use two Merkle trees to reduce verification overhead.
pub struct DualTree {
    pub tree0: MerkleTree,
    pub tree1: MerkleTree,
}

impl DualTree {
    // Initialize the Merkle tree.
    pub fn new(tiers: usize) -> Self {
        let mut tree0 = MerkleTree::new(tiers);
        let mut tree1 = MerkleTree::new(tiers);
        // Mark the left boundary and the right boundary.
        tree0.insert_nodes(vec![ZERO.clone(), BNMAX.clone()]);
        tree1.insert_nodes(vec![ZERO.clone(), ZERO.clone(), BNMAX.clone()]);

        Self { tree0, tree1 }
    }
    
    // root of the merkle tree
    pub fn roots(&self) -> (BigInt, BigInt) {
        (self.tree0.root(), self.tree1.root())
    }
    
    // insert nodes
    pub fn insert_nodes(&mut self, nodes: Vec<BigInt>) {
        self.tree0.insert_nodes(nodes.clone());
        self.tree1.insert_nodes(nodes.clone());
    }
    
    // Generate non-existence proof for the node.
    pub fn gen_notinproof(&self, node: BigInt) -> Result<NotInProof, usize> {
        let idx = self.tree0.nodes[0].binary_search(&node);

        match idx {
            Ok(i) => Err(i),
            Err(i) => {
                let (proof, root) = if i % 2 == 1 {
                    (self.tree0.gen_inproof_raw(i), self.tree0.root())
                } else {
                    (self.tree1.gen_inproof_raw(i), self.tree1.root())
                };
                Ok(NotInProof {
                    value: node,
                    siblings: [proof.path[0].clone(), proof.value],
                    path: proof.path[1..].to_vec(),
                    flags: proof.flags[1..].to_vec(),
                    root,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DualTree, MerkleTree};
    use num_bigint::ToBigInt;

    #[test]
    // test existence proof
    fn test_inproof() {
        let mut tree = MerkleTree::new(64);
        tree.insert_nodes(
            (1..20usize)
                .step_by(2)
                .map(|x| x.to_bigint().unwrap())
                .collect(),
        );
        let proof = tree.gen_inproof(5.to_bigint().unwrap()).unwrap();
        assert!(proof.verify(&tree.root()));
        let proof = tree.gen_inproof(19.to_bigint().unwrap()).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    // test non-existence proof
    fn test_notinproof() {
        let mut tree = DualTree::new(64);
        tree.insert_nodes(
            (1..20usize)
                .step_by(2)
                .map(|x| x.to_bigint().unwrap())
                .collect(),
        );
        let proof = tree.gen_notinproof(8.to_bigint().unwrap()).unwrap();

        let (root1, root2) = tree.roots();
        assert!(proof.verify([&root1, &root2]))
    }
}

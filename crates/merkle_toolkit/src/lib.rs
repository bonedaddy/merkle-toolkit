use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub depth: usize,
    pub leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!(depth <= 27);
        Self {
            depth,
            leaves: Vec::new(),
        }
    }

    pub fn append_leaf(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
    }

    pub fn root(&self) -> [u8; 32] {
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| {
                    let left = pair[0];
                    let right = if pair.len() == 2 { pair[1] } else { [0u8; 32] };
                    hash_nodes(left, right)
                })
                .collect();
        }
        if level.is_empty() {
            [0u8; 32]
        } else {
            level[0]
        }
    }

    pub fn get_proof(&self, index: usize) -> Vec<[u8; 32]> {
        assert!(index < self.leaves.len());
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut level = self.leaves.clone();

        while level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                [0u8; 32]
            };
            proof.push(sibling);

            level = level
                .chunks(2)
                .map(|pair| {
                    let left = pair[0];
                    let right = if pair.len() == 2 { pair[1] } else { [0u8; 32] };
                    hash_nodes(left, right)
                })
                .collect();

            current_index /= 2;
        }

        proof
    }

    pub fn get_proof_optimized(&self, index: usize) -> Vec<[u8; 32]> {
        assert!(index < self.leaves.len());
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut levels: Vec<Vec<[u8; 32]>> = vec![self.leaves.clone()];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { [0u8; 32] };
                next.push(hash_nodes(left, right));
            }
            levels.push(next);
        }

        for level in &levels[..levels.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                [0u8; 32]
            };
            proof.push(sibling);
            current_index /= 2;
        }

        proof
    }

    pub fn verify_proof(leaf: [u8; 32], proof: &[[u8; 32]], index: usize, root: [u8; 32]) -> bool {
        let mut computed_hash = leaf;
        let mut idx = index;
        for sibling in proof {
            computed_hash = if idx % 2 == 0 {
                hash_nodes(computed_hash, *sibling)
            } else {
                hash_nodes(*sibling, computed_hash)
            };
            idx /= 2;
        }
        computed_hash == root
    }
}

pub fn hash_nodes(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn test_merkle_root_and_proof() {
        let mut tree = MerkleTree::new(3);

        let leaf1 = Sha256::digest(b"leaf1").into();
        let leaf2 = Sha256::digest(b"leaf2").into();
        let leaf3 = Sha256::digest(b"leaf3").into();

        tree.append_leaf(leaf1);
        tree.append_leaf(leaf2);
        tree.append_leaf(leaf3);

        let root = tree.root();

        for i in 0..tree.leaves.len() {
            let leaf = tree.leaves[i];
            let proof_1 = tree.get_proof(i);
            assert!(MerkleTree::verify_proof(leaf, &proof_1, i, root));
            let proof_2 = tree.get_proof_optimized(i);
            assert!(MerkleTree::verify_proof(leaf, &proof_2, i, root));
            assert_eq!(proof_1, proof_2);
        }
    }

    #[test]
    fn test_invalid_proof_fails() {
        let mut tree = MerkleTree::new(3);

        tree.append_leaf(Sha256::digest(b"a").into());
        tree.append_leaf(Sha256::digest(b"b").into());

        let bad_leaf = Sha256::digest(b"c").into();
        let proof = tree.get_proof(0);
        let root = tree.root();

        assert!(!MerkleTree::verify_proof(bad_leaf, &proof, 0, root));
    }
}

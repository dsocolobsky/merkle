mod serializable;

use std::fmt::{Debug, Formatter};
use sha3::{Digest, Keccak256};
use crate::serializable::Serializable;

type Hash = [u8; 32];

struct MerkleTree {
    levels: Vec<Vec<Hash>>
}

impl MerkleTree {
    /// Creates a Merkle Tree given a vector of u32
    fn create_from_values<T: Serializable + Clone>(initial_vals: &[T]) -> Self {
        let mut levels = vec![create_initial_level(initial_vals)];
        let mut i: usize = 0;
        while levels[i].len() > 1 {
            levels.push(calculate_next_level(&levels[i]));
            i += 1;
        }
        MerkleTree {
            levels
        }
    }

    /// Returns the height of the tree; including the root
    fn height(&self) -> usize {
        self.levels.len()
    }

    /// Returns the number of elements in the tree (leafs)
    fn num_elements(&self) -> usize {
        self.leafs().len()
    }

    /// Returns the leafs for the tree
    fn leafs(&self) -> &Vec<Hash> {
        &self.levels[0]
    }

    /// Returns the root hash of the tree
    fn root(&self) -> Option<&Hash> {
        if let Some(root_level) = self.levels.last() {
            Some(&root_level[0])
        } else {
            None
        }
    }

    /// Returns the index in the leaf array for a given element, if present.
    fn leaf_index_for_element(&self, element: u32) -> Option<usize> {
        let hash = hash_one(element);
        self.leafs().iter().position(|h| *h == hash)
    }

    /// Checks if the given hash is present at any level of the Merkle Tree
    fn contains_hash(&self, hash: &Hash) -> bool {
        self.levels.iter().any(|level| level.contains(hash))
    }

    /// Generates a proof that a certain element belongs to the tree, if present.
    fn generate_proof(&self, element: u32) -> Option<(Vec<Hash>, usize)> {
        let leaf_index = self.leaf_index_for_element(element)?;
        let mut proof: Vec<Hash> = vec![];

        let mut index = leaf_index;
        for level in self.levels.iter().take(self.height() - 1) {
            if index % 2 == 0 {
                proof.push(level[index+1])
            } else {
                proof.push(level[index-1])
            }
            index /= 2;
        }

        Some((proof, leaf_index))
    }

    /// Given an element, it's index and a proof verifies it against the root of a Merkle Tree
    fn verify_proof(&self, element: u32, index: usize, proof: &[Hash]) -> bool {
        let Some(root) = self.root() else {
            return false;
        };
        let mut hash = hash_one(element);
        let mut index = index;
        for p in proof.iter() {
            hash = if index % 2 == 0 {
                hash_multiple(&[hash, *p])
            } else {
                hash_multiple(&[*p, hash])
            };
            index /= 2;
        }
        hash == *root
    }

    fn add_element(&mut self, element: u32) {
        let hash = hash_one(element);
        self.levels[0].push(hash);
        if self.leafs().len() % 2 == 1 { // Duplicate if we end up with odd number of elements
            self.levels[0].push(hash);
        }

        let mut new_levels: Vec<Vec<Hash>> = vec![self.leafs().clone()];
        let mut i = 0;
        while new_levels[i].len() > 1 {
            new_levels.push(calculate_next_level(&new_levels[i]));
            i += 1;
        }
        self.levels = new_levels;
    }
}

impl Debug for MerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        for level in &self.levels {
            writeln!(f, "{{")?;
            for hash in level {
                write!(f, "\t")?;
                for byte in hash {
                    write!(f, "{:02x}", byte)?;
                }
                writeln!(f, ",")?;
            }
            writeln!(f, "}},")?;
        }
        writeln!(f, "}}")
    }
}

macro_rules! dbg_level {
    ($var:expr) => {{
        let name = stringify!($var);
        println!("{}: {{", name);
        for hash in &$var {
            println!(
                "\t{},",
                hash.iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>()
            );
        }
        println!("}}");
    }};
}

/// Creates the next (upper) level for a Merkle Tree given the previous level.
fn calculate_next_level(prev_level: &[Hash]) -> Vec<Hash> {
    let mut next_level: Vec<Hash> = vec![];
    if prev_level.is_empty() {
        return next_level;
    }
    for i in (0..prev_level.len()-1).step_by(2) {
        let left = prev_level[i];
        let right = prev_level[i+1];
        let hash = hash_multiple(&[left, right]);
        next_level.push(hash);
    }
    // If the level has an odd number of elements duplicate the last, unless it's the root.
    if next_level.len() > 1 && next_level.len() % 2 == 1 {
        next_level.push(next_level[next_level.len()-1]);
    }
    next_level
}

/// Creates the bottom level (leafs) for a Merkle Tree given a vector of u32
fn create_initial_level<T: Serializable>(initial_vals: &[T]) -> Vec<Hash> {
    let mut level: Vec<Hash> = vec![];
    for i in initial_vals.iter() {
        level.push(Keccak256::digest(i.to_le_bytes()).into());
    }
    if level.len() % 2 == 1 { // Duplicate last element if we end up with odd number of elements
        level.push(level[level.len()-1]);
    }
    level
}

/// Returns the digest for a single u32
fn hash_one<T: Serializable>(n: T) -> Hash {
    Keccak256::digest(n.to_le_bytes()).into()
}

/// Returns the digest for several strings
fn hash_multiple(hashes: &[Hash]) -> Hash {
    let mut hasher = Keccak256::new();
    for h in hashes.iter() {
        sha3::Digest::update(&mut hasher, h);
    }
    hasher.finalize().into()
}

fn main() {
    let mut tree = MerkleTree::create_from_values(&[3, 4, 5, 6, 11, 10, 2, 1]);
    dbg!(&tree);

    if tree.num_elements() == 8 {
        println!("Tree has 8 elements")
    }

    // Ensure tree contains a given hash
    if tree.contains_hash(&hash_one(5)) {
        println!("Contains hash for 5")
    } else {
        println!("Does not contain hash for 5")
    }

    tree.add_element(9);
    // Create and verify proof
    let (proof, idx) = tree.generate_proof( 9).unwrap();
    dbg_level!(proof);
    if tree.verify_proof(9, idx, &proof) {
        println!("9 belongs to tree")
    } else {
        println!("9 does not belong to tree")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_the_same() {
        let first_hash = hash_one(32);
        let second_hash = hash_one(32);
        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn test_creation_and_contains_hash() {
        let mut tree = MerkleTree::create_from_values(&[3, 4, 5, 6]);
        dbg!(&tree);

        let three_hash = hash_one(3);
        let four_hash = hash_one(4);
        let threefour_hash = hash_multiple(&[three_hash.clone(), four_hash.clone()]);

        let five_hash = hash_one(5);
        let six_hash = hash_one(6);
        let fivesix_hash = hash_multiple(&[five_hash.clone(), six_hash.clone()]);

        let root = hash_multiple(&[threefour_hash.clone(), fivesix_hash.clone()]);

        // Test we can get the leaf index for each element
        assert_eq!(tree.leaf_index_for_element(5), Some(2));
        assert_eq!(tree.leaf_index_for_element(6), Some(3));
        assert_eq!(tree.leaf_index_for_element(11), None);

        // Test contains_hash
        assert!(tree.contains_hash(&three_hash));
        assert!(tree.contains_hash(&four_hash));
        assert!(tree.contains_hash(&threefour_hash));
        assert!(tree.contains_hash(&five_hash));
        assert!(tree.contains_hash(&six_hash));
        assert!(tree.contains_hash(&fivesix_hash));
        assert!(tree.contains_hash(&root));
        assert!(!tree.contains_hash(&hash_one(7)));


        // Test verify_proof for even index
        let (proof_3, index_3) = tree.generate_proof(3).unwrap();
        dbg_level!(proof_3);
        assert!(tree.verify_proof(3, index_3, &proof_3,));
        assert!(!tree.verify_proof(9, index_3, &proof_3,));

        // Test tree.verify_proof for odd index
        let (proof_6, index_6) = tree.generate_proof(6).unwrap();
        dbg_level!(proof_6);
        assert!(tree.verify_proof(6, index_6, &proof_6,));
        assert!(!tree.verify_proof(9, index_6, &proof_6,));

        // Test verify_proof is None for non-existent item
        assert_eq!(tree.generate_proof(11), None);

        // Now let's attempt to add a new element to the three
        assert_eq!(tree.leaf_index_for_element(7), None);
        tree.add_element(7);
        assert_eq!(tree.leaf_index_for_element(7), Some(4));
        let (proof_7, index_7) = tree.generate_proof(7).unwrap();
        dbg_level!(proof_7);
        assert!(tree.verify_proof(7, index_7, &proof_7,));
    }

    #[test]
    fn test_tree_is_generic_over_integers() {
        let tree = MerkleTree::create_from_values(&[3i32, 4i32, 5i32, 6i32]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(&[3u32, 4u32, 5u32, 6u32]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(&[3u8, 4u8, 5u8, 6u8]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(&[3i16, 4i16, 5i16, 6i16]);
        assert_eq!(tree.num_elements(), 4);
    }

    #[test]
    fn test_create_tree_with_odd_num_elements() {
        let tree = MerkleTree::create_from_values(&[3, 4, 5]);
        dbg!(&tree);
        assert_eq!(tree.num_elements(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.leafs()[2], tree.leafs()[3]);

        let tree = MerkleTree::create_from_values(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        dbg!(&tree);
        assert_eq!(tree.num_elements(), 10);
        assert_eq!(tree.leafs()[8], tree.leafs()[9]);
    }

    #[test]
    fn test_add_to_tree_4_elems() {
        let mut tree = MerkleTree::create_from_values(&[1, 2, 3, 4]);
        assert_eq!(tree.num_elements(), 4);
        dbg!(&tree);

        tree.add_element(5);
        dbg!(&tree);
        assert_eq!(tree.num_elements(), 6);
        let n = tree.leafs().len();
        assert_eq!(tree.leafs()[n-1], tree.leafs()[n-2]);
    }

    #[test]
    fn test_add_to_tree_8_elems() {
        let mut tree = MerkleTree::create_from_values(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(tree.levels[0].len(), 8);
        assert_eq!(tree.levels[1].len(), 4);
        assert_eq!(tree.levels[2].len(), 2);
        assert_eq!(tree.levels[3].len(), 1);
        dbg!(&tree);

        tree.add_element(10);
        dbg!(&tree);
        assert_eq!(tree.levels[0].len(), 10);
        assert_eq!(tree.levels[1].len(), 6);
        assert_eq!(tree.levels[2].len(), 4);
        assert_eq!(tree.levels[3].len(), 2);
        assert_eq!(tree.levels[4].len(), 1);
        let n = tree.leafs().len();
        assert_eq!(tree.leafs()[n-1], tree.leafs()[n-2]);
    }
}

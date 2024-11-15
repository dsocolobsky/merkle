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
    fn create_from_values<T: Serializable + Clone>(initial_vals: Vec<T>) -> Self {
        // If we have an odd number of leafs we need to duplicate the last element
        let mut initial_vals = initial_vals.clone();
        if initial_vals.len() % 2 == 1 {
            initial_vals.push(initial_vals.last().unwrap().clone());
        }

        let initial = create_initial_level(&initial_vals);
        let mut actual: Box<Vec<Hash>> = Box::new(initial);
        let mut merkle = MerkleTree {
            levels: vec![],
        };
        merkle.levels.push(*actual.clone());
        while actual.len() > 1 {
            actual = Box::new(calculate_next_level(&actual));
            merkle.levels.push(*actual.clone());
        }
        merkle
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
                proof.push(level[index+1].clone())
            } else {
                proof.push(level[index-1].clone())
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
                hash_multiple(&vec![hash.clone(), p.clone()])
            } else {
                hash_multiple(&vec![p.clone(), hash.clone()])
            };
            index /= 2;
        }
        hash == *root
    }

    fn add_element(&mut self, element: u32) {
        let n = self.num_elements();
        if !is_power_of_2(n) {
            unimplemented!("Only can add to a tree with power of 2 elements");
        }
        // Add n times the hash to the leaves
        let hash = hash_one(element);
        let mut new_leafs: Vec<Hash> = vec![];
        for _ in 0..n {
            new_leafs.push(hash.clone());
        }
        self.levels[0].extend_from_slice(&new_leafs);

        let mut next_level_extension = calculate_next_level(&new_leafs);
        let last_level = self.height() - 1;
        for current_level in self.levels.iter_mut().skip(1).take(last_level) {
            current_level.extend_from_slice(&next_level_extension);
            next_level_extension = calculate_next_level(&next_level_extension);
        }
        // We are now at the level previous from the root, first extend that level
        self.levels[last_level].extend_from_slice(&next_level_extension);
        // Now generate the new root based on that level, and push it to the end
        let new_root_level = calculate_next_level(&self.levels[self.height()-1]);
        self.levels.push(new_root_level);
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
                write!(f, ",\n")?;
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
        let right = *prev_level.get(i+1).unwrap_or(&left);
        let hash = hash_multiple(&vec![left, right]);
        next_level.push(hash);
    }
    next_level
}

/// Creates the bottom level (leafs) for a Merkle Tree given a vector of u32
fn create_initial_level<T: Serializable>(initial_vals: &[T]) -> Vec<Hash> {
    let mut res: Vec<Hash> = vec![];
    for i in initial_vals.iter() {
        res.push(Keccak256::digest(i.to_le_bytes()).into());
    }
    res
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

/// Returns if a number is power of 2, or 0
// In this case considering 0 as a power of 2 is useful.
fn is_power_of_2(n: usize) -> bool {
    (n & (n - 1)) == 0
}

fn main() {
    let mut tree = MerkleTree::create_from_values(vec![3, 4, 5, 6, 11, 10, 2, 1]);
    dbg!(&tree);

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
        let mut tree = MerkleTree::create_from_values(vec![3, 4, 5, 6]);
        dbg!(&tree);

        let three_hash = hash_one(3);
        let four_hash = hash_one(4);
        let threefour_hash = hash_multiple(&vec![three_hash.clone(), four_hash.clone()]);

        let five_hash = hash_one(5);
        let six_hash = hash_one(6);
        let fivesix_hash = hash_multiple(&vec![five_hash.clone(), six_hash.clone()]);

        let root = hash_multiple(&vec![threefour_hash.clone(), fivesix_hash.clone()]);

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
        let tree = MerkleTree::create_from_values(vec![3i32, 4i32, 5i32, 6i32]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(vec![3u32, 4u32, 5u32, 6u32]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(vec![3u8, 4u8, 5u8, 6u8]);
        assert_eq!(tree.num_elements(), 4);
        let tree = MerkleTree::create_from_values(vec![3i16, 4i16, 5i16, 6i16]);
        assert_eq!(tree.num_elements(), 4);
    }

    #[test]
    fn test_create_tree_with_odd_num_elements() {
        let tree = MerkleTree::create_from_values(vec![3, 4, 5]);
        assert_eq!(tree.num_elements(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.leafs()[2], tree.leafs()[3]);

        let tree = MerkleTree::create_from_values(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(tree.num_elements(), 10);
        assert_eq!(tree.leafs()[8], tree.leafs()[9]);
    }
}

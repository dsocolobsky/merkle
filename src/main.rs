use sha3::{Digest, Keccak256};

type MerkleTree = Vec<Vec<String>>;

/// Returns the index in the leaf array for a given element, if present.
fn leaf_index_for_element(merkle: &MerkleTree, element: u32) -> Option<usize> {
    let hash = hash_one(element);
    if let Some(index) = merkle[0].iter().position(|h| *h == hash) {
        Some(index)
    } else {
        None
    }
}

/// Generates a proof that a certain element belongs to the tree, if present.
fn generate_proof(merkle: &MerkleTree, element: u32) -> Option<(Vec<String>, usize)> {
    let Some( leaf_index) = leaf_index_for_element(merkle, element) else {
        return None
    };
    let mut proof: Vec<String> = vec![];

    let mut index = leaf_index;
    for level in merkle.iter().take(merkle.len() - 1) {
        if index % 2 == 0 {
            proof.push(level[index+1].clone())
        } else {
            proof.push(level[index-1].clone())
        }
        index = index / 2;
    }

    Some((proof, leaf_index))
}

/// Given an element, it's index and a proof verifies it against the root of a Merkle Tree
fn verify_proof(element: u32, index: usize, proof: &[String], root: &String) -> bool {
    let mut hash = hash_one(element);
    let mut index = index;

    for p in proof.iter() {
        hash = if index % 2 == 0 {
            hash_multiple(vec![hash.clone(), p.clone()])
        } else {
            hash_multiple(vec![p.clone(), hash.clone()])
        };
        index = index / 2;
    }
    hash == *root
}

/// Checks if the given hash is present at any level of the Merkle Tree
fn contains_hash(merkle: &MerkleTree, hash: &String) -> bool {
    merkle.iter().any(|level| level.contains(hash))
}

/// Creates the next (upper) level for a Merkle Tree given the previous level.
fn calculate_next_level(prev_level: &[String]) -> Vec<String> {
    let mut next_level: Vec<String> = vec![];
    if prev_level.is_empty() {
        return next_level;
    }
    for i in (0..prev_level.len()-1).step_by(2) {
        let hash = hash_multiple(vec![prev_level[i].clone(), prev_level[i+1].clone()]);
        next_level.push(hash);
    }
    next_level
}

/// Creates the bottom level (leafs) for a Merkle Tree given a vector of u32
fn create_initial_level(initial_vals: &[u32]) -> Vec<String> {
    let mut res: Vec<String> = vec![];
    for &i in initial_vals.iter() {
        let hash = Keccak256::digest(i.to_le_bytes());
        let hash = hex::encode(hash);
        res.push(hash);
    }
    res
}

/// Creates a Merkle Tree given a vector of u32
fn create_merkle_tree(initial_vals: &[u32]) -> MerkleTree {
    let initial = create_initial_level(initial_vals);
    let mut actual: Box<Vec<String>> = Box::new(initial);
    let mut levels: MerkleTree = vec![];
    levels.push(*actual.clone());
    while actual.len() > 1 {
        actual = Box::new(calculate_next_level(&actual));
        levels.push(*actual.clone());
    }
    levels
}

/// Returns the digest for a single u32
fn hash_one(n: u32) -> String {
    hex::encode(Keccak256::digest(n.to_le_bytes()))
}

/// Returns the digest for several strings
fn hash_multiple(hashes: Vec<String>) -> String {
    let mut hasher = Keccak256::new();
    for h in hashes.iter() {
        sha3::Digest::update(&mut hasher, h);
    }
    hex::encode(hasher.finalize())
}

fn main() {
    let tree = create_merkle_tree(&vec![3, 4, 5, 6, 9, 10, 2, 1]);
    let Some(root) = tree.last() else {
        panic!("Tree should have a root");
    };
    dbg!(&tree);

    // Ensure tree contains a given hash
    if contains_hash(&tree, &hash_one(5)) {
        println!("Contains hash for 5")
    } else {
        println!("Does not contain hash for 5")
    }

    // Create and verify proof
    let (proof, idx) = generate_proof(&tree, 9).unwrap();
    if verify_proof(9, idx, &proof, &root[0]) {
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
        let tree = create_merkle_tree(&vec![3, 4, 5, 6]);
        dbg!(&tree);

        let three_hash = hash_one(3);
        let four_hash = hash_one(4);
        let threefour_hash = hash_multiple(vec![three_hash.clone(), four_hash.clone()]);

        let five_hash = hash_one(5);
        let six_hash = hash_one(6);
        let fivesix_hash = hash_multiple(vec![five_hash.clone(), six_hash.clone()]);

        let root = hash_multiple(vec![threefour_hash.clone(), fivesix_hash.clone()]);

        // Test we can get the leaf index for each element
        assert_eq!(leaf_index_for_element(&tree, 5), Some(2));
        assert_eq!(leaf_index_for_element(&tree, 6), Some(3));
        assert_eq!(leaf_index_for_element(&tree, 11), None);

        // Test contains_hash
        assert!(contains_hash(&tree, &three_hash));
        assert!(contains_hash(&tree, &four_hash));
        assert!(contains_hash(&tree, &threefour_hash));
        assert!(contains_hash(&tree, &five_hash));
        assert!(contains_hash(&tree, &six_hash));
        assert!(contains_hash(&tree, &fivesix_hash));
        assert!(contains_hash(&tree, &root));
        assert!(!contains_hash(&tree, &hash_one(7)));


        // Test verify_proof for even index
        let (proof_3, index_3) = generate_proof(&tree, 3).unwrap();
        dbg!(&proof_3);
        assert!(verify_proof(3, index_3, &proof_3, &root));
        assert!(!verify_proof(9, index_3, &proof_3, &root));

        // Test verify_proof for odd index
        let (proof_6, index_6) = generate_proof(&tree, 6).unwrap();
        dbg!(&proof_6);
        assert!(verify_proof(6, index_6, &proof_6, &root));
        assert!(!verify_proof(9, index_6, &proof_6, &root));

        // Test verify_proof is None for non-existent item
        assert_eq!(generate_proof(&tree, 11), None)
    }
}

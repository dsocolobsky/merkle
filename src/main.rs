use sha3::{Digest, Keccak256};

type MerkleTree = Vec<Vec<String>>;

/// Checks if the given hash is present at any level of the Merkle Tree
fn contains_hash(merkle: &MerkleTree, hash: &String) -> bool {
    merkle.iter().any(|level| level.contains(hash))
}

/// Creates the next (upper) level for a Merkle Tree given the previous level.
fn calculate_next_level(vec: &[String]) -> Vec<String> {
    let mut next_level: Vec<String> = vec![];
    if vec.is_empty() {
        return next_level;
    }
    for i in (0..vec.len()-1).step_by(2) {
        let hash = hash_multiple_str(vec![vec[i].clone(), vec[i+1].clone()]);
        next_level.push(hash);
    }
    next_level
}

/// Creates the bottom level (leafs) for a Merkle Tree given a vector of u32
fn create_initial_level(vec: &[u32]) -> Vec<String> {
    let mut res: Vec<String> = vec![];
    for &i in vec.iter() {
        let hash = Keccak256::digest(i.to_le_bytes());
        let hash = hex::encode(hash);
        res.push(hash);
    }
    res
}

/// Creates a Merkle Tree given a vector of u32
fn create_merkle_tree(vec: &[u32]) -> MerkleTree {
    let initial = create_initial_level(vec);
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
fn hash_multiple_str(vec: Vec<String>) -> String {
    let mut hasher = Keccak256::new();
    for s in vec.iter() {
        sha3::Digest::update(&mut hasher, s);
    }
    hex::encode(hasher.finalize())
}

fn main() {
    let tree = create_merkle_tree(&vec![3, 4, 5, 6, 9, 10, 2, 1]);
    contains_hash(&tree, &hash_one(6));
    dbg!(tree);
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
        let threefour_hash = hash_multiple_str(vec![three_hash.clone(), four_hash.clone()]);

        let five_hash = hash_one(5);
        let six_hash = hash_one(6);
        let fivesix_hash = hash_multiple_str(vec![five_hash.clone(), six_hash.clone()]);

        let root = hash_multiple_str(vec![threefour_hash.clone(), fivesix_hash.clone()]);

        assert!(contains_hash(&tree, &three_hash));
        assert!(contains_hash(&tree, &four_hash));
        assert!(contains_hash(&tree, &threefour_hash));
        assert!(contains_hash(&tree, &five_hash));
        assert!(contains_hash(&tree, &six_hash));
        assert!(contains_hash(&tree, &fivesix_hash));
        assert!(contains_hash(&tree, &root));

        assert!(!contains_hash(&tree, &hash_one(7)));
    }
}
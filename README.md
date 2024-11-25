# Rusty Merkle

This is an implementation of a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)
written in Rust.

## Running

```bash
git clone git@github.com:dsocolobsky/merkle.git && cd merkle
make run
make test
```

## Implemented Features
- Create a Merkle Tree from a list of integers or strings.
- Add a new element to an existing Merkle Tree.
- Create a proof that an element belongs to the Merkle Tree.
- Given an element, index and a proof, verify it against a Merkle Tree.

## How to use
```rust
// Create a new merkle tree from certain values
let mut tree = MerkleTree::create_from_values(&[1, 2, 3, 4]);

// Get information about the tree
println!("{tree.height()})");
println!("{tree.num_elements()})");
println!("{tree.leaves()})");
println!("{tree.root()})");

// Add a new element to the existing tree
tree.add_element(5);

// Generate a proof that an element belongs to the tree
let (proof, idx) = tree.generate_proof(3).expect("Failed to generate proof");

// Verify a proof against the tree
tree.verify_proof(3, idx, &proof);

// Trees are generic over integer types (u8...u128/i8...i128) and strings too
let tree = MerkleTree::create_from_values(&["banana", "manzana"]);
```

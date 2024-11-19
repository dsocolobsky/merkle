# Rusty Merkle

This is an implementation of a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)
written in Rust.

## Running

* Clone the repository `git clone git@github.com:dsocolobsky/merkle.git`
* `make run`
* `make test`

## Implemented Features
- Create a Merkle Tree from a list of integers.
- Add a new element to an existing Merkle Tree.
- Create a proof that an element belongs to the Merkle Tree.
- Given an element, index and a proof, verify it against a Merkle Tree.

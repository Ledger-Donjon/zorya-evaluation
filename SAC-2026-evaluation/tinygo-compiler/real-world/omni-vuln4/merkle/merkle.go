package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

// MultiProof is a merkle-multi-proof for multiple leaves.
type MultiProof struct {
	Leaves     [][32]byte
	Proof      [][32]byte
	ProofFlags []bool
}

// MakeTree returns a merkle tree given the leaves.
func MakeTree(leaves [][32]byte) ([][32]byte, error) {
	if len(leaves) == 0 {
		return nil, errors.New("no leaves provided")
	}

	treeLen := 2*len(leaves) - 1
	tree := make([][32]byte, treeLen)

	// Fill in leaves in reverse order.
	for i, leaf := range leaves {
		tree[treeLen-1-i] = leaf
	}

	// Fill in the internal nodes up to the root.
	for i := treeLen - 1 - len(leaves); i >= 0; i-- {
		tree[i] = hashPair(tree[leftChildIndex(i)], tree[rightChildIndex(i)])
	}

	return tree, nil
}

// GetMultiProof returns a merkle-multi-proof for the given leaf indices.
func GetMultiProof(tree [][32]byte, indices ...int) (MultiProof, error) {
	if len(indices) == 0 {
		return MultiProof{}, errors.New("no indices provided")
	}

	// Ensure each index is actually a leaf
	for _, i := range indices {
		if err := checkLeafNode(tree, i); err != nil {
			return MultiProof{}, err
		}
	}

	// Sort indices in descending order
	sort.Slice(indices, func(i, j int) bool {
		return indices[i] > indices[j]
	})

	// Check for duplicates
	for i := 1; i < len(indices); i++ {
		if indices[i] == indices[i-1] {
			return MultiProof{}, errors.New("cannot prove duplicated index")
		}
	}

	stack := make([]int, len(indices))
	copy(stack, indices)

	var proof [][32]byte
	var proofFlags []bool

	for len(stack) > 0 && stack[0] > 0 {
		// Pop from the beginning
		j := stack[0]
		stack = stack[1:]

		s := siblingIndex(j)
		p := parentIndex(j)

		// If next item in stack is the sibling, skip adding proof
		if len(stack) > 0 && s == stack[0] {
			proofFlags = append(proofFlags, true)
			stack = stack[1:]
		} else {
			proofFlags = append(proofFlags, false)
			// VULN: can panic if s >= len(tree)!
			proof = append(proof, tree[s])
		}
		stack = append(stack, p)
	}

	leaves := make([][32]byte, 0, len(indices))
	for _, i := range indices {
		leaves = append(leaves, tree[i])
	}

	return MultiProof{
		Leaves:     leaves,
		Proof:      proof,
		ProofFlags: proofFlags,
	}, nil
}

// ---------------------------------------------------
// Helper functions
// ---------------------------------------------------

func leftChildIndex(i int) int  { return 2*i + 1 }
func rightChildIndex(i int) int { return 2*i + 2 }

func parentIndex(i int) int {
	if i == 0 {
		panic("root has no parent")
	}
	return (i - 1) / 2
}

func siblingIndex(i int) int {
	if i == 0 {
		panic("root has no sibling")
	}
	if i%2 == 0 {
		return i - 1
	}
	return i + 1
}

func isTreeNode(tree [][32]byte, i int) bool {
	return i >= 0 && i < len(tree)
}

func isInternalNode(tree [][32]byte, i int) bool {
	return isTreeNode(tree, leftChildIndex(i))
}

func isLeafNode(tree [][32]byte, i int) bool {
	return isTreeNode(tree, i) && !isInternalNode(tree, i)
}

func checkLeafNode(tree [][32]byte, i int) error {
	if !isLeafNode(tree, i) {
		return errors.New("index is not a leaf")
	}
	return nil
}

func hashPair(a, b [32]byte) [32]byte {
	// sort and concat
	data := sortBytes(a[:], b[:])
	return hash(append(data[0], data[1]...))
}

func hash(buf []byte) [32]byte {
	return sha256.Sum256(buf)
}

func sortBytes(bufs ...[]byte) [][]byte {
	sort.Slice(bufs, func(i, j int) bool {
		return bytes.Compare(bufs[i], bufs[j]) < 0
	})
	return bufs
}

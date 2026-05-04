//go:build go1.18

// FuzzVerifyCommit_NoOracle demonstrates that go test -fuzz CANNOT detect
// the Tendermint v0.26.0 voting-power INTMUL overflow in VerifyCommit because:
//
//  1. VerifyCommit returns (error, nil) — never panics.
//  2. When the overflow fires it returns nil (accepted) instead of an error
//     (rejected) — a silent wrong result with no crash signal for the fuzzer.
//  3. Without a test oracle asserting "this commit must be rejected", the
//     fuzzer has zero feedback and cannot distinguish correct from buggy behaviour.
//
// Expected result: fuzzer runs indefinitely; finds 0 bugs.
package tmfuzz

import (
	"testing"

	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/types"
)

// testKey is a fixed ed25519 key used to create validators.
// We reuse one key so every validator has a valid PubKey without
// generating fresh entropy on every fuzz iteration.
var testKey = ed25519.GenPrivKey()

func FuzzVerifyCommit_NoOracle(f *testing.F) {
	// Seed corpus includes the exact overflow trigger values.
	// Even though the fuzzer will generate these, it has no signal to act on.
	f.Add(int64(4611686018427387904)) // MaxInt64/2 + 1 — overflow trigger
	f.Add(int64(9223372036854775806)) // MaxInt64 - 1   — also overflows
	f.Add(int64(1))
	f.Add(int64(1000))

	f.Fuzz(func(t *testing.T, votingPower int64) {
		if votingPower <= 0 {
			return
		}

		// Build a one-validator set whose totalVotingPower equals votingPower.
		val := types.NewValidator(testKey.PubKey(), votingPower)
		vals := types.NewValidatorSet([]*types.Validator{val})

		// Commit with one nil precommit:
		//   - vals.Size() == 1 == len(commit.Precommits)  → size check passes
		//   - precommit == nil → VerifyBytes is NEVER called
		//   - talliedVotingPower stays 0 after the loop
		//   - blockID{} == commit.BlockID{}               → blockID check passes
		//   - height 0 == commit.Height() (nil precommit) → height check passes
		commit := &types.Commit{
			BlockID:    types.BlockID{},
			Precommits: []*types.Vote{nil},
		}

		err := vals.VerifyCommit("test-chain", types.BlockID{}, 0, commit)

		// NO oracle.
		// Fuzzer observes:
		//   err != nil  → "rejected"  (correct behaviour for most inputs)
		//   err == nil  → "accepted"  (WRONG when votingPower causes overflow,
		//                              but fuzzer cannot tell the difference)
		_ = err
	})
}

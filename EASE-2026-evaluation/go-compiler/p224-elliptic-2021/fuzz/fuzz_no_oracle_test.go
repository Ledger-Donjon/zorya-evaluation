//go:build go1.18

package p224fuzz

import "testing"

// FuzzP224_NoOracle demonstrates that standard coverage-guided fuzzing
// CANNOT detect the CVE-2021-3114 P-224 carry bug.
//
// The vulnerable P224Contract_Buggy function returns silently wrong field
// elements in two edge cases, but NEVER panics, never calls runtime.throw,
// and never triggers any Go runtime safety check.
//
// A coverage-guided fuzzer (go test -fuzz) only stops when it finds a crash.
// Since there is no crash, it runs forever with zero findings regardless of
// how many inputs it tries.
//
// Expected result after any fuzz duration:
//
//	PASS  (zero failures)
func FuzzP224_NoOracle(f *testing.F) {
	// Seed 1: P - 1 with zero lowest limb → directly triggers Bug 2
	f.Add(uint32(0), uint32(0), uint32(0), uint32(0x0ffff000),
		uint32(0xfffffff), uint32(0xfffffff), uint32(0xfffffff), uint32(0xfffffff))

	// Seed 2: P + 2^28 with zero lowest limb → another Bug 2 trigger
	f.Add(uint32(0), uint32(1), uint32(0), uint32(0x0ffff000),
		uint32(0xfffffff), uint32(0xfffffff), uint32(0xfffffff), uint32(0xfffffff))

	// Seed 3: all-zeros (trivial case)
	f.Add(uint32(0), uint32(0), uint32(0), uint32(0),
		uint32(0), uint32(0), uint32(0), uint32(0))

	f.Fuzz(func(t *testing.T,
		l0, l1, l2, l3, l4, l5, l6, l7 uint32) {

		in := P224FieldElement{
			l0 & 0x1fffffff, l1 & 0x1fffffff, l2 & 0x1fffffff, l3 & 0x1fffffff,
			l4 & 0x1fffffff, l5 & 0x1fffffff, l6 & 0x1fffffff, l7 & 0x1fffffff,
		}
		var out P224FieldElement

		// Call the buggy function — even on the bug-triggering seeds above,
		// this returns wrong values silently with no panic or abort.
		P224Contract_Buggy(&out, &in)

		// No assertion here = no oracle = fuzzer is blind.
		// The wrong output in `out` is not observable without a reference.
		_ = out
	})
}

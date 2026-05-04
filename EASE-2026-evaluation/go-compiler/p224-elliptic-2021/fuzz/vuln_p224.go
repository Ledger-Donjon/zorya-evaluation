// vuln_p224.go — verbatim copy of the VULNERABLE p224Contract from go1.14.13
// (src/crypto/elliptic/p224.go before CVE-2021-3114 fix, commit d95ca91)
//
// Bug 1 (line marked BUG1): wrong sign in out3GT mask
//
//	n := out[3] - 0xffff000   should be   0xffff000 - out[3]
//	out3GT := ^uint32(...)    should be   uint32(...)
//
// Bug 2 (line marked BUG2): missing carry-down after conditional P-subtraction
//
//	When out[0] == 0 and the subtraction fires, out[0] wraps to 0xFFFFFFFF
//	(uint32 underflow) with NO panic. The fix adds a final carry-down loop.
//
// Both bugs produce silently wrong field elements — no abort, no panic.
package p224fuzz

// P224FieldElement is an 8-limb radix-2^28 representation of a P-224 field element.
// Each limb must be < 2^29 on entry; < 2^28 after p224Contract.
type P224FieldElement [8]uint32

const bottom28Bits uint32 = 0xFFFFFFF

// P224Contract_Buggy is the exact vulnerable function from go1.14.13.
// It performs the final complete reduction modulo P-224 but contains two bugs.
func P224Contract_Buggy(out, in *P224FieldElement) {
	copy(out[:], in[:])

	// First carry chain: normalise each limb to < 2^28.
	for i := 0; i < 7; i++ {
		out[i+1] += out[i] >> 28
		out[i] &= bottom28Bits
	}
	top := out[7] >> 28
	out[7] &= bottom28Bits

	// Use the P-224 reduction identity:  a + top*2^224 = a + top*2^96 - top
	out[0] -= top
	out[3] += top << 12

	// Carry down any negative limbs produced above.
	for i := 0; i < 3; i++ {
		mask := uint32(int32(out[i]) >> 31)
		out[i] += (1 << 28) & mask
		out[i+1] -= 1 & mask
	}

	// Second carry chain (handles the extra top from out[3] overflow).
	for i := 0; i < 7; i++ {
		out[i+1] += out[i] >> 28
		out[i] &= bottom28Bits
	}
	top = out[7] >> 28
	out[7] &= bottom28Bits

	out[0] -= top
	out[3] += top << 12

	for i := 0; i < 3; i++ {
		mask := uint32(int32(out[i]) >> 31)
		out[i] += (1 << 28) & mask
		out[i+1] -= 1 & mask
	}

	// Check whether value >= P and conditionally subtract P.
	top4AllOnes := uint32(0xFFFFFFFF)
	for i := 4; i < 8; i++ {
		top4AllOnes &= out[i]
	}
	top4AllOnes |= 0xF0000000
	top4AllOnes++
	top4AllOnes >>= 28

	bottom3NonZero := out[0] | out[1] | out[2]
	bottom3NonZero |= bottom3NonZero >> 16
	bottom3NonZero |= bottom3NonZero >> 8
	bottom3NonZero |= bottom3NonZero >> 4
	bottom3NonZero |= bottom3NonZero >> 2
	bottom3NonZero |= bottom3NonZero >> 1
	bottom3NonZero = uint32(int32(bottom3NonZero<<31) >> 31)

	// BUG1: subtraction in wrong direction → out3GT mask is inverted.
	// Correct: n := 0xffff000 - out[3]  and  out3GT := uint32(int32(n) >> 31)
	n := out[3] - 0xffff000 // BUG1a
	out3Equal := n
	out3Equal |= out3Equal >> 16
	out3Equal |= out3Equal >> 8
	out3Equal |= out3Equal >> 4
	out3Equal |= out3Equal >> 2
	out3Equal |= out3Equal >> 1
	out3Equal = ^uint32(int32(out3Equal<<31) >> 31)

	out3GT := ^uint32(int32(n) >> 31) // BUG1b — should be uint32(...), not ^uint32(...)

	mask := top4AllOnes & ((out3Equal & bottom3NonZero) | out3GT)
	out[0] -= 1 & mask
	out[3] -= 0xffff000 & mask
	out[4] -= 0xfffffff & mask
	out[5] -= 0xfffffff & mask
	out[6] -= 0xfffffff & mask
	out[7] -= 0xfffffff & mask

	// BUG2: missing carry-down here.
	// When out[0] == 0 and mask == 1, out[0] wraps to 0xFFFFFFFF (silent uint32 underflow).
	// The fix (commit d95ca91) adds:
	//   for i := 0; i < 3; i++ {
	//       mask := uint32(int32(out[i]) >> 31)
	//       out[i] += (1 << 28) & mask
	//       out[i+1] -= 1 & mask
	//   }
}

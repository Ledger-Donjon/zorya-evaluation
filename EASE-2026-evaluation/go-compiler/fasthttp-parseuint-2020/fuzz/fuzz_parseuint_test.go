//go:build go1.18

// Package fasthttp is used here only to access parseUintBuf via a test file
// placed inside the fasthttp module (same package).
// Run from the fasthttp source tree at the vulnerable commit:
//
//	cp fuzz_parseuint_test.go /path/to/fasthttp/
//	cd /path/to/fasthttp
//	go test -run=^$ -fuzz=FuzzParseUintBuf        # no oracle — never fails
//	go test -run=^$ -fuzz=FuzzParseUintBuf_Oracle  # with oracle — finds bug immediately
package fasthttp

import (
	"math/big"
	"testing"
)

// FuzzParseUintBuf runs parseUintBuf with random byte-slice inputs but has
// NO oracle. Because the overflow is silent (wrong int, no panic, no error),
// the fuzzer has zero signal and runs indefinitely without finding the bug.
//
// Expected result: PASS after millions of executions — bug is invisible.
func FuzzParseUintBuf(f *testing.F) {
	f.Add([]byte("0"))
	f.Add([]byte("1"))
	f.Add([]byte("123"))
	f.Add([]byte("9223372036854775807"))  // MaxInt64
	f.Add([]byte("9999999999999999999"))  // 19 nines — potential overflow trigger
	f.Add([]byte("18446744073709551615")) // MaxUint64 — should be rejected
	f.Fuzz(func(t *testing.T, b []byte) {
		// Calling parseUintBuf: returns (value, consumed, error).
		// The bug causes it to return a WRONG value with err=nil for large inputs.
		// No panic ever occurs → fuzzer has zero signal → never terminates with a bug.
		parseUintBuf(b) //nolint:errcheck
	})
}

// FuzzParseUintBuf_Oracle runs parseUintBuf against a big.Int reference
// implementation. This differential oracle immediately detects wrong outputs.
//
// Expected result: bug found quickly with input like "9999999999999999999".
func FuzzParseUintBuf_Oracle(f *testing.F) {
	f.Add([]byte("0"))
	f.Add([]byte("9223372036854775807")) // MaxInt64
	f.Add([]byte("9999999999999999999")) // 19 nines
	f.Fuzz(func(t *testing.T, b []byte) {
		// Only test all-digit strings to isolate the arithmetic path.
		if len(b) == 0 {
			return
		}
		for _, c := range b {
			if c < '0' || c > '9' {
				return
			}
		}
		// Skip leading zeros (parseUintBuf accepts them but they're uninteresting).
		if len(b) > 1 && b[0] == '0' {
			return
		}

		got, n, err := parseUintBuf(b)

		// Oracle: compute the true value with arbitrary precision.
		expected, ok := new(big.Int).SetString(string(b), 10)
		if !ok {
			return
		}
		maxInt64 := big.NewInt(1<<63 - 1)

		if expected.Cmp(maxInt64) > 0 {
			// Input exceeds MaxInt64 — parseUintBuf MUST return an error.
			if err == nil {
				t.Fatalf(
					"OVERFLOW NOT DETECTED:\n  input    = %q\n  expected = error\n  got      = %d (consumed %d bytes, err=nil)",
					b, got, n,
				)
			}
			return
		}

		// Input fits in int64 — parseUintBuf must return the correct value.
		if err != nil {
			t.Fatalf("unexpected error for valid input %q: %v", b, err)
		}
		if int64(got) != expected.Int64() {
			t.Fatalf(
				"WRONG RESULT:\n  input    = %q\n  expected = %s\n  got      = %d",
				b, expected, got,
			)
		}
	})
}

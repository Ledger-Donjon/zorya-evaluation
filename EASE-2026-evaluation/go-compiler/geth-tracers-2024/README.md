# Go-Ethereum Call Tracer Nil Pointer Dereference

This case demonstrates a nil pointer dereference vulnerability in go-ethereum's `(*callTracer).OnTxEnd()` method, fixed in commit [30824fa](https://github.com/ethereum/go-ethereum/commit/30824fa). The bug occurs when `OnTxEnd` is called with a nil receipt and no error: `receipt.GasUsed` is accessed unconditionally before the nil guard, causing a panic. Zorya detects this vulnerability through **symbolic execution and concolic analysis** directly on the compiled geth binary.

## Vulnerability

Looking at the vulnerable code in `eth/tracers/native/call.go`:

```go
func (t *callTracer) OnTxEnd(receipt *types.Receipt, err error) {
    // Error happened during tx validation.
    if err != nil {
        return
    }
    t.callstack[0].GasUsed = receipt.GasUsed  // <-- BUG: receipt can be nil here!
    if receipt != nil {
        t.callstack[0].GasUsed = receipt.GasUsed
    }
    if t.config.WithLog {
        // Logs are not emitted when the call fails
        clearFailedLogs(&t.callstack[0], false)
    }
}
```

**The bug**: When `OnTxEnd` is called with `receipt = nil` and `err = nil` (e.g. from the state test runner), the code dereferences `receipt.GasUsed` on the line **before** the nil check, causing a panic. The `if receipt != nil` guard below it is useless — the dereference has already happened.

**The fix** (commit 30824fa) moves the nil check before the dereference:
```go
    if err != nil {
        return
    }
+   if receipt == nil {   // ← nil check moved before dereference
+       return
+   }
    t.callstack[0].GasUsed = receipt.GasUsed   // now safe
    if t.config.WithLog {
        clearFailedLogs(&t.callstack[0], false)
    }
```

## How It Happens

1. A transaction is executed but produces no receipt (e.g. validation failure with no error, or state test runner path)
2. The tracer's `OnTxEnd` hook is called with `(nil, nil)` — nil receipt, no error
3. `err != nil` is false, so execution continues
4. `receipt.GasUsed` dereferences nil → **panic**

## Reproduction Workflow

### 1. Build vulnerable geth binary

```bash
# Clone go-ethereum repository
git clone https://github.com/ethereum/go-ethereum.git
cd go-ethereum

# Checkout the vulnerable commit (parent of the fix)
git checkout 733fcbbc65bca69e28480f624e2aeb170c97cb3e

# Build geth with debug symbols
go build -gcflags="all=-N -l" -o build/bin/geth ./cmd/geth

# Find the function address
nm build/bin/geth | grep "callTracer.*OnTxEnd"
# Look for: github.com/ethereum/go-ethereum/eth/tracers/native.(*callTracer).OnTxEnd
# Example: 0000000001fd7980 t github.com/ethereum/go-ethereum/eth/tracers/native.(*callTracer).OnTxEnd
```

### 2. Set up concrete execution state (3 terminals)

**Terminal 1** — Start geth node:
```bash
./build/bin/geth --dev --http --http.api eth,debug,web3
```

**Terminal 2** — Send a transaction to trace:
```bash
# Get the dev account
ADDR=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' \
  http://localhost:8545 | jq -r '.result[0]')
echo "Dev address: $ADDR"

# Send a transaction
TX_HASH=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"'$ADDR'","to":"'$ADDR'","value":"0x1"}],"id":1}' \
  http://localhost:8545 | jq -r '.result')
echo "TX_HASH: $TX_HASH"
```

**Terminal 3** — Trigger the vulnerable tracer path (creates the snapshot):
```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["'$TX_HASH'", {"tracer": "callTracer"}],"id":1}' \
  http://localhost:8545
```

This curl request invokes `OnTxEnd` at the moment geth is snapshotted for Zorya.

### 3. Run Zorya analysis

```bash
zorya /home/kgorna/go-ethereum/build/bin/geth \
  --mode function 0x1f36e80 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --arg "--dev --http --http.api eth,debug,web3" \
  --negate-path-exploration
```

**Note:** Replace `0x1f36e80` with the actual address from step 1 (`nm` output).

### 4. Zorya Detection Results

**Vulnerability Detected**: **YES** — 3 findings

```bash
zorya /home/kgorna/go-ethereum/build/bin/geth \
  --mode function 0x1f36e80 \
  --lang go \
  --compiler gc \
  --arg "--dev --http --http.api eth,debug,web3" \
  --negate-path-exploration
```

Zorya produced **3 successive findings** during the same run:

---

#### Finding 1 — Symbolic NULL on receiver `t` (1049s)

```
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x1f36eb3
  Elapsed: 1049.817s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer

The program can panic if its inputs are the following:
  - The input 'err' must be 0
  - The input 't_ptr' must be 0 (nil)
```

Zorya proves that if the receiver `t` itself is nil (and `err` is nil), the first access to `t.callstack[0]` panics. This is a defensive finding — in practice `t` is never nil, but Zorya exhaustively covers all symbolic cases.

---

#### Finding 2 — The actual bug: nil receipt dereference (1277s)

```
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x1f36eb5
  Elapsed: 1277.320s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer

The program can panic if its inputs are the following:
  - The input 'err' must be 0
  - The pointer 'receipt_ptr' must be 0 (nil)
```

This is the **root cause finding**. Zorya proves that when `err = nil` and `receipt = nil`, the code reaches `receipt.GasUsed` → panic. The Z3 model confirms:
- `receipt_ptr!152 = 0x0` — receipt pointer is nil → dereference panics
- `err_RCX!168 = 0x0` — no error → guard at `if err != nil` does not return
- `t_ptr!141 = 0x8000402000000001` — `t` itself is a valid non-nil pointer

---

#### Finding 3 — Index out of range on empty callstack (1615s)

```
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x1f36ec8  →  Panic: 0x1f36f16
  Elapsed: 1615.504s
  Opcode: CBRANCH
  Detection method: Exploring the current path with a symbolic check on the pointer

The program can panic if its inputs are the following:
  - The input 'err' must be 0
  - The pointer 't.callstack.len' must be NULL (nil)
```

This finding is a **different bug** from Finding 2, even though both originate from the same source line:

```go
t.callstack[0].GasUsed = receipt.GasUsed
```

This single line has two independent failure modes:
| Finding | Failure mode | Panic type |
|---------|-------------|-----------|
| 2 | `receipt = nil` | nil pointer dereference reading `receipt.GasUsed` |
| 3 | `len(t.callstack) = 0` | index out of range accessing `t.callstack[0]` |

Go's compiler emits a **bounds check** before the slice access: a `CBRANCH` at `0x1f36ec8` that checks `len(t.callstack) >= 1`. If the check fails (len = 0), execution jumps to the runtime panic at `0x1f36f16`. Zorya detected that this conditional branch leads to a panic.

**Why Zorya says "NULL (nil)" for `t.callstack.len`**: `t.callstack.len` is an **integer**, not a pointer. Zorya uses the "NULL" label generically for any symbolic variable whose Z3 value is `0x0`, whether it is a pointer or a length field. In this context, `t_callstack_len!143 = 0x0` simply means the slice has zero elements.

**Why `receipt_ptr = 0x0` in this finding too**: on this particular path both `receipt` and `callstack` are empty/nil, but the **bounds-check panic fires first** (Go evaluates the slice index before dereferencing `receipt`), so Zorya reports the index-out-of-range at `0x1f36f16`, not the nil dereference.

The Z3 model confirms:
- `t_callstack_len!143 = 0x0` — empty slice → `t.callstack[0]` is out of bounds
- `err_RCX!168 = 0x0` — no error → guard at `if err != nil` does not return
- `t_ptr!141 = 0xffffffffffffffff` — `t` is a valid non-nil pointer
- `receipt_ptr!152 = 0x0` — receipt is also nil (but the callstack panic fires first)

---

### Symbolic Variable Trace

The link from symbolic initialization (`execution_log.txt`) to the satisfying model (`FOUND_SAT_STATE.txt`, finding 2):

| execution_log.txt | Symbolic var | FOUND_SAT_STATE (finding 2) | Meaning |
|---|---|---|---|
| Line 107-118: `t` → RAX | `t_ptr!141` | `0x8000402000000001` | t is valid (non-nil) |
| Line 119-126: `t.callstack` (slice) | `t_callstack_ptr!142`, `len!143`, `cap!144` | all `0x0` | slice fields zero |
| Line 127-129: `t.config` | `t_config!145` | `0xffff7ffffbfffffe` | some config value |
| Line 143-154: `receipt` → RBX | `receipt_ptr!152` | `0x0` ← **nil** | receipt is nil → bug! |
| Line 219-221: `err` → RCX | `err_RCX!168` | `0x0` | no error → guard skipped |

---

## Comparison with Other Go Analysis Tools

### Running Other Tools

From the go-ethereum repository root (at the vulnerable commit `30824fa`'s parent):

#### 1. go vet (Standard Go Static Analyzer)

```bash
cd eth/tracers/native
go vet ./...
```

**Output**:
```
(clean exit - no output)
```

**Result**: **No issues detected**. `go vet` performs only shallow intra-procedural checks and has no nil flow analysis across call boundaries. It cannot see that a caller may pass a nil `receipt`.

#### 2. staticcheck (Enhanced Static Analysis)

```bash
# Install
go install honnef.co/go/tools/cmd/staticcheck@latest
export PATH=$PATH:$(go env GOPATH)/bin

staticcheck ./...
```

**Output**:
```
(clean exit - no output)
```

**Result**: **No issues detected**. `staticcheck` finds dead code, redundant checks, and many other patterns, but does not perform deep inter-procedural nil pointer tracking.

#### 3. gosec (Security-focused Static Analyzer)

```bash
gosec ./eth/tracers/...
```

**Output** (abbreviated — 66 issues total, all unrelated to the nil bug):
```
[gosec] 2026/02/18 13:18:04 Including rules: default
...
Results:

[/home/kgorna/go-ethereum/eth/tracers/native/prestate.go:136] - G115 (CWE-190): integer overflow conversion uint64 -> int64 (Confidence: MEDIUM, Severity: HIGH)
[/home/kgorna/go-ethereum/eth/tracers/api.go:866]             - G115 (CWE-190): integer overflow conversion uint64 -> int64 (Confidence: MEDIUM, Severity: HIGH)
[/home/kgorna/go-ethereum/eth/tracers/api.go:729]             - G115 (CWE-190): integer overflow conversion uint64 -> int64 (Confidence: MEDIUM, Severity: HIGH)
[/home/kgorna/go-ethereum/eth/tracers/api.go:583]             - G115 (CWE-190): integer overflow conversion uint64 -> int64 (Confidence: MEDIUM, Severity: HIGH)
[/home/kgorna/go-ethereum/eth/tracers/tracker.go:58]          - G115 (CWE-190): integer overflow conversion uint64 -> int (Confidence: MEDIUM, Severity: HIGH)
[/home/kgorna/go-ethereum/eth/tracers/api.go:470]             - G304 (CWE-22): Potential file inclusion via variable (Confidence: HIGH, Severity: MEDIUM)
[/home/kgorna/go-ethereum/eth/tracers/logger/logger_json.go:172] - G104 (CWE-703): Errors unhandled (Confidence: HIGH, Severity: LOW)
[/home/kgorna/go-ethereum/eth/tracers/js/goja.go:1029]        - G104 (CWE-703): Errors unhandled (Confidence: HIGH, Severity: LOW)
... (58 more issues of the same types)

Summary:
  Gosec  : dev
  Files  : 28
  Lines  : 5778
  Nosec  : 0
  Issues : 66
```

**Result**: **Did NOT detect the nil pointer bug**. Found 66 issues across 28 files, all in three categories:
- **G115** (CWE-190): integer overflow conversions (`uint64 → int64`, `uint64 → int`, `int → uint64`) — 15 instances in `api.go`, `tracker.go`, `prestate.go`, `call_flat.go`
- **G304** (CWE-22): potential file inclusion via variable — 1 instance in `api.go:470` (`TraceBlockFromFile`)
- **G104** (CWE-703): unhandled errors — 50 instances, mostly in `eth/tracers/js/goja.go` (`vm.Set(...)` calls) and `logger/logger_json.go` (`encoder.Encode(...)`)

None of these are the nil pointer dereference in `call.go`.

#### 4. govulncheck (Known Vulnerability Database)

```bash
cd ../..
govulncheck -mode binary ./build/bin/geth
```

**Output** (abbreviated):
```
=== Symbol Results ===

Vulnerability #1: GO-2026-4341  Memory exhaustion in query parameter parsing in net/url
Vulnerability #2: GO-2026-4340  Handshake messages at incorrect encryption level in crypto/tls
Vulnerability #3: GO-2026-4337  Unexpected session resumption in crypto/tls
Vulnerability #4: GO-2026-4315  DoS via malicious p2p message in github.com/ethereum/go-ethereum
Vulnerability #5: GO-2026-4314  High CPU usage via malicious p2p message in github.com/ethereum/go-ethereum
Vulnerability #6: GO-2025-4175  Improper application of excluded DNS name constraints in crypto/x509
Vulnerability #7: GO-2025-4155  Excessive resource consumption when printing error string in crypto/x509
Vulnerability #8: GO-2025-4087  Unchecked memory allocation in github.com/consensys/gnark-crypto
Vulnerability #9: GO-2025-4015  Excessive CPU consumption in net/textproto
Vulnerability #10: GO-2025-4013 Panic when validating DSA certificates in crypto/x509
Vulnerability #11: GO-2025-4012 Memory exhaustion when parsing cookies in net/http
Vulnerability #12: GO-2025-4011 Memory exhaustion when parsing DER in encoding/asn1
Vulnerability #13: GO-2025-4010 Insufficient validation of IPv6 hostnames in net/url
Vulnerability #14: GO-2025-4009 Quadratic complexity in encoding/pem
Vulnerability #15: GO-2025-4008 ALPN negotiation error in crypto/tls
Vulnerability #16: GO-2025-4007 Quadratic complexity when checking name constraints in crypto/x509
Vulnerability #17: GO-2025-3751 Sensitive headers not cleared on redirect in net/http
Vulnerability #18: GO-2025-3749 ExtKeyUsageAny disables policy validation in crypto/x509
Vulnerability #19: GO-2025-3563 Request smuggling in net/http
Vulnerability #20: GO-2025-3553 Excessive memory allocation in github.com/golang-jwt/jwt
Vulnerability #21: GO-2025-3436 Go Ethereum DoS via malicious p2p message
Vulnerability #22: GO-2024-3250 Improper error handling in github.com/golang-jwt/jwt
...

Your code is affected by 22 vulnerabilities from 3 modules and the Go standard library.
This scan also found 3 vulnerabilities in packages you import and 13
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

**Result**: **Did NOT detect this bug**. Found 22 known CVEs in Go stdlib, geth, and dependencies. This nil pointer dereference was never assigned a CVE — it is a logic error in the tracer hook, not a known security advisory. The two geth-specific entries (GO-2026-4315, GO-2026-4314, GO-2025-3436) concern malicious P2P messages, unrelated to `OnTxEnd`.

#### 5. nilaway (Nil Pointer Static Analyzer)

```bash
cd eth/tracers/native
nilaway ./...
```

**Output**:
```
/home/kgorna/go-ethereum/eth/tracers/native/call.go:176:37: error: Potential nil panic detected. Observed nil flow from source to dereference point:
  - eth/tracers/native/call.go:176:37: parameter `receipt` of `OnTxEnd` accessed field `GasUsed` without nil check
    (nil value may be passed by callers that follow the hook contract where receipt can be nil)
```

**Result**: **Bug detected** — `nilaway` flags the unconditional `receipt.GasUsed` dereference on the line before the `if receipt != nil` guard. The pattern is straightforward: a pointer parameter is dereferenced without a prior nil check. `nilaway` identifies exactly the vulnerable line.

#### 6. go test -fuzz (Fuzzing)

Save the following as `eth/tracers/native/call_tracer_fuzz_test.go`:

```go
//go:build go1.18
package native

import (
    "testing"

    "github.com/ethereum/go-ethereum/core/types"
)

func FuzzOnTxEnd(f *testing.F) {
    f.Fuzz(func(t *testing.T, nilReceipt bool) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("PANIC DETECTED: %v", r)
            }
        }()

        tracer := &callTracer{
            callstack: make([]callFrame, 1),
        }

        var receipt *types.Receipt
        if !nilReceipt {
            receipt = &types.Receipt{GasUsed: 21000}
        }
        // nil receipt + nil error = the bug
        tracer.OnTxEnd(receipt, nil)
    })
}
```

```bash
go test -fuzz=FuzzOnTxEnd -fuzztime=30s ./eth/tracers/native/
```

**Output**:
```
warning: starting with empty corpus
fuzz: elapsed: 0s, execs: 0 (0/sec), new interesting: 0 (total: 0)
fuzz: elapsed: 0s, execs: 1 (18/sec), new interesting: 0 (total: 0)
--- FAIL: FuzzOnTxEnd (0.06s)
    --- FAIL: FuzzOnTxEnd (0.00s)
        call_tracer_fuzz_test.go:14: PANIC DETECTED: runtime error: invalid memory address or nil pointer dereference

Failing input written to testdata/fuzz/FuzzOnTxEnd/c65b91a05f9ec86e
To re-run:
go test -run=FuzzOnTxEnd/c65b91a05f9ec86e
FAIL
exit status 1
FAIL	github.com/ethereum/go-ethereum/eth/tracers/native	0.067s
```

Failing corpus entry (`eth/tracers/native/testdata/fuzz/FuzzOnTxEnd/c65b91a05f9ec86e`):
```
go test fuzz v1
bool(true)
```

**Result**: **Bug detected in 1 execution** (`nilReceipt=true`, elapsed 0.06s). The fuzzer started with an empty corpus (no seeds) and still found the bug on its very first generated input. `OnTxEnd` is a pure function — no mock backend, no goroutines, no HTTP server — so the bug triggers immediately whenever `nilReceipt=true` and `err=nil`.

### Summary

| Tool | Detected | Notes |
|------|----------|-------|
| go vet | No | No inter-procedural nil analysis |
| staticcheck | No | No inter-procedural nil analysis |
| gosec | No | Found 66 unrelated issues (G115 integer overflows, G104 unhandled errors, G304 file inclusion) |
| govulncheck | No | 22 known CVEs found, none is this nil dereference |
| nilaway | **Yes** | Flags unconditional `receipt.GasUsed` before nil guard |
| go test -fuzz | **Yes** | Detected on first seed — `nilReceipt=true` |
| GoLibAFL | **Yes** | 125 crash objectives in 3m 46s at ~83k exec/s (24 clients); nil dereference at `call.go:176` confirmed via replay |
| **Zorya** | **Yes** | 3 findings: nil receiver (1049s), nil receipt — the bug (1277s), empty callstack (1615s) |

---

## GoLibAFL Fuzzing

`OnTxEnd` is a pure function with no goroutines or network I/O, so it is an ideal GoLibAFL target. The bug fires the moment the harness passes `receipt = nil` with `err = nil`, producing a SIGSEGV that LibAFL records as a crash.

### Harness

```go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "github.com/ethereum/go-ethereum/core/types"
    native "github.com/ethereum/go-ethereum/eth/tracers/native"
)

// harness is called by LibAFL for every generated input.
// data[0] bit-0: 0 → non-nil receipt, 1 → nil receipt (triggers the bug)
func harness(data []byte) {
    if len(data) == 0 {
        return
    }
    tracer := &native.CallTracer{}
    tracer.InitCallstack() // make([]callFrame, 1)

    var receipt *types.Receipt
    if data[0]&1 == 0 {
        receipt = &types.Receipt{GasUsed: 21000}
    }
    // nil receipt + nil error → panic: nil pointer dereference
    tracer.OnTxEnd(receipt, nil)
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

### Export shim

`callTracer` and its fields are unexported. Add a thin shim file to the go-ethereum checkout so the GoLibAFL harness can call `OnTxEnd` from outside the package:

```go
// eth/tracers/native/fuzz_export.go  (add to the vulnerable go-ethereum checkout)
package native

import "github.com/ethereum/go-ethereum/core/types"

// OnTxEndFuzz is an exported wrapper around callTracer.OnTxEnd for GoLibAFL.
// nilReceipt=true passes a nil receipt, which triggers the nil dereference bug.
func OnTxEndFuzz(nilReceipt bool) {
	t := &callTracer{
		callstack: make([]callFrame, 1),
	}
	var receipt *types.Receipt
	if !nilReceipt {
		receipt = &types.Receipt{GasUsed: 21000}
	}
	// nil receipt + nil error → panic: nil pointer dereference at receipt.GasUsed
	t.OnTxEnd(receipt, nil)
}
```

### Harness

With the shim in place the harness becomes trivial — `data[0]&1 == 1` routes to the buggy path:

```go
// harnesses/geth-tracers/main.go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    native "github.com/ethereum/go-ethereum/eth/tracers/native"
)

// harness is called by LibAFL for every generated input.
// data[0] bit-0: 1 → nil receipt (triggers the bug); 0 → valid receipt
func harness(data []byte) {
    if len(data) == 0 {
        return
    }
    native.OnTxEndFuzz(data[0]&1 == 1)
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

### Build and run

```bash
# 0. Add the export shim to the vulnerable go-ethereum checkout (if not already there)
cp fuzz_export.go /home/kgorna/go-ethereum/eth/tracers/native/

# 1. Create the harness directory inside the existing GoLibAFL checkout
mkdir -p /home/kgorna/golibafl/harnesses/geth-tracers
# paste main.go above into /home/kgorna/golibafl/harnesses/geth-tracers/main.go

export GO111MODULE=on
cd /home/kgorna/golibafl/harnesses/geth-tracers
go mod init fuzz
go mod edit -replace github.com/ethereum/go-ethereum=/home/kgorna/go-ethereum
go mod tidy
cd /home/kgorna/golibafl

# 2. Build and fuzz (5-minute budget)
export HARNESS=harnesses/geth-tracers
cargo run --release -- fuzz

# 3. Replay a crash to confirm the nil dereference
cargo run -- run -i output/crashes/<crashfile>
```

**Result**: **Bug detected** — 24 LibAFL clients running at ~83k exec/s collectively found
125 crash objectives in 3 minutes 46 seconds (~18.8M total executions). The fuzzer converged
immediately: corpus stayed at 24 entries (the input space is essentially one bit — nil vs
non-nil receipt), all 10 covered edges were stable from the start
(`edges_stability: 10/10 (100%)`), and objectives accumulated rapidly as every client
independently hit the nil dereference path.

Replaying a crash file confirms the nil dereference at `call.go:176`:

```
$ cargo run -- run -i output/crashes/<crashfile>
Running: output/crashes/<crashfile>
Go panic: runtime error: invalid memory address or nil pointer dereference
goroutine 17 [running, locked to thread]:
runtime/debug.Stack()
        /usr/local/go/src/runtime/debug/stack.go:26 +0x9b
runtime/debug.PrintStack()
        /usr/local/go/src/runtime/debug/stack.go:18 +0x2f
main.catchPanics()
        /home/kgorna/golibafl/harnesses/geth-tracers/harness_fuzz.go:28 +0xa5
panic({0x...?, 0x...?})
        /usr/local/go/src/runtime/panic.go:787 +0x132
github.com/ethereum/go-ethereum/eth/tracers/native.(*callTracer).OnTxEnd(...)
        /home/kgorna/go-ethereum/eth/tracers/native/call.go:176 +0x35
github.com/ethereum/go-ethereum/eth/tracers/native.OnTxEndFuzz(...)
        /home/kgorna/go-ethereum/eth/tracers/native/fuzz_export.go:15 +0x72
main.harness({0xc000..., 0x1, ...})
        /home/kgorna/golibafl/harnesses/geth-tracers/main.go:14 +0x3b
Aborted (core dumped)
```

The panic originates at `call.go:176` — the unconditional `receipt.GasUsed` dereference —
confirming the root cause. The stack trace is identical to what `go test -fuzz` reports.

### Comparison with `go test -fuzz`

| Aspect | `go test -fuzz` | GoLibAFL |
|--------|-----------------|---------|
| Instrumentation | Go native sancov | Go native sancov (same) |
| Signal | `recover()` → `t.Fatalf` | SIGSEGV → crash file |
| Detection speed | 1 execution (0.06 s) | < 1 s (first objective in first seconds) |
| Throughput | single-threaded | ~83k exec/s across 24 parallel clients |
| Total crashes found | 1 corpus entry | 125 crash objectives |
| Setup complexity | Trivial | Requires Rust + Cargo; export shim needed for unexported types |
| Oracle needed | No — explicit panic | No — crash-based |

**Conclusion**: Both tools find this bug immediately. GoLibAFL provides no advantage here — the crash is trivially reachable and the input space is essentially one bit (`nilReceipt`). The 125 objectives are all the same nil dereference hit by 24 clients in parallel. The difference between tools would matter in cases requiring deep path exploration or implicit bug classes (silent overflows).

See also:
- [`binsec-findings/README-binsec.md`](./binsec-findings/README-binsec.md) — binary-level symbolic execution (**partially detected**: Finding 3 / `runtime.panicIndex`)
- [`symqemu-findings/README-symqemu.md`](./symqemu-findings/README-symqemu.md) — concolic execution (not detected)

## Bug Classification

**Type:** Nil Pointer Dereference

- `OnTxEnd` is a hook called by the tracing framework; callers may legitimately pass `nil` receipt
- The nil check existed in the code but was placed **after** the dereference — dead code
- The unconditional `receipt.GasUsed` access on the line before the guard is the root cause
- Fixed by returning early when receipt is nil, before any dereference

## References

- **Fix commit**: [30824fa](https://github.com/ethereum/go-ethereum/commit/30824fa)
- **Pull Request**: [#30332](https://github.com/ethereum/go-ethereum/pull/30332)
- **File**: `eth/tracers/native/call.go`
- **Function**: `(*callTracer).OnTxEnd`
- **Analyzed function address**: `0x1f36e80` (`github.com/ethereum/go-ethereum/eth/tracers/native.(*callTracer).OnTxEnd`)
- **Panic address (finding 2)**: `0x1f36eb5`

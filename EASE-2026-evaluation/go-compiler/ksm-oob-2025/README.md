# kube-state-metrics Custom Resource State Off-by-One Panic

This case demonstrates an off-by-one index out-of-range vulnerability in kube-state-metrics' `compilePath` function, fixed in commit [dc54dc6](https://github.com/kubernetes/kube-state-metrics/commit/dc54dc6580b06fe82203d75e32d68901e8df8287). The bug occurs when a KSM custom resource metric config references a list index equal to the length of the list: the bounds check uses `>` instead of `>=`, allowing `s[i]` to be executed when `i == len(s)`, causing a panic. Zorya was run on the binary but was **unable to confirm** the off-by-one due to an OOM kill mid-analysis; fuzzing (`go test -fuzz`) found the bug in 19 executions.

## Vulnerability

Looking at the vulnerable code in `pkg/customresourcestate/registry_factory.go`:

```go
func compilePath(path []string) (out valuePath, _ error) {
    for i := range path {
        // ...
        out = append(out, pathOp{
            part: part,
            op: func(m interface{}) interface{} {
                // ...
                } else if s, ok := m.([]interface{}); ok {
                    i, err := strconv.Atoi(part)
                    if err != nil {
                        return nil
                    }
                    if i < 0 {
                        // negative index
                        i += len(s)
                    }
                    if i < 0 || i > len(s) {   // <-- BUG: should be >= len(s)
                        return fmt.Errorf("list index out of range: %s", part)
                    }
                    return s[i]                 // <-- PANIC when i == len(s)
                }
                return nil
            },
        })
    }
    return out, nil
}
```

**The bug**: The guard `i > len(s)` fails to catch the case `i == len(s)`. A valid slice of length N has indices `0..N-1`; index `N` is out of range. When the config references index `N` (e.g., `path: [spec, items, 2, value]` on a 2-element list), the check passes (`2 > 2` is false) and `s[2]` panics with "index out of range".

**The fix** ([commit dc54dc6](https://github.com/kubernetes/kube-state-metrics/commit/dc54dc6580b06fe82203d75e32d68901e8df8287)) changes the comparison to `>=`:
```go
-   if i < 0 || i > len(s) {
+   if i < 0 || i >= len(s) {
        return fmt.Errorf("list index out of range: %s", part)
    }
```

## How It Happens

1. A KSM custom resource metric config specifies a path that indexes into a list field, e.g. `path: [spec, items, 2, value]`
2. At runtime, a Custom Resource object has only 2 elements in `spec.items` (indices 0 and 1)
3. `compilePath` builds a closure that evaluates `path[2]` on the list
4. The closure is invoked: `i = 2`, `len(s) = 2`
5. The check `i > len(s)` evaluates to `2 > 2` → **false** → guard does not fire
6. `s[2]` is executed → **panic: index out of range [2] with length 2**

Note: This is an **off-by-one** bug, not a nil pointer dereference. The panic type is `runtime.panicIndex`, not `runtime.panicmem`.

## Reproduction Workflow

### 1. Build vulnerable kube-state-metrics binary

```bash
# Clone kube-state-metrics repository
git clone https://github.com/kubernetes/kube-state-metrics.git
cd kube-state-metrics

# Checkout the vulnerable commit (parent of the fix)
git checkout 61be81f

# Build with debug symbols
go build -gcflags="all=-N -l" -ldflags="" -o kube-state-metrics .

# Find the function address of the inner closure
nm kube-state-metrics | grep "compilePath"
# Look for: k8s.io/kube-state-metrics/v2/pkg/customresourcestate.compilePath.func2
# Example: 0000000002b04e00 g F .text ... compilePath.func2
```

### 2. Set up Kubernetes cluster with the trigger resource

```bash
# Create a local kind cluster
kind create cluster --name ksm-test

# Apply the CRD and CR (see crd.yaml and cr-instance.yaml)
kubectl apply -f crd.yaml
kubectl wait --for=condition=Established crd/testresources.example.com --timeout=30s
kubectl apply -f cr-instance.yaml
```

The CR (`cr-instance.yaml`) has **2 elements** in `spec.items` (indices 0 and 1). The KSM config (`ksm-config.yaml`) requests index `1` — valid — so the concrete execution path does not panic. Zorya would then explore what happens if the slice had fewer elements (e.g., length 1, where index 1 == len(s)). However, in practice the analysis was killed (OOM) before this path was confirmed.

### 3. Run Zorya analysis

Zorya was run targeting `valuePath.Get` (`0x2b04240`) — the outer function that invokes the compiled path closures — which then calls `compilePath.func2` (`0x2b04e00`) at runtime:

```bash
zorya /home/kgorna/go-projects/kube-state-metrics/kube-state-metrics \
  --mode function 0x2b04240 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --arg "--kubeconfig=/root/.kube/config --custom-resource-state-config-file=/home/kgorna/go-projects/kube-state-metrics/ksm-config.yaml --custom-resource-state-only" \
  --negate-path-exploration
```

Zorya symbolized two arguments of `valuePath.Get`:
- `p` (the valuePath slice header): `RAX=0xc0008984e0`, `RBX=0x2` (len), `RCX=0x2` (cap)
- `obj` (the interface{} to evaluate against): `RDI=0x2f11060`, `RSI=0xc000899350`

### 4. Zorya Detection Results

**Vulnerability Detected**: **NO** — the specific off-by-one index bug (`i == len(s)` → `runtime.panicIndex`) was **not confirmed**. The Zorya process was killed (OOM) before completing the analysis.

#### What Zorya found (from `execution_trace.txt`)

Two findings were reported before the process was terminated:

**Finding 1** — NULL pointer dereference in `valuePath.Get` (elapsed: 421.642s):
```
VULNERABILITY: Symbolic NULL pointer dereference
  Address: 0x2b042e2
  Elapsed: 421.642s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
```
Zorya detected that the symbolic `p` pointer (the `valuePath` slice) could be nil. If `p` is nil, dereferencing it in `valuePath.Get` panics — but this is a **different bug** from the off-by-one (nil slice header, not an invalid index on a non-nil slice).

**Finding 2** — Satisfiable branch path in `compilePath.func2` (elapsed: 434.053s):
```
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x2b04e71
  Elapsed: 434.053s
  Opcode: CBRANCH
  Detection method: Exploring the not taken path with Overlay Execution
```
Zorya entered `compilePath.func2` and identified a satisfiable conditional branch (`CBRANCH`) at `0x2b04e71` where taking the not-taken path leads to a panic. This is **potentially related** to the `if i < 0 || i > len(s)` check, but the finding is reported as a reachable branch path — not as a confirmed `runtime.panicIndex` triggered by `s[i]` when `i == len(s)`.

#### Why the bug was NOT confirmed

**Process killed (OOM)**: Immediately after entering `strings.Split` (line 427 of `execution_trace.txt`), the Zorya process was killed by the OS:
```
/usr/local/bin/zorya: line 330: 2998605 Killed   RUSTFLAGS="--cap-lints=allow" cargo run --release -- --write-args "$ARGS"
```
No `FOUND_SAT_STATE.txt` was preserved from this run. The analysis was terminated before Zorya could:
- Compute the Z3 model confirming `i == len(s)` for the slice used in `compilePath.func2`
- Confirm a `runtime.panicIndex` at the `s[i]` instruction

**Function mismatch**: Zorya started at `valuePath.Get` (`0x2b04240`) rather than directly at `compilePath.func2` (`0x2b04e00`). The outer function adds extra symbolic state (the slice header pointer `p` could be nil or have arbitrary length), which increases path explosion before even reaching the closure body. Running directly at `compilePath.func2` with concrete `m` arguments but symbolic index would have been more targeted.

**Symbolic scope**: The symbolic variables (`p` and `obj`) were the outer function's arguments. The slice `s` inside `compilePath.func2` is derived from `obj` through a type assertion — Zorya must symbolically execute through the type assertion before it can model `len(s)`, which requires significant exploration depth.

#### Summary

| Aspect | Result |
|--------|--------|
| Function analyzed | `valuePath.Get` (`0x2b04240`), calls `compilePath.func2` at runtime |
| Target bug function | `compilePath.func2` (`0x2b04e00`) |
| Findings before OOM | 2 (nil pointer in valuePath.Get + reachable CBRANCH in compilePath.func2) |
| Off-by-one (`panicIndex`) confirmed | **No** — process killed before confirmation |
| `FOUND_SAT_STATE.txt` available | **No** — OOM killed process mid-analysis |
| Elapsed before kill | ~434s |
| Root cause of failure | OOM kill during `strings.Split` exploration |

---

### Symbolic Variable Trace

From the initialization block at `0x2b04240` (`valuePath.Get`):
```
p   = RAX=0xc0008984e0, RBX=0x2 (len=2), RCX=0x2 (cap=2)  → symbolic
obj = RDI=0x2f11060 (type), RSI=0xc000899350 (data)         → symbolic
```
Zorya symbolized `p` (the path slice) and `obj` (the interface value). The concrete snapshot had `len(p)=2` and a 2-element list, so the concrete execution did not panic. Zorya explored negated paths but was killed before finding `i == len(s)`.

---

## Comparison with Other Go Analysis Tools

From the kube-state-metrics repository root (at the vulnerable commit `61be81f`):

#### 1. go vet (Standard Go Static Analyzer)

```bash
cd pkg/customresourcestate
go vet ./...
```

**Output**:
```
(clean exit - no output)
```

**Result**: **No issues detected**. `go vet` has no bounds analysis for slice accesses inside closures — it cannot trace that `i` may equal `len(s)`.

#### 2. staticcheck (Enhanced Static Analysis)

```bash
# staticcheck must be invoked via its full path if not in PATH:
$(go env GOPATH)/bin/staticcheck ./...
```

**Output**:
```
(clean exit - no output)
```

**Result**: **No issues detected**. `staticcheck` does not perform symbolic reasoning about slice index values.

#### 3. gosec (Security-focused Static Analyzer)

```bash
# Install and add to PATH first:
go install github.com/securego/gosec/v2/cmd/gosec@latest
export PATH=$PATH:$(go env GOPATH)/bin

gosec ./pkg/customresourcestate/...
```

**Output**:
```
[gosec] 2026/02/18 17:17:39 Including rules: default
[gosec] 2026/02/18 17:17:39 Excluding rules: default
[gosec] 2026/02/18 17:17:40 Checking package: customresourcestate
[gosec] 2026/02/18 17:17:40 Checking file: config.go
[gosec] 2026/02/18 17:17:40 Checking file: config_metrics_types.go
[gosec] 2026/02/18 17:17:40 Checking file: custom_resource_metrics.go
[gosec] 2026/02/18 17:17:40 Checking file: doc.go
[gosec] 2026/02/18 17:17:40 Checking file: registry_factory.go
Results:

Summary:
  Gosec  : dev
  Files  : 5
  Lines  : 1205
  Nosec  : 0
  Issues : 0
```

**Result**: **No issues detected** — 0 issues across all 5 files in the package. This is the cleanest gosec result across all bugs studied: the `customresourcestate` package has no integer overflow conversions, no unhandled errors flagged, and no file inclusion patterns. The off-by-one logic error (`>` vs `>=`) is invisible to security-focused static analysis.

#### 4. govulncheck (Known Vulnerability Database)

```bash
govulncheck -mode binary ./kube-state-metrics
```

**Output** (abbreviated):
```
=== Symbol Results ===

Vulnerability #1:  GO-2026-4341  Memory exhaustion in query parameter parsing in net/url
Vulnerability #2:  GO-2026-4340  Handshake messages at incorrect encryption level in crypto/tls
Vulnerability #3:  GO-2026-4337  Unexpected session resumption in crypto/tls
Vulnerability #4:  GO-2025-4175  Excluded DNS name constraints in crypto/x509
Vulnerability #5:  GO-2025-4155  Excessive resource consumption in crypto/x509
Vulnerability #6:  GO-2025-4015  Excessive CPU in net/textproto
Vulnerability #7:  GO-2025-4013  Panic when validating DSA certificates in crypto/x509
Vulnerability #8:  GO-2025-4012  Memory exhaustion parsing cookies in net/http
Vulnerability #9:  GO-2025-4011  Memory exhaustion parsing DER in encoding/asn1
Vulnerability #10: GO-2025-4010  Insufficient validation of IPv6 hostnames in net/url
Vulnerability #11: GO-2025-4009  Quadratic complexity in encoding/pem
Vulnerability #12: GO-2025-4008  ALPN negotiation error in crypto/tls
Vulnerability #13: GO-2025-4007  Quadratic complexity checking name constraints in crypto/x509
Vulnerability #14: GO-2025-4006  Excessive CPU in net/mail
Vulnerability #15: GO-2025-3956  Unexpected paths from LookPath in os/exec
Vulnerability #16: GO-2025-3751  Sensitive headers not cleared on redirect in net/http
Vulnerability #17: GO-2025-3749  ExtKeyUsageAny disables policy validation in crypto/x509
Vulnerability #18: GO-2025-3563  Request smuggling in net/http

Your code is affected by 18 vulnerabilities from the Go standard library.
This scan also found 2 vulnerabilities in packages you import and 9
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

**Result**: **Did NOT detect this bug**. Found 18 known CVEs — all in the Go standard library (TLS, x509, net/http, net/url, encoding). None are in `kube-state-metrics` itself, and this off-by-one was never assigned a CVE.

#### 5. nilaway (Nil Pointer Static Analyzer)

```bash
# From the kube-state-metrics repo root (vulnerable commit 61be81f):
cd /home/kgorna/go-projects/kube-state-metrics
nilaway ./pkg/customresourcestate/...
```

**Output**:
```
(clean exit — no output)
```

**Result**: **No issues detected** — `nilaway` tracks nil pointer flows only. This bug is an off-by-one index error (`i > len(s)` should be `i >= len(s)`), not a nil dereference; it is outside nilaway's scope.

#### 6. go test -fuzz (Fuzzing)

Save the following as `pkg/customresourcestate/path_fuzz_test.go`:

```go
//go:build go1.18
package customresourcestate

import (
    "testing"
)

func FuzzCompilePath(f *testing.F) {
    f.Fuzz(func(t *testing.T, indexStr string, listLen int) {
        if listLen < 0 || listLen > 100 {
            return
        }
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("PANIC DETECTED: %v (indexStr=%q, listLen=%d)", r, indexStr, listLen)
            }
        }()

        // Build a compilePath closure for a single index component
        path, err := compilePath([]string{indexStr})
        if err != nil {
            return // invalid path, not a bug
        }

        // Build a slice of listLen elements
        s := make([]interface{}, listLen)
        for i := range s {
            s[i] = map[string]interface{}{"value": "x"}
        }

        // Invoke the closure — may panic if off-by-one
        for _, op := range path {
            op.op(s)
        }
    })
}
```

```bash
go test -fuzz=FuzzCompilePath -fuzztime=30s ./pkg/customresourcestate/
```

**Output**:
```
warning: starting with empty corpus
fuzz: elapsed: 0s, execs: 0 (0/sec), new interesting: 0 (total: 0)
fuzz: elapsed: 0s, execs: 19 (44/sec), new interesting: 0 (total: 0)
--- FAIL: FuzzCompilePath (0.43s)
    --- FAIL: FuzzCompilePath (0.00s)
        path_fuzz_test.go:15: PANIC DETECTED: runtime error: index out of range [0] with length 0
            (indexStr="0", listLen=0)

Failing input written to testdata/fuzz/FuzzCompilePath/c67a4c431a76e31d
To re-run:
go test -run=FuzzCompilePath/c67a4c431a76e31d
FAIL
exit status 1
FAIL	k8s.io/kube-state-metrics/v2/pkg/customresourcestate	0.446s
```

Failing corpus entry (`pkg/customresourcestate/testdata/fuzz/FuzzCompilePath/c67a4c431a76e31d`):
```
go test fuzz v1
string("0")
int(0)
```

**Result**: **Bug detected in 19 executions** (0.43s). Starting from an empty corpus, the fuzzer generated `indexStr="0"`, `listLen=0` — an empty slice with index 0. This is the most extreme case of the off-by-one: `i = 0`, `len(s) = 0`, guard `0 > 0` is false, `s[0]` panics.

Note the panic is `index out of range [0] with length 0`, not `[2] with length 2` — the fuzzer found the simplest possible trigger: an empty list rather than the exact-boundary case (`len=N, index=N`). Both are the same bug: `i == len(s)` bypasses the guard. The fixed code `i >= len(s)` catches both: `0 >= 0` → true → returns error.

### Summary

| Tool | Detected | Notes |
|------|----------|-------|
| go vet | No | No slice bounds analysis |
| staticcheck | No | No symbolic index reasoning |
| gosec | No | 0 issues — package is clean; off-by-one is invisible to security patterns |
| govulncheck | No | 18 stdlib CVEs found, none for this bug (no CVE assigned) |
| nilaway | No | Nil pointer tool — wrong bug class |
| go test -fuzz | **Yes** | Detected in 19 execs (0.43s) — `("0", 0)` triggers `[0] with length 0` |
| GoLibAFL | **Yes** | 3,729 crash objectives (611 unique files) in 2m 45s at ~263k exec/s (24 clients); crash at `registry_factory.go:658` confirmed via replay |
| **Zorya** | **No** | 2 partial findings before OOM kill; off-by-one (`panicIndex`) not confirmed |

---

## GoLibAFL Fuzzing

The off-by-one produces a Go runtime `index out of range` panic — a hard crash signal (SIGSEGV). GoLibAFL catches this via its crash detector without any domain oracle, just like `go test -fuzz` catches it via `recover()`.

### Export shim

`compilePath` and the `pathOp` closure are unexported. Add a thin shim file so the
GoLibAFL harness can call them from outside the package:

```go
// pkg/customresourcestate/fuzz_export.go  (add to the vulnerable KSM checkout)
package customresourcestate

// FuzzCompilePath is an exported wrapper around compilePath for use with GoLibAFL.
// It builds a path from a single index component, creates a slice of listLen elements,
// evaluates each path operation, and returns without error — panicking on off-by-one.
func FuzzCompilePath(indexStr string, listLen int) {
    if listLen < 0 || listLen > 100 {
        return
    }
    path, err := compilePath([]string{indexStr})
    if err != nil {
        return // invalid path component, not a bug
    }
    s := make([]interface{}, listLen)
    for i := range s {
        s[i] = map[string]interface{}{"value": "x"}
    }
    // Invoke each compiled closure — panics when i == len(s) (off-by-one)
    for _, op := range path {
        op.op(s) //nolint:all
    }
}
```

### Harness

```go
// harnesses/ksm-oob/main.go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "strconv"

    "k8s.io/kube-state-metrics/v2/pkg/customresourcestate"
)

// harness is called by LibAFL for every generated input.
// Encoding: data[0] = listLen (0–100); data[1:] = indexStr bytes.
func harness(data []byte) {
    if len(data) < 2 {
        return
    }
    listLen := int(data[0])
    indexStr := string(data[1:])
    // Only pass strings that look like integers — avoid wasting cycles on non-index paths
    if _, err := strconv.Atoi(indexStr); err != nil {
        return
    }
    // FuzzCompilePath is the exported shim in fuzz_export.go
    customresourcestate.FuzzCompilePath(indexStr, listLen)
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

### Build and run (5-minute budget)

```bash
# 0. Add the export shim to the vulnerable KSM checkout (if not already there)
cp fuzz_export.go /home/kgorna/go-projects/kube-state-metrics/pkg/customresourcestate/

# 1. Clone GoLibAFL
git clone https://github.com/srlabs/golibafl
cd golibafl

# 2. Create harness directory and paste main.go
mkdir -p harnesses/ksm-oob
# paste main.go above into harnesses/ksm-oob/main.go

# IMPORTANT: if pkg/customresourcestate/ contains its own go.mod from a prior
# 'go test -fuzz' run, remove it first — otherwise 'go mod tidy' will report
# "does not contain package" because Go treats the subdirectory as a separate module.
rm -f /home/kgorna/go-projects/kube-state-metrics/pkg/customresourcestate/go.mod
rm -f /home/kgorna/go-projects/kube-state-metrics/pkg/customresourcestate/go.sum

export GO111MODULE=on
cd harnesses/ksm-oob
go mod init fuzz
go mod edit -replace k8s.io/kube-state-metrics/v2=/home/kgorna/go-projects/kube-state-metrics
go mod tidy
cd ../..

# 3. Build and fuzz (5 minutes)
export HARNESS=harnesses/ksm-oob
cargo run --release -- fuzz --timeout 300

# 4. Replay a crash
cargo run -- run -i output/crashes/<crashfile>
```

**Result**: **Bug detected** — 24 LibAFL clients running at ~263k exec/s collectively found
3,729 crash objectives (611 unique crash files saved) within the first 2 minutes 45 seconds
of fuzzing. The fuzzer immediately converged on the `i == len(s)` boundary condition,
generating inputs such as `listLen=0, indexStr="0"` (the simplest trigger) as well as
every variant `("N", N)` for N = 0..98, all of which bypass the `i > len(s)` guard and
panic in `compilePath.func2`.

Replaying the minimised crash file `30eafe4efb62d719` (bytes `\x00 0`, i.e. `listLen=0,
indexStr="0"`):

```
$ cargo run -- run -i output/crashes/30eafe4efb62d719
Running: output/crashes/30eafe4efb62d719
Go panic: runtime error: index out of range [0] with length 0
goroutine 17 [running, locked to thread]:
runtime/debug.Stack()
        /usr/local/go/src/runtime/debug/stack.go:26 +0x9b
runtime/debug.PrintStack()
        /usr/local/go/src/runtime/debug/stack.go:18 +0x2f
main.catchPanics()
        /home/kgorna/golibafl/harnesses/ksm-oob/harness_fuzz.go:28 +0xa5
panic({0x6454b1c5c4a0?, 0xc000a8a690?})
        /usr/local/go/src/runtime/panic.go:787 +0x132
k8s.io/kube-state-metrics/v2/pkg/customresourcestate.compilePath.func2(...)
        /home/kgorna/go-projects/kube-state-metrics/pkg/customresourcestate/registry_factory.go:658 +0x52a
k8s.io/kube-state-metrics/v2/pkg/customresourcestate.FuzzCompilePath({0x6454af403d60, 0x1}, 0x0)
        /home/kgorna/go-projects/kube-state-metrics/pkg/customresourcestate/fuzz_export.go:21 +0x2b9
main.harness({0xc000aa20b2, 0x2, 0x0?})
        /home/kgorna/golibafl/harnesses/ksm-oob/main.go:25 +0x11e
Aborted (core dumped)
```

The panic originates at `registry_factory.go:658` — the `s[i]` statement inside
`compilePath.func2` — confirming the off-by-one. The stack trace is identical to what
`go test -fuzz` reports.

**Note on false-positive objectives**: of the 611 saved crash files, a subset have inputs
that are filtered by the harness guards (`listLen > 100`, or `indexStr` not a valid
integer). These are collected by LibAFL because the fuzzer operates at the signal level
(SIGSIGV / abort) and cannot see the early-return guards. Only inputs satisfying both
`listLen ≤ 100` and `strconv.Atoi(indexStr) == nil` actually reach `compilePath.func2`.

### Comparison with `go test -fuzz`

| Aspect | `go test -fuzz` | GoLibAFL |
|--------|-----------------|---------|
| Instrumentation | Go native sancov | Go native sancov (same) |
| Signal | `recover()` → `t.Fatalf` | abort / SIGSEGV → crash file |
| Detection speed | 19 execs (0.43 s) | < 1 s (first objective within seconds) |
| Throughput | ~single-threaded | ~263k exec/s across 24 parallel clients |
| Total crashes found | 1 corpus entry | 611 unique crash files (3,729 objectives) |
| Setup complexity | Trivial | Requires Rust + Cargo; nested `go.mod` in package must be removed first |
| Oracle needed | No — explicit panic | No — crash-based |
| False positives | None (harness guards enforced by `recover`) | Some (LibAFL saves inputs filtered by harness guards before reaching the bug) |

**Conclusion**: GoLibAFL and `go test -fuzz` are equivalent for detecting this bug class — both find it within the first few iterations. GoLibAFL's higher throughput (263k exec/s vs single-threaded) and parallel clients produce many more crash variants (`("N", N)` for all N in 0..98), but give no additional diagnostic value here since the bug is the same in every case. GoLibAFL's advantage (comparison-tracing mutations, custom schedulers) would matter for subtler bugs that require specific byte-level values to reach; here any `i == len(s)` pairing triggers the crash immediately.

See also:
- [`binsec-findings/README-binsec.md`](./binsec-findings/README-binsec.md) — binary-level symbolic execution
- [`symqemu-findings/README-symqemu.md`](./symqemu-findings/README-symqemu.md) — concolic execution

## Bug Classification

**Type:** Off-by-One Index Out of Range (not a nil pointer dereference)

- The bounds check `i > len(s)` should be `i >= len(s)` — valid indices are `0..len(s)-1`
- When `i == len(s)`, the error return is skipped and `s[i]` panics
- Triggered by a KSM metric config that specifies an index exactly equal to the list length
- Fixed by a one-character change (`>` → `>=`)

## References

- **Fix commit**: [dc54dc6](https://github.com/kubernetes/kube-state-metrics/commit/dc54dc6580b06fe82203d75e32d68901e8df8287)
- **Pull Request**: [#2716](https://github.com/kubernetes/kube-state-metrics/pull/2716)
- **Fixed in**: v2.17.0, v2.18.0
- **File**: `pkg/customresourcestate/registry_factory.go`
- **Function**: `compilePath` (inner closure `compilePath.func2`)
- **Zorya entry function**: `0x2b04240` (`valuePath.Get`); target closure `0x2b04e00` (`compilePath.func2`)

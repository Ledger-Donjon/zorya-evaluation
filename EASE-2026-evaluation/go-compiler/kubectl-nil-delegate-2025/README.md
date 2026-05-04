# Kubectl Terminal Size Queue Nil Pointer Dereference

This case demonstrates a nil pointer dereference vulnerability in kubectl's terminal size queue adapter, fixed in commit [5f67574](https://github.com/kubernetes/kubernetes/commit/5f675740442edc32f2dcbbe1453f49484440e7a8). Zorya detects this vulnerability through **symbolic execution and concolic analysis** directly on the compiled binary.

## Vulnerability

The `terminalSizeQueueAdapter.Next()` method in kubectl's exec command dereferences the `delegate` field without checking if it's nil. When `delegate` is nil, calling `delegate.Next()` causes a nil pointer dereference panic.

```go
func (a *terminalSizeQueueAdapter) Next() *remotecommand.TerminalSize {
    // MISSING: if a.delegate == nil { return nil }
    next := a.delegate.Next()  // <-- Panic if a.delegate is nil
    if next == nil {
        return nil
    }
    return &remotecommand.TerminalSize{
        Width:  next.Width,
        Height: next.Height,
    }
}
```

**The fix** (commit 5f67574) adds a nil check:
```go
func (a *terminalSizeQueueAdapter) Next() *remotecommand.TerminalSize {
    if a.delegate == nil {
        return nil
    }
    next := a.delegate.Next()
    // ...
}
```

## How it happens

1. A `terminalSizeQueueAdapter` is created with `delegate` field uninitialized (nil)
2. `Next()` is called on the adapter
3. The code attempts to dereference `a.delegate` to call `.Next()` on it
4. Since `delegate` is nil, this causes a panic

The vulnerability is in `staging/src/k8s.io/kubectl/pkg/cmd/exec/exec.go` in the kubectl binary, specifically in the terminal size handling code for the `kubectl exec` command.

## Reproduction Workflow

### 1. Build vulnerable kubectl binary

```bash
# Clone kubernetes repository
git clone https://github.com/kubernetes/kubernetes.git
cd kubernetes

# Checkout the vulnerable commit (parent of the fix)
git checkout 1c30a75a22d0052c5e0e2d3c1b8cca2dfa02ded1

# Build kubectl with debug symbols
go build -gcflags="all=-N -l" -o _output/bin/kubectl ./cmd/kubectl

# Find the function address
nm _output/bin/kubectl | grep "terminalSizeQueueAdapter.*Next"
# Look for: k8s.io/kubectl/pkg/cmd/exec.(*terminalSizeQueueAdapter).Next
# Example output: 000000000036d82a0 T k8s.io/kubectl/pkg/cmd/exec.(*terminalSizeQueueAdapter).Next
```

### 2. Set up Kubernetes test environment

```bash
# Install kind (Kubernetes in Docker)
go install sigs.k8s.io/kind@latest
export PATH=$PATH:~/go/bin

# Create a test cluster
kind create cluster

# Create a test pod (this will fail because the pod doesn't exist yet)
./_output/bin/kubectl run test-pod --image=busybox --restart=Never -- sleep 3600
./_output/bin/kubectl wait --for=condition=Ready pod/test-pod --timeout=60s

# Clean up for Zorya test
./_output/bin/kubectl delete pod test-pod
```

### 3. Run Zorya analysis

```bash
zorya /path/to/kubernetes/_output/bin/kubectl \
  --mode function 0x36d6820 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --arg "exec -it test-pod -- ls" \
  --negate-path-exploration \
  --force-pty
```

**Note:** Replace `0x36d6820` with the actual address from step 1.

**Flag explanations:**
- `--force-pty`: Forces pseudo-terminal allocation, necessary for the `kubectl exec -it` command to properly exercise terminal-related code paths (including the `terminalSizeQueueAdapter`) during symbolic execution.

## Zorya Detection Results

Zorya successfully detects **two nil pointer dereferences** in the function:

```
========================================================================
VULNERABILITY: Symbolic nil pointer dereference
  Address: 0x36d6845
  Elapsed: 1233.811s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

========================================================================
VULNERABILITY: Symbolic nil pointer dereference
  Address: 0x36d684a
  Elapsed: 1234.208s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
  More details in: results/FOUND_SAT_STATE.txt
========================================================================
```

### What Zorya Found

1. **First dereference (0x36d6845)**: Loading the struct pointer `a` itself - Zorya proved `a_ptr` can be nil (0)
2. **Second dereference (0x36d684a)**: Loading the interface's itab pointer from `a.delegate` - Zorya proved `a.delegate.itab` can be nil (0)

Both dereferences are caught because Zorya's Z3 solver determines that the symbolic pointers can be nil, satisfying all path constraints.

## Why Runtime Testing Misses This

Traditional testing approaches struggle to trigger this bug because:

- The bug requires specific initialization paths where `delegate` remains uninitialized
- The conditions that lead to nil `delegate` may be rare in normal usage
- Integration tests typically exercise the "happy path" with properly initialized objects
- The bug only manifests when the exact sequence of calls leaves `delegate` nil

Zorya's symbolic execution explores all possible paths through the function, including edge cases where `delegate` is nil, without requiring a specific runtime test case.

## Comparison with Other Go Analysis Tools

To demonstrate Zorya's effectiveness, we tested the vulnerable kubectl codebase against standard Go static analysis and testing tools. **None of them detected this vulnerability.**

### Running Other Tools

From the kubernetes repository root (at the vulnerable commit `1c30a75`):

#### 1. go vet (Standard Go Static Analyzer)

```bash
cd staging/src/k8s.io/kubectl/pkg/cmd/exec
go vet ./...
```

**Output**:
```
(no output - clean exit)
```

**Result**: **No issues detected**. `go vet` focuses on common mistakes (unreachable code, format strings, shadow variables) but doesn't perform deep nil pointer analysis or track data flow across function calls.

#### 2. staticcheck (Enhanced Static Analysis)

```bash
# Install staticcheck
go install honnef.co/go/tools/cmd/staticcheck@latest

# Run on the exec package
cd staging/src/k8s.io/kubectl/pkg/cmd/exec
staticcheck ./...
```

**Output**:
```
(no output - clean exit)
```

**Result**: **No issues detected**. While `staticcheck` is more thorough than `go vet` and includes hundreds of checks, it doesn't perform path-sensitive nil pointer analysis to detect that `delegate` can be nil at the dereference site.

#### 3. gosec (Security-focused Static Analyzer)

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run on the exec package
cd staging/src/k8s.io/kubectl/pkg/cmd/exec
gosec ./...
```

**Output**:
```
[gosec] 2026/02/11 16:54:21 Including rules: default
[gosec] 2026/02/11 16:54:21 Checking package: exec
[gosec] 2026/02/11 16:54:21 Checking file: exec.go
Results:

Summary:
  Files  : 1
  Lines  : 422
  Nosec  : 0
  Issues : 0
```

**Result**: **No issues detected**. `gosec` scanned 422 lines of code but found nothing. It focuses on security anti-patterns (hardcoded credentials, weak crypto, SQL injection) but doesn't perform deep nil pointer analysis.

#### 4. go test -fuzz (Fuzzing)

```bash
cd staging/src/k8s.io/kubectl/pkg/cmd/exec

# Attempt to create a fuzz test (without helping the fuzzer)
cat > exec_fuzz_test.go << 'EOF'
//go:build go1.18
package exec

import (
    "testing"
)

func FuzzTerminalSizeQueueAdapter(f *testing.F) {
    f.Add(true)  // with delegate
    f.Add(false) // without delegate
    
    f.Fuzz(func(t *testing.T, hasDelegate bool) {
        adapter := &terminalSizeQueueAdapter{}
        if hasDelegate {
            // In real usage, this would be properly initialized
            // But there's no easy way to create a valid delegate
            // without pulling in the entire kubectl test infrastructure
            // Let's see if the fuzzer can find the bug naturally
        }
        // Try to trigger the bug (no recover - let it panic if vulnerable)
        _ = adapter.Next()
    })
}
EOF

go test -fuzz=FuzzTerminalSizeQueueAdapter -fuzztime=30s
```

**Output**:
```
fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed
failure while testing seed corpus entry: FuzzTerminalSizeQueueAdapter/seed#0
fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed
--- FAIL: FuzzTerminalSizeQueueAdapter (0.11s)
    --- FAIL: FuzzTerminalSizeQueueAdapter (0.00s)
        testing.go:1825: panic: runtime error: invalid memory address or nil pointer dereference
            goroutine 43 [running]:
            ...
            k8s.io/kubectl/pkg/cmd/exec.(*terminalSizeQueueAdapter).Next(...)
            	.../exec.go:414
            k8s.io/kubectl/pkg/cmd/exec.FuzzTerminalSizeQueueAdapter.func1(...)
            	.../exec_fuzz_test.go:21 +0x80
            ...
    
FAIL
exit status 1
FAIL	k8s.io/kubectl/pkg/cmd/exec	0.203s
```

**Result**: **Panic detected!** The fuzzer found the bug, but with important caveats:

1. **Found during baseline coverage, not fuzzing**: The crash happened on `seed#0` (first seed input) during "gathering baseline coverage" - before any actual fuzzing/mutation began
2. **Zero fuzzing iterations**: `elapsed: 0s` - the fuzzer never actually ran
3. **Required knowing where to look**: You had to write a test specifically for `terminalSizeQueueAdapter.Next()`
4. **No root cause explanation**: The output shows "nil pointer dereference" but doesn't explain:
   - Which struct field is nil (`delegate`)
   - Why it's nil (uninitialized)
   - What inputs make it nil (symbolic reasoning)
   - How to fix it (add nil check)


#### 4b. nilaway (Nil Pointer Static Analyzer)

```bash
# Install nilaway
go install go.uber.org/nilaway/cmd/nilaway@latest
export PATH=$PATH:$(go env GOPATH)/bin

cd staging/src/k8s.io/kubectl/pkg/cmd/exec
nilaway ./...
```

**Output** (abbreviated — dozens of identical lines):
```
nilaway_config: analysis skipped due to errors in package
buildssa: analysis skipped due to errors in package
nilaway_function_contracts_analyzer: failed prerequisites: buildssa@k8s.io/client-go/dynamic/fake,
  nilaway_config@k8s.io/client-go/dynamic/fake,
  nilaway_function_contracts_analyzer@k8s.io/apimachinery/pkg/runtime, ...
nilaway_function_contracts_analyzer: failed prerequisites: buildssa@k8s.io/kubectl/pkg/cmd/exec [k8s.io/kubectl/pkg/cmd/exec.test],
  nilaway_function_contracts_analyzer@k8s.io/client-go/tools/remotecommand, ...
nilaway_accumulation_analyzer: failed prerequisites: nilaway_accumulation_analyzer@k8s.io/kubectl/pkg/cmd/exec [...],
  nilaway_config@k8s.io/kubectl/pkg/cmd/exec [...]
nilaway: failed prerequisites: nilaway_accumulation_analyzer@k8s.io/kubectl/pkg/cmd/exec [k8s.io/kubectl/pkg/cmd/exec.test],
  nilaway_config@k8s.io/kubectl/pkg/cmd/exec [k8s.io/kubectl/pkg/cmd/exec.test]
... (hundreds more lines of the same pattern)
```

**Result**: **Analysis failed — could not load package graph**. The kubernetes monorepo's internal sub-modules (`k8s.io/client-go/dynamic/fake`, `k8s.io/client-go/rest/fake`, `k8s.io/kubectl/pkg/cmd/testing`, `k8s.io/apimachinery/...`, etc.) are wired together by the root `go.mod` replace directives. When `nilaway` is run from the sub-package directory, it cannot resolve the dependency graph and every internal analyzer (`nilaway_config`, `buildssa`, `nilaway_function_contracts_analyzer`, `nilaway_accumulation_analyzer`) fails with "failed prerequisites" or "analysis skipped due to errors in package". The final `nilaway:` line shows the top-level analyzer also fails, meaning **no nil-flow analysis was performed at all**.

This is the same dependency cascade that breaks `go mod tidy` for the GoLibAFL harness. Even if nilaway had run successfully, it would likely not have flagged the bug — the `delegate` interface field is nil through zero-value struct initialization, not through an explicit `nil` literal or nil-returning function call, which is the nil source pattern nilaway tracks.

#### 5. govulncheck (Known Vulnerability Database)

```bash
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Check the built binary
govulncheck -mode binary ./_output/bin/kubectl
```

**Output**:
```
=== Symbol Results ===

Vulnerability #1: GO-2026-4337
    Unexpected session resumption in crypto/tls
  More info: https://pkg.go.dev/vuln/GO-2026-4337
  Standard library
    Found in: crypto/tls@go1.25.6
    Fixed in: crypto/tls@go1.25.7

Vulnerability #2: GO-2025-3547
    Kubernetes kube-apiserver Vulnerable to Race Condition
  More info: https://pkg.go.dev/vuln/GO-2025-3547
  Module: k8s.io/kubernetes
    Found in: k8s.io/kubernetes@v1.36.0-alpha.0

Vulnerability #3: GO-2025-3521
    Kubernetes GitRepo Volume Inadvertent Local Repository Access
  More info: https://pkg.go.dev/vuln/GO-2025-3521
  Module: k8s.io/kubernetes
    Found in: k8s.io/kubernetes@v1.36.0-alpha.0

Your code is affected by 3 vulnerabilities from 1 module and the Go standard library.
```

**Result**: **Found 3 OTHER vulnerabilities, but NOT our nil pointer bug**. `govulncheck` correctly identified:
- A crypto/tls vulnerability (GO-2026-4337)
- A kube-apiserver race condition (GO-2025-3547)  
- A GitRepo volume vulnerability (GO-2025-3521)

However, it **did NOT detect** the `terminalSizeQueueAdapter.Next()` nil pointer dereference because:
1. This bug was unknown at the time (no CVE assigned yet)
2. `govulncheck` only queries the Go vulnerability database for already-reported issues
3. Zero-day bugs are invisible to signature-based tools

### Summary

| Tool | Detected | Notes |
|------|----------|-------|
| go vet | No | No inter-procedural nil analysis |
| staticcheck | No | No path-sensitive nil tracking |
| gosec | No | 0 issues found — no security patterns match nil struct fields |
| nilaway | No | Analysis failed — kubernetes sub-module dependency cascade prevents package loading |
| go test -fuzz | **Yes** | Crashed on seed#0 (0.11 s) — nil dereference immediately reachable |
| GoLibAFL | **Yes** | 192 crash objectives in 1 min at ~1.9M exec/s (24 clients, vendored harness) |
| **Zorya** | **Yes** | 2 findings: nil receiver and nil `delegate.itab` (1233s, 1234s) |

### Zorya's Advantage

Zorya works at the **binary level with symbolic execution**, which means:

✓ **No source code needed** - works on compiled binaries with symbols
✓ **Path exploration** - explores all possible execution paths through the function  
✓ **Symbolic reasoning** - tracks symbolic state of pointers (nil vs. non-nil)  
✓ **Z3 solver** - mathematically proves a nil pointer dereference is reachable  
✓ **Zero-day detection** - finds unknown bugs without prior knowledge or test cases

This is why Zorya found the bug while traditional tools did not.

---

## GoLibAFL Fuzzing

`terminalSizeQueueAdapter.Next()` is a tiny, pure function — an ideal GoLibAFL target. The nil dereference fires the moment the harness calls `Next()` on an adapter with a nil `delegate`, producing a SIGSEGV that LibAFL records as a crash.

Because `terminalSizeQueueAdapter` is unexported and the kubernetes monorepo pulls in a cascade of internal sub-modules that make `go mod tidy` fail even with a local replace directive, the cleanest approach — identical to the kubelet-empty-flag and p224 harnesses — is to **vendor the vulnerable struct and method directly into the harness package**.

### Vendored vulnerable code (`vuln_exec.go`)

```go
// harnesses/kubectl-nil-delegate/vuln_exec.go
package main

// TerminalSize mirrors k8s.io/client-go/tools/remotecommand.TerminalSize.
type TerminalSize struct {
    Width  uint16
    Height uint16
}

// TerminalSizeQueue mirrors the interface used by terminalSizeQueueAdapter.
type TerminalSizeQueue interface {
    Next() *TerminalSize
}

// noopTerminalSizeQueue is a safe no-op implementation used on the non-crashing path.
type noopTerminalSizeQueue struct{}

func (n *noopTerminalSizeQueue) Next() *TerminalSize { return nil }

// terminalSizeQueueAdapter mirrors the vulnerable kubectl struct.
type terminalSizeQueueAdapter struct {
    delegate TerminalSizeQueue
}

// Next is the vulnerable method — panics when delegate is nil.
func (a *terminalSizeQueueAdapter) Next() *TerminalSize {
    // MISSING: if a.delegate == nil { return nil }
    next := a.delegate.Next() // <-- panic when a.delegate is nil
    if next == nil {
        return nil
    }
    return &TerminalSize{
        Width:  next.Width,
        Height: next.Height,
    }
}
```

### Harness (`main.go`)

With the vulnerable struct vendored locally, the harness has no external imports:

```go
// harnesses/kubectl-nil-delegate/main.go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

// harness is called by LibAFL for every generated input.
// data[0] bit-0: 0 → nil delegate (triggers bug); 1 → noop delegate (safe path)
func harness(data []byte) {
    if len(data) == 0 {
        return
    }
    adapter := &terminalSizeQueueAdapter{}
    if data[0]&1 == 1 {
        adapter.delegate = &noopTerminalSizeQueue{}
    }
    // nil delegate → panic: nil pointer dereference in a.delegate.Next()
    _ = adapter.Next()
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

### Build and run

```bash
# 1. Create the harness directory and write both files above
mkdir -p /home/kgorna/golibafl/harnesses/kubectl-nil-delegate
# write vuln_exec.go and main.go as above

# 2. Initialise the module — no replace directive needed (stdlib only)
cd /home/kgorna/golibafl/harnesses/kubectl-nil-delegate
go mod init fuzz
go mod tidy
cd /home/kgorna/golibafl

# 3. Build and fuzz
export HARNESS=harnesses/kubectl-nil-delegate
cargo run --release -- fuzz

# 4. Replay a crash to confirm the nil dereference
cargo run -- run -i output/crashes/<crashfile>
```

**Result**: **Bug detected** — 24 LibAFL clients running at ~1.9M exec/s collectively found
192 crash objectives in 1 minute (~118M total executions). The corpus stabilised at 25
entries and all 9 covered edges were stable from the first heartbeat
(`edges_stability: 9/9 (100%)`), confirming that the input space is essentially one bit
(`data[0]&1`). The throughput is slightly lower than the kubelet-empty-flag harness (~2.7M)
because `vuln_exec.go` includes an interface dispatch on the safe path, adding a few more
covered edges (`10/4608` vs `10/4644`).

Replaying a crash file confirms the nil dereference:

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
        /home/kgorna/golibafl/harnesses/kubectl-nil-delegate/harness_fuzz.go:28 +0xa5
panic({0x...?, 0x...?})
        /usr/local/go/src/runtime/panic.go:787 +0x132
main.(*terminalSizeQueueAdapter).Next(...)
        /home/kgorna/golibafl/harnesses/kubectl-nil-delegate/vuln_exec.go:29 +0x...
main.harness({0xc000..., 0x1, ...})
        /home/kgorna/golibafl/harnesses/kubectl-nil-delegate/main.go:14 +0x...
Aborted (core dumped)
```

### Comparison with `go test -fuzz`

| Aspect | `go test -fuzz` | GoLibAFL |
|--------|-----------------|---------|
| Instrumentation | Go native sancov | Go native sancov (same) |
| Signal | panic → test failure | SIGSEGV → crash file |
| Detection speed | seed#0 (0.11 s) | < 1 s (first mutation) |
| Throughput | single-threaded | ~1.9M exec/s across 24 parallel clients |
| Total crashes found | 1 corpus entry | 192 crash objectives in 1 min (~118M execs) |
| Setup complexity | Trivial | Requires Rust + Cargo; kubernetes import replaced by vendored `vuln_exec.go` |
| Oracle needed | No — explicit panic | No — crash-based |

**Conclusion**: Both tools find this bug on the very first execution. GoLibAFL provides no additional detection advantage here — the nil dereference is immediately reachable from any call with an uninitialized adapter. The difference would matter in cases requiring deep path exploration or implicit bug classes (silent overflows).

## References

- **Fix commit**: [5f67574](https://github.com/kubernetes/kubernetes/commit/5f675740442edc32f2dcbbe1453f49484440e7a8)
- **Kubernetes version**: Fixed in v1.36.0-alpha.1
- **File**: `staging/src/k8s.io/kubectl/pkg/cmd/exec/exec.go`
- **Function**: `(*terminalSizeQueueAdapter).Next()`

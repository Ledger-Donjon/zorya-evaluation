# Tendermint ValidatorSet.VerifyCommit Voting-Power INTMUL Overflow

**Bug class**: Silent integer overflow (INTMUL)  
**Project**: [tendermint/tendermint](https://github.com/tendermint/tendermint) — BFT consensus engine used by Cosmos Hub, Binance Chain, and dozens of other PoS blockchains  
**Vulnerable versions**: v0.25.0 – v0.26.x  
**Fix commit**: [`c4d93fd`](https://github.com/tendermint/tendermint/commit/c4d93fd) (tag v0.27.0) — introduces `MaxTotalVotingPower` input validation  
**Related issue**: https://github.com/tendermint/tendermint/issues/919

---

## Vulnerability

In `types/validator_set.go`, `VerifyCommit` checks whether a block commit has ≥ 2/3 majority voting power:

```go
// types/validator_set.go — Tendermint v0.26.0, line 303
if talliedVotingPower > vals.TotalVotingPower()*2/3 {
    return nil  // commit accepted
}
return fmt.Errorf("Invalid commit -- insufficient voting power: got %v, needed %v",
    talliedVotingPower, (vals.TotalVotingPower()*2/3 + 1))
```

`TotalVotingPower()` returns `int64`. The expression `TotalVotingPower()*2` is a **raw `int64` multiplication with no overflow guard**. When `totalVotingPower > MaxInt64/2 = 4 611 686 018 427 387 903`, the product silently overflows to a **negative** value:

```
totalVotingPower = 4 611 686 018 427 387 904   (MaxInt64/2 + 1)
totalVotingPower * 2  →  -9 223 372 036 854 775 808   (int64 overflow!)
-9 223 372 036 854 775 808 / 3  →  -3 074 457 345 618 258 602
```

`talliedVotingPower > -3 074 457 345 618 258 602` is `0 > negative` = **TRUE**.

**Consequence**: `VerifyCommit` returns `nil` (block accepted) for a commit where **every precommit is nil** — zero tallied votes. No signature verification is required. Any validator set whose cached `totalVotingPower` ∈ `[MaxInt64/2 + 1, MaxInt64 - 1]` accepts empty commits unconditionally, enabling consensus bypass.

### Why the empty-precommit path reaches the overflow

```go
for idx, precommit := range commit.Precommits {
    if precommit == nil {
        continue   // ← all nil entries skip VerifyBytes entirely
    }
    // signature check — never reached
    if !val.PubKey.VerifyBytes(...) { ... }
    talliedVotingPower += val.VotingPower
}
// talliedVotingPower = 0 here
if talliedVotingPower > vals.TotalVotingPower()*2/3 {  // ← IMULQ overflow
```

Guard conditions that must be symbolically satisfied to reach the `IMULQ`:

| Guard | Condition satisfied by |
|---|---|
| `vals.Size() == len(commit.Precommits)` | 1 validator, 1 nil precommit |
| `height == commit.Height()` | both 0 (default) |
| `blockID.Equals(commit.BlockID)` | both empty `BlockID{}` |

> **Note**: In practice, Zorya was killed (OOM) before reaching the `IMULQ` instruction — see the actual output in the Reproduction section.

### Arithmetic proof

| `totalVotingPower` | `*2` (int64 overflow) | `/3` | `0 > result` | Effect |
|---|---|---|---|---|
| `4611686018427387904` (MaxInt64/2+1) | `-9223372036854775808` | `-3074457345618258602` | **TRUE** | empty commit accepted |
| `9223372036854775806` (MaxInt64-1) | `-4` | `-1` | **TRUE** | empty commit accepted |
| `9223372036854775807` (MaxInt64) | `-2` | `0` | FALSE | safe (only exception) |

### Fix (v0.27.0)

```go
const MaxTotalVotingPower = int64(8198552921648689607)

// Enforced when adding validators — totalVotingPower is bounded at input
if sum > MaxTotalVotingPower {
    return fmt.Errorf("total voting power exceeds limit: %d", sum)
}
```

The raw `*2/3` expression is **still present** in v0.27.0 — the fix bounds the input rather than making the arithmetic safe.

---

## Why `go test -fuzz` cannot find this

- **No crash**: `VerifyCommit` returns `error`, never panics; the overflow produces a wrong `nil` return with no crash signal
- **No oracle**: the fuzzer has no way to know that `nil` for an empty commit is wrong
- **Categorically undetectable** without a test oracle asserting `rejected ↔ tallied < 2/3 × total`

---

## Reproduction Workflow

### 1. Build the vulnerable `tendermint` binary

Tendermint v0.26.0 predates Go modules (it used `dep` / `Gopkg.lock`). Building it
with a modern Go toolchain requires a hand-crafted `go.mod` that pins `grpc` to
**v1.52.0** — the last release that uses the *monolithic* `google.golang.org/genproto`.
`grpc ≥ v1.53` requires the split `google.golang.org/genproto/googleapis/rpc` module,
which in turn requires `go ≥ 1.25` and triggers an "ambiguous import" error at
`go mod tidy` time. Simply running `go mod init + go mod tidy` without this pin
**will fail**.

```bash
# Clone vulnerable source
git clone --depth=1 --branch v0.26.0 \
    https://github.com/tendermint/tendermint.git /tmp/tendermint-026

cd /tmp/tendermint-026

# Create a go.mod with grpc pinned to the last pre-split version.
# Do NOT run 'go mod init' first — write the file directly.
cat > go.mod << 'EOF'
module github.com/tendermint/tendermint

go 1.11

// Pin grpc to v1.52.0 — the last release that uses the monolithic genproto.
// grpc v1.53+ requires google.golang.org/genproto/googleapis/rpc (split 2023)
// which needs go >= 1.25 and causes an "ambiguous import" at go mod tidy time.
require google.golang.org/grpc v1.52.0
EOF

# Resolve all transitive dependencies via the module proxy.
# GONOSUMDB skips checksum verification for packages whose sums may not be
# in the sum database (common for old or fork-only packages like tendermint/btcd).
GONOSUMDB='*' go mod tidy

# Sanity-check: grpc must NOT be upgraded to v1.53+ (which needs split genproto + go 1.25).
# MVS may bump it slightly (e.g. v1.55.0) but anything <= v1.62.x is safe.
grep "google.golang.org/grpc" go.mod
# Expected: something like  google.golang.org/grpc v1.55.0  (NOT v1.79+)

# Build the full tendermint binary with debug symbols (no optimisations)
go build -gcflags="all=-N -l" -o /tmp/tendermint-v026 ./cmd/tendermint/

# Sanity check
/tmp/tendermint-v026 version
```

### 2. Find the target function address

```bash
go tool nm /tmp/tendermint-v026 \
    | grep "ValidatorSet.*VerifyCommit" \
    | grep -v "Future\|Light"
# Example output:
#   10547a0 T github.com/tendermint/tendermint/types.(*ValidatorSet).VerifyCommit
```

Note the address; you will need it for the Zorya command in Step 4.

### 3. Set up a single-node testnet

`VerifyCommit` is called on every committed block. Use `tendermint init` to create a
**single-validator** home directory — this node is the sole proposer and reaches
consensus on its own without any peers.

> **Do not use `tendermint testnet --n 1`**: in v0.26.0 that command always generates
> a multi-validator network (4–5 nodes), and a single node cannot reach 2/3 consensus
> in such a setup, so no blocks are ever committed and `VerifyCommit` is never called.

```bash
# Create a fresh single-node home
/tmp/tendermint-v026 init --home /tmp/tmnode0

# Verify
ls /tmp/tmnode0/config/
# config.toml  genesis.json  node_key.json  priv_validator.json
```

### 4. Run Zorya

Zorya runs `tendermint node` under GDB. When the first block is committed (≈1–2 s), GDB hits the breakpoint at `VerifyCommit`, captures a memory/register snapshot, and Zorya begins symbolic execution with a symbolised `vals.totalVotingPower` field.

> **Critical**: pass `--proxy_app=kvstore` to use the built-in ABCI application.
> Without it, `tendermint node` tries to connect to an external ABCI process on
> `tcp://127.0.0.1:26658`, retries indefinitely, and never reaches consensus —
> so `VerifyCommit` is never called and GDB never hits the breakpoint.

```bash
zorya /tmp/tendermint-v026 \
    --mode function 0x10547a0 \
    --lang go \
    --compiler gc \
    --thread-scheduling main-only \
    --arg "node --home /tmp/tmnode0 --proxy_app=kvstore" \
    --negate-path-exploration
```

Replace `0x10547a0` with the address obtained from Step 2 (it may differ between builds).

**What Zorya intends to do** (idealised flow):

1. Runs `tendermint node --home /tmp/tmnode0 --proxy_app=kvstore` under GDB
2. Waits for the first real `VerifyCommit` call (block 1 finalisation)
3. Takes a GDB snapshot at the function entry with the concrete arguments
4. Symbolises `vals.totalVotingPower` as an unconstrained `int64`
5. Explores the empty-precommit path (all `commit.Precommits[i] == nil → continue`)
6. At the `IMULQ` for `totalVotingPower * 2`, the INTMUL checker asks Z3: can this overflow?
7. Z3 returns **SAT**: `totalVotingPower = 4611686018427387904`
8. `0 > (-9223372036854775808 / 3)` = **TRUE** — empty commit accepted

**In practice** (actual run): Zorya explored the function and its callees for ~29 minutes, finding nil-pointer dereferences and UAF bugs in the surrounding validator logic, then was **killed (OOM) before the engine reached the `IMULQ` instruction**. The INTMUL overflow was not detected.

### 5. Actual Zorya output

```
Writing 565036 reachable blocks to results/panic_reachable.txt
Writing 26350 tainted functions to results/tainted_functions.txt
Writing coverage analysis to results/panic_coverage.json
Writing unreachable summary to results/unreachable_summary.txt and results/unreachable_summary.json
**************************************************************************
THE CONCOLIC EXECUTION OF THE BINARY HAS STARTED!
Find the logs in results/execution_log.txt and results/execution_trace.txt
**************************************************************************
Address: 10547a0, Symbol: github.com/tendermint/tendermint/types.(*ValidatorSet).VerifyCommit -> vals=0xc0002b7170 (reg=RAX @0x0), chainID=0xc0003b0690 (reg=RBX @0x18), chainID=0x11 (reg=RCX @0x8), height=0x1 (reg=RDI @0x38), commit=0xc000386200 (reg=RSI @0x30)
Address: 1053380, Symbol: github.com/tendermint/tendermint/types.(*ValidatorSet).Size -> vals=0xc0002b7170 (reg=RAX @0x0)
[Z3-SOLVER] NULL pointer check took 0.002s

========================================================================
VULNERABILITY: Symbolic NULL pointer dereference
  Address: 0x1053395
  Elapsed: 375.681s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

[Z3-SOLVER] NULL pointer check took 0.002s

========================================================================
VULNERABILITY: Symbolic NULL pointer dereference
  Address: 0x105480b
  Elapsed: 375.811s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
  More details in: results/FOUND_SAT_STATE.txt
========================================================================


========================================================================
VULNERABILITY: Dangling pointer write — Use-After-Free (STORE)
  Address: 0x105482d
  Elapsed: 375.927s
  Opcode: STORE
  Detection method: Exploring the current path with a symbolic check on the pointer
  Written address: 0xc000aa6428
  Memory belongs to freed stack frame from function 0x1053380 (frame RSP: 0xc000aa6428)
  This is a Use-After-Free vulnerability (stack memory reuse).
========================================================================

[Z3-SOLVER] NULL pointer check took 0.002s

========================================================================
VULNERABILITY: Symbolic NULL pointer dereference
  Address: 0x1054842
  Elapsed: 376.002s
  Opcode: LOAD
  Detection method: Exploring the not taken path with Overlay Execution
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

[Z3-OPTIMIZE] CBranch evaluation took 0.352s

========================================================================
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x105481c
  Elapsed: 379.962s
  Opcode: CBRANCH
  Detection method: Exploring the not taken path with Overlay Execution
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

Address: 103e5a0, Symbol: github.com/tendermint/tendermint/types.(*Commit).Height -> commit=0xc000386200 (reg=RAX @0x0)
[Z3-SOLVER] NULL pointer check took 0.002s

========================================================================
VULNERABILITY: Symbolic NULL pointer dereference
  Address: 0x103e5bc
  Elapsed: 384.252s
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

Address: 103e3e0, Symbol: github.com/tendermint/tendermint/types.(*Commit).FirstPrecommit -> commit=0xc000386200 (reg=RAX @0x0)
[Z3-OPTIMIZE] CBranch evaluation took 0.307s

========================================================================
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x103e434
  Elapsed: 417.503s
  Opcode: CBRANCH
  Detection method: Exploring the not taken path with Overlay Execution
  More details in: results/FOUND_SAT_STATE.txt
========================================================================


========================================================================
VULNERABILITY: Dangling pointer write — Use-After-Free (STORE)
  Address: 0x10549a5
  Elapsed: 1244.053s
  Opcode: STORE
  Detection method: Exploring the current path with a symbolic check on the pointer
  Written address: 0xc000aa6428
  Memory belongs to freed stack frame from function 0x1053380 (frame RSP: 0xc000aa6428)
  This is a Use-After-Free vulnerability (stack memory reuse).
========================================================================

[Z3-OPTIMIZE] CBranch evaluation took 0.325s

========================================================================
VULNERABILITY: Satisfiable path to panic/vulnerability
  Address: 0x1054996
  Elapsed: 1738.836s
  Opcode: CBRANCH
  Detection method: Exploring the not taken path with Overlay Execution
  More details in: results/FOUND_SAT_STATE.txt
========================================================================

/usr/local/bin/zorya: line 330: 3132904 Killed   RUSTFLAGS="--cap-lints=allow" cargo run --release -- --write-args "$ARGS"
```

### What happened

Zorya successfully reached `VerifyCommit` and began symbolic exploration of the function and its callees (`Size`, `Commit.Height`, `Commit.FirstPrecommit`). During this exploration it discovered several real bugs via its null-pointer and UAF checkers:

| Finding | Type | Address | Elapsed |
|---|---|---|---|
| Nil dereference in `Size()` | NULL pointer | `0x1053395` | 375.7 s |
| Nil dereference in `VerifyCommit` | NULL pointer | `0x105480b` | 375.8 s |
| Use-After-Free (stack reuse from `Size`) | UAF STORE | `0x105482d` | 375.9 s |
| Nil dereference in `VerifyCommit` | NULL pointer | `0x1054842` | 376.0 s |
| Satisfiable panic path in `VerifyCommit` | CBRANCH | `0x105481c` | 380.0 s |
| Nil dereference in `Commit.Height` | NULL pointer | `0x103e5bc` | 384.3 s |
| Satisfiable panic path in `FirstPrecommit` | CBRANCH | `0x103e434` | 417.5 s |
| Use-After-Free (stack reuse from `Size`) | UAF STORE | `0x10549a5` | 1244.1 s |
| Satisfiable panic path in `VerifyCommit` | CBRANCH | `0x1054996` | 1738.8 s |

**However, Zorya was killed (OOM) before it could explore the path leading to the `IMULQ totalVotingPower*2` instruction.** The findings above are all pointer-safety and nil-dereference side-bugs in the surrounding validator logic — real issues, but not the INTMUL overflow CVE this case study targets.

The INTMUL overflow is a **silent wrong-value** defect: the `IMULQ` executes and returns a negative number without any panic, signal, or branch-taken change that Zorya's standard checkers would flag. Even if Zorya had reached the instruction before being killed, the INTMUL checker would need to be explicitly enabled and configured to fire on this specific instruction — and the resulting wrong `nil` return would still require an oracle asserting "this must be rejected" to be classified as a vulnerability.

---

## Comparison with Other Go Analysis Tools

We tested the vulnerable `types/validator_set.go` against every standard analysis tool. **None detect the overflow without a domain-specific oracle** — it is a silent wrong-value defect, not a crash.

### Running Other Tools

From the tendermint repository root (at the vulnerable tag v0.26.0, built in Step 1):

#### 1. go vet (Standard Go Static Analyzer)

```bash
cd /tmp/tendermint-026/types
go vet ./...
```

**Output**:
```
# github.com/tendermint/tendermint/types
# [github.com/tendermint/tendermint/types]
./block_test.go:253:23: github.com/tendermint/tendermint/version.Consensus struct literal uses unkeyed fields
./protobuf_test.go:94:21: github.com/tendermint/tendermint/version.Consensus struct literal uses unkeyed fields
```

**Result**: **Did NOT detect the overflow**. The 2 findings are in test files (unkeyed struct literals for `version.Consensus`) — a common style issue in pre-module era Go code. `go vet` has no integer overflow analysis and cannot reason about the arithmetic semantics of `int64 * 2`.

#### 2. staticcheck (Enhanced Static Analysis)

```bash
# Install staticcheck
go install honnef.co/go/tools/cmd/staticcheck@latest
export PATH=$PATH:$(go env GOPATH)/bin

cd /tmp/tendermint-026/types
staticcheck ./...
```

**Output** (abbreviated — 65 findings across the types package):
```
block.go:195:4: possible nil pointer dereference (SA5011)
    block.go:198:5: this check suggests that the pointer can be nil
block.go:196:10: possible nil pointer dereference (SA5011)
    block.go:198:5: this check suggests that the pointer can be nil
genesis.go:7:2: "io/ioutil" has been deprecated since Go 1.19 (SA1019)
genesis_test.go:71:2: this value of genDoc is never used (SA4006)
validator_set_test.go:223:4: printf-style function with dynamic format string and
    no further arguments should use print-style function instead (SA1006)
proto3_test.go:7:2: "github.com/golang/protobuf/proto" is deprecated (SA1019)
block.go:84:10: error strings should not be capitalized (ST1005)
... (+ 58 more ST1005 / SA1019 / SA1006 findings across block.go, proposal.go,
     vote.go, heartbeat.go, evidence.go, validation.go, validator_set.go, ...)
```

**Result**: **Did NOT detect the overflow**. `staticcheck` found 65 issues — primarily ST1005 (capitalised error strings throughout the v0.26.0 codebase), SA1019 (deprecated `io/ioutil` and `github.com/golang/protobuf/proto`), SA5011 (possible nil pointer in `block.go`), and SA4006/SA1006 coding style. None relate to the `TotalVotingPower()*2` arithmetic overflow: the multiplication is type-correct `int64` and `staticcheck` performs no integer range analysis.

#### 3. gosec (Security-focused Static Analyzer)

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest
export PATH=$PATH:$(go env GOPATH)/bin

cd /tmp/tendermint-026/types
gosec ./...
```

**Output**:
```
[gosec] 2026/02/27 12:29:20 Including rules: default
[gosec] 2026/02/27 12:29:21 Checking package: types
[gosec] 2026/02/27 12:29:21 Checking file: validator_set.go
[gosec] 2026/02/27 12:29:21 Checking file: validator.go
... (28 files checked)
Results:

[/tmp/tendermint-026/types/protobuf.go:85] - G115 (CWE-190):
    integer overflow conversion int -> int32 (Confidence: MEDIUM, Severity: HIGH)
  > 85:     Total: int32(header.Total),

[/tmp/tendermint-026/types/genesis.go:117] - G304 (CWE-22):
    Potential file inclusion via variable (Confidence: HIGH, Severity: MEDIUM)
  > 117:     jsonBlob, err := ioutil.ReadFile(genDocFile)

[/tmp/tendermint-026/types/event_bus.go:119] - G104 (CWE-703): Errors unhandled
[/tmp/tendermint-026/types/event_bus.go:70]  - G104 (CWE-703): Errors unhandled
[/tmp/tendermint-026/types/event_bus.go:52]  - G104 (CWE-703): Errors unhandled

Summary:
  Gosec  : dev
  Files  : 28
  Lines  : 4972
  Nosec  : 0
  Issues : 5
```

**Result**: **Did NOT detect the overflow**. `gosec` found 5 issues: one G115 for `int → int32` type conversion in `protobuf.go` (unrelated protobuf serialisation), one G304 path traversal in `genesis.go`, and three G104 unhandled errors in `event_bus.go`. The `TotalVotingPower()*2` multiplication is a pure `int64 × int64 → int64` arithmetic operation with no type conversion, so G115 does not fire. `gosec` has no arithmetic overflow detector for same-type multiplications.

#### 4. govulncheck (Known Vulnerability Database)

```bash
govulncheck -mode binary /tmp/tendermint-v026
```

**Output** (abbreviated — 18 vulnerabilities found):
```
=== Symbol Results ===

Vulnerability #1:  GO-2026-4341  Memory exhaustion in net/url
Vulnerability #2:  GO-2026-4340  Handshake messages at incorrect level in crypto/tls
Vulnerability #3:  GO-2026-4337  Unexpected session resumption in crypto/tls
... (13 more stdlib CVEs in crypto/tls, crypto/x509, net/http, net/url, encoding/*)

Vulnerability #17: GO-2023-2153
    Denial of service from HTTP/2 Rapid Reset in google.golang.org/grpc
  Module: google.golang.org/grpc
    Found in: google.golang.org/grpc@v1.55.0 / Fixed in: v1.56.3

Vulnerability #18: GO-2020-0037
    Uncontrolled resource consumption in github.com/tendermint/tendermint
  Module: github.com/tendermint/tendermint
    Found in: github.com/tendermint/tendermint@v0.26.0+dirty
    Fixed in: github.com/tendermint/tendermint@v0.31.1
    Vulnerable symbols found:
      #1: client.NewJSONRPCClient

Your code is affected by 18 vulnerabilities from 2 modules and the Go standard library.
```

**Result**: **Did NOT detect the voting-power overflow**. Found 18 vulnerabilities: 16 in the Go stdlib (all built with go1.24, fixed in later patch releases), 1 in `grpc` (HTTP/2 Rapid Reset DoS, GO-2023-2153), and 1 in `tendermint` itself (GO-2020-0037 — uncontrolled resource consumption via `client.NewJSONRPCClient`, a different bug). The `VerifyCommit` overflow was never assigned a CVE or Go advisory ID — it was described in [issue #919](https://github.com/tendermint/tendermint/issues/919) and silently fixed in v0.27.0. `govulncheck` cannot discover unregistered vulnerabilities.

#### 5. nilaway (Nil Pointer Static Analyzer)

```bash
# Install nilaway
go install go.uber.org/nilaway/cmd/nilaway@latest
export PATH=$PATH:$(go env GOPATH)/bin

cd /tmp/tendermint-026
nilaway ./types/...
```

**Output** (7 findings):
```
/tmp/tendermint-026/types/block.go:494:9: error: Potential nil panic detected.
    Observed nil flow: FirstPrecommit() returns nil → .Height accessed at 494:9
    (same source also at block.go:502:9)

/tmp/tendermint-026/types/validator_set.go:291:7: error: Potential nil panic detected.
    Observed nil flow: GetByIndex() returns nil → .PubKey accessed at 291:7
    (via `val` at validator_set.go:288:6; same source also at 296:26)

/tmp/tendermint-026/types/canonical.go:74:14: error: Potential nil panic detected.
    Observed nil flow: testProposal (global, nilable) → CanonicalizeProposal() →
    proposal.Height accessed at 74:14

/tmp/tendermint-026/types/heartbeat_test.go:14:2: error: Potential nil panic detected.
    Observed nil flow: hb.Copy() returns nil → .Round accessed at 14:2

/tmp/tendermint-026/types/validator_set_test.go:70:31: error: Potential nil panic detected.
    (vset.Remove() result lacking nil guard → .Address accessed)

/tmp/tendermint-026/types/validator_set_test.go:118:40: error: Potential nil panic detected.
    Observed nil flow: GetProposer() returns nil → .Address accessed
    (same source also at 9 other places in validator_set_test.go)

/tmp/tendermint-026/types/validator_set_test.go:221:15: error: Potential nil panic detected.
    Observed nil flow: GetProposer() deeply assigned into proposerOrder → .Address
```

**Result**: **Did NOT detect the overflow** — but found **7 real nil-flow bugs** in the types package. Notably, `validator_set.go:291` is *inside* `VerifyCommit`: `GetByIndex(idx)` can return `nil` for `val`, and then `val.PubKey.VerifyBytes(...)` would panic — a genuine nil dereference that the overflow guard prevents from being reached in practice. This demonstrates that `nilaway` correctly identifies pointer-safety issues in the same function that contains the overflow, but the overflow itself (`int64 * 2`) involves no pointers and is categorically outside nilaway's analysis scope.

#### 6. go test -fuzz (Fuzzing)

##### Without oracle (naïve — just checks for panics):

```go
// types/verify_fuzz_test.go
//go:build go1.18
package types

import (
    "testing"
)

func FuzzVerifyCommit_NoOracle(f *testing.F) {
    // Seed: totalVotingPower just above the overflow threshold
    f.Add(int64(4611686018427387904))
    f.Fuzz(func(t *testing.T, totalVotingPower int64) {
        if totalVotingPower <= 0 {
            return
        }
        vals := NewValidatorSet([]*Validator{
            {Address: []byte("addr"), VotingPower: totalVotingPower},
        })
        commit := &Commit{
            Precommits: []*Vote{nil}, // one nil precommit → tallied = 0
        }
        // No oracle — just checking whether VerifyCommit panics
        _ = vals.VerifyCommit("chain", BlockID{}, 0, commit)
    })
}
```

```bash
cd /tmp/tendermint-026/types
go test -fuzz=FuzzVerifyCommit_NoOracle -fuzztime=60s -v 2>&1 | tee fuzz-no-oracle.log
```

**Output**:
```
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 8 workers
fuzz: elapsed: 60s, execs: 4318200 (71969/sec), new interesting: 3 (total: 4)
PASS
ok      github.com/tendermint/tendermint/types  60.048s
```

**Result**: **Did NOT detect the bug** — 4.3M executions, 0 failures. `VerifyCommit` returns `nil` for the empty commit with overflowing total power — which is **the same return value as a legitimately valid commit**. Without an oracle asserting "this must be rejected", the fuzzer treats a `nil` error as success and has zero crash signal to chase.

##### With oracle (checks that empty commits are rejected):

```go
// types/verify_fuzz_oracle_test.go
//go:build go1.18
package types

import (
    "math"
    "testing"
)

func FuzzVerifyCommit_Oracle(f *testing.F) {
    // Seed: totalVotingPower just above the overflow threshold (MaxInt64/2 + 1)
    f.Add(int64(4611686018427387904))
    f.Fuzz(func(t *testing.T, totalVotingPower int64) {
        if totalVotingPower <= 0 || totalVotingPower == math.MaxInt64 {
            return
        }
        vals := NewValidatorSet([]*Validator{
            {Address: []byte("addr"), VotingPower: totalVotingPower},
        })
        commit := &Commit{
            Precommits: []*Vote{nil}, // one nil precommit → tallied = 0
        }
        err := vals.VerifyCommit("chain", BlockID{}, 0, commit)

        // Oracle: zero tallied voting power must NEVER satisfy ≥ 2/3 majority
        // (totalVotingPower > 0, tallied = 0  →  0 < 2/3 * total  →  must fail)
        if err == nil {
            t.Errorf("OVERFLOW: totalVotingPower=%d accepted empty commit (tallied=0)",
                totalVotingPower)
        }
    })
}
```

```bash
cd /tmp/tendermint-026/types
go test -fuzz=FuzzVerifyCommit_Oracle -fuzztime=60s -v 2>&1 | tee fuzz-oracle.log
```

**Output** (seed triggers immediate detection):
```
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 8 workers
--- FAIL: FuzzVerifyCommit_Oracle (0.00s)
    --- FAIL: FuzzVerifyCommit_Oracle (0.00s)
        verify_fuzz_oracle_test.go:28: OVERFLOW: totalVotingPower=4611686018427387904
            accepted empty commit (tallied=0)

Failing input written to testdata/fuzz/FuzzVerifyCommit_Oracle/seed0
FAIL
exit status 1
FAIL    github.com/tendermint/tendermint/types  0.008s
```

**Result**: **Bug detected instantly** — but only because the seed `4611686018427387904` (= MaxInt64/2 + 1) was hand-crafted at the exact overflow threshold, and the oracle explicitly asserts that zero-tally commits must be rejected. Without the seed, the fuzzer would need to independently generate values in the range `[MaxInt64/2 + 1, MaxInt64)` — a 1-in-4-billion slice of the int64 space — which is impractical with uniform random mutation.

#### 7. GoLibAFL

This bug is a **silent wrong-value** defect: `VerifyCommit` returns a wrong `nil` (commit accepted) instead of an error, with no panic, no SIGSEGV, and no crash signal. This has the same detectability profile as the `evm-gascost-2017` overflow.

##### Harness setup:

```bash
# Inside the GoLibAFL project:
mkdir -p harnesses/tendermint-voting
cd harnesses/tendermint-voting
go mod init fuzz
go mod edit -replace github.com/tendermint/tendermint=/tmp/tendermint-026
GONOSUMDB='*' go mod tidy
cd ../..
```

##### Without oracle (does NOT detect the bug):

```go
// harnesses/tendermint-voting/main.go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "encoding/binary"

    "github.com/tendermint/tendermint/types"
)

func harness(data []byte) {
    if len(data) < 8 {
        return
    }
    totalVotingPower := int64(binary.LittleEndian.Uint64(data[:8]))
    if totalVotingPower <= 0 {
        return
    }
    vals := types.NewValidatorSet([]*types.Validator{
        {Address: []byte("addr"), VotingPower: totalVotingPower},
    })
    commit := &types.Commit{Precommits: []*types.Vote{nil}}
    _ = vals.VerifyCommit("chain", types.BlockID{}, 0, commit)
    // No oracle — overflow returns nil silently, no crash.
}
```

```bash
export HARNESS=harnesses/tendermint-voting
cargo run --release -- fuzz
```

**Result** (6m 15s budget): **Bug NOT detected** — 24 clients ran at ~840–856k exec/s, reaching ~321M total executions across the run, covering 171 edges with a corpus of 120 entries and **0 objectives**. All 171 covered edges are fully stable (100% stability) — the fuzzer saturated coverage immediately and has no gradient toward the overflow range. The overflowed `nil` return is indistinguishable from a legitimate commit acceptance; there is no crash signal to report as an objective.

```
[Client Heartbeat #9]  run time: 6m-15s, clients: 24, corpus: 120, objectives: 0,
    executions: 312695257, exec/sec: 833.8k, edges: 171/98651 (0%), edges_stability: 70/70 (100%)
...
[Client Heartbeat #23] run time: 6m-15s, clients: 24, corpus: 120, objectives: 0,
    executions: 321149021, exec/sec: 856.2k, edges: 171/98651 (0%), edges_stability: 8/8 (100%)
Fuzzing stopped by user. Good bye.
```

##### With oracle + seed (detects the bug):

```go
// harnesses/tendermint-voting/main.go  (oracle version)
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "encoding/binary"
    "math"
    "math/big"

    "github.com/tendermint/tendermint/types"
)

func harness(data []byte) {
    if len(data) < 8 {
        return
    }
    totalVotingPower := int64(binary.LittleEndian.Uint64(data[:8]))
    if totalVotingPower <= 0 || totalVotingPower == math.MaxInt64 {
        return
    }
    vals := types.NewValidatorSet([]*types.Validator{
        {Address: []byte("addr"), VotingPower: totalVotingPower},
    })
    commit := &types.Commit{Precommits: []*types.Vote{nil}}
    err := vals.VerifyCommit("chain", types.BlockID{}, 0, commit)

    // Oracle: tallied = 0, total > 0 → must be rejected
    if err == nil {
        panic("OVERFLOW: totalVotingPower=" +
            new(big.Int).SetInt64(totalVotingPower).String() +
            " accepted empty commit (tallied=0)")
    }
}
```

```bash
# Seed: MaxInt64/2 + 1 = 0x4000000000000000 in little-endian
mkdir -p seeds
printf '\x00\x00\x00\x00\x00\x00\x00\x40' > seeds/overflow_trigger
rm -rf output
export HARNESS=harnesses/tendermint-voting
cargo run --release -- fuzz --input seeds/
```

**Result**: All 24 clients hit an objective on **execution 1, run time 0s** — identical to the `evm-gascost-2017` oracle+seed result:

```
[Objective #1]  run time: 0s, clients: 1,  corpus: 0, objectives: 1,  executions: 1,  exec/sec: 0.000
[Objective #4]  run time: 0s, clients: 2,  corpus: 0, objectives: 2,  executions: 2,  exec/sec: 0.000
[Objective #7]  run time: 0s, clients: 3,  corpus: 0, objectives: 3,  executions: 3,  exec/sec: 0.000
...
[Objective #21] run time: 0s, clients: 24, corpus: 0, objectives: 24, executions: 24, exec/sec: 0.000
Fuzzing stopped by user. Good bye.
```

The seed `\x00\x00\x00\x00\x00\x00\x00\x40` encodes `totalVotingPower = 0x4000000000000000 = 4611686018427387904` (MaxInt64/2 + 1) in little-endian. Every client receives it as its first input, the oracle fires immediately, and the panic is caught as a crash objective before any fuzzing mutation takes place.

**Key takeaway**: GoLibAFL's ~35× throughput advantage over `go test -fuzz` provides no benefit for this bug class. The fundamental bottleneck is not iteration speed but input-space navigation: without a seed near `MaxInt64/2`, coverage-guided mutation has no gradient to explore the overflow region.

---

### Summary

| Tool | Detected | Notes |
|------|----------|-------|
| go vet | No | 2 findings (unkeyed struct literals in test files) — no arithmetic overflow analysis |
| staticcheck | No | 65 findings (ST1005 style, SA1019 deprecations, SA5011 nil pointer in block.go) — no integer range analysis |
| gosec | No | 5 findings (G115 int→int32 in protobuf.go, G304 path traversal, G104 unhandled errors) — G115 only fires on type-conversion overflows, not same-type multiplication |
| govulncheck | No | 18 vulnerabilities found (16 stdlib, grpc HTTP/2 Rapid Reset, tendermint GO-2020-0037 JSONRPCClient) — voting-power overflow has no CVE/advisory |
| nilaway | No | 7 nil-flow findings including one inside `VerifyCommit` (val.PubKey nil if GetByIndex returns nil) — overflow is arithmetic, not a pointer issue |
| go test -fuzz (no oracle) | **No** | 4.3M executions, 0 failures — `nil` return is indistinguishable from valid acceptance |
| go test -fuzz (oracle + seed) | **Yes** | Detected instantly — requires oracle asserting "empty commit must be rejected" + seed `MaxInt64/2+1` |
| GoLibAFL (no oracle) | **No** | 321M+ execs in 6m 15s at ~840–856k exec/s (24 clients), 171 edges, 0 objectives — overflow is silent, `nil` return indistinguishable from valid acceptance |
| GoLibAFL (oracle + seed) | **Yes** | All 24 clients hit objective on execution 1, run time 0s — 24/24 objectives from seed `\x00\x00\x00\x00\x00\x00\x00\x40` (`MaxInt64/2+1`) before any mutation |
| **Zorya** | **Partial** | Found 9 side-bugs (nil dereferences, UAF in surrounding logic) in ~29 min; killed (OOM) before reaching the `IMULQ totalVotingPower*2` instruction — INTMUL overflow not detected |

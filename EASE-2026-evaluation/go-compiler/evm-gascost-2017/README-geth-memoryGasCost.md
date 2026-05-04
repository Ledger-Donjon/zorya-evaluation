# Go-Ethereum EVM Memory Gas Cost Integer Overflow

This case demonstrates an integer overflow vulnerability in go-ethereum's `memoryGasCost()` function, present in geth v1.6.0 (release commit [facc47c](https://github.com/ethereum/go-ethereum/commit/facc47cb5cec97b22c815a0a6118816a98f39876)), fixed in commit [bae7565](https://github.com/ethereum/go-ethereum/commit/bae7565231376bbd23474e2e91c99a21542ef47a). The bug occurs when the quadratic gas cost calculation `newMemSizeWords * newMemSizeWords` silently overflows `uint64`, wrapping the result to a tiny value and making the gas cost near-zero. An attacker can allocate massive EVM memory for almost no gas (DoS vector). Zorya detects this vulnerability through **concolic execution with an integer overflow detector** that asks Z3: "can the 128-bit product differ from the 64-bit product?"

## Vulnerability

Looking at the vulnerable code in `core/vm/gas_table.go`:

```go
func memoryGasCost(mem *Memory, newMemSize uint64) (uint64, error) {
    if newMemSize > gmath.MaxUint64-32 {
        return 0, errGasUintOverflow
    }

    if newMemSize == 0 {
        return 0, nil
    }

    newMemSizeWords := toWordSize(newMemSize)
    newMemSize = newMemSizeWords * 32

    if newMemSize > uint64(mem.Len()) {
        square := newMemSizeWords * newMemSizeWords  // <-- BUG: uint64 overflow!
        linCoef := newMemSizeWords * params.MemoryGas
        quadCoef := square / params.QuadCoeffDiv
        newTotalFee := linCoef + quadCoef

        fee := newTotalFee - mem.lastGasCost
        mem.lastGasCost = newTotalFee

        return fee, nil
    }
    return 0, nil
}
```

**The bug**: `newMemSizeWords * newMemSizeWords` is a `uint64 × uint64 → uint64` multiplication. When `newMemSizeWords` exceeds ~2³², the mathematical result requires more than 64 bits, but Go silently truncates to 64 bits (wrapping). The overflow guard above (`newMemSize > MaxUint64-32`) only protects `toWordSize` from overflowing — it does **not** prevent the subsequent squaring from overflowing. A carefully chosen `newMemSize` (e.g. `0xfffbffe746d9c6c2`) passes the guard, produces a large `newMemSizeWords`, and the squared result wraps to a tiny value — making the gas cost near-zero.

**The impact**: An attacker can craft a transaction that allocates massive EVM memory while paying almost no gas, enabling denial-of-service against Ethereum nodes.

**The fix** (commit [bae7565](https://github.com/ethereum/go-ethereum/commit/bae7565231376bbd23474e2e91c99a21542ef47a)) tightens the overflow guard from `MaxUint64-32` to `0xffffffffe0` and moves the `newMemSize == 0` check before the guard. The constant `0xffffffffe0` is `0x7ffffffff × 32`, ensuring `newMemSizeWords ≤ 0x7ffffffff` after `toWordSize`, so `0x7ffffffff² = 0x3FFFFFFF00000001` fits in `uint64`:
```diff
 func memoryGasCost(mem *Memory, newMemSize uint64) (uint64, error) {
-    if newMemSize > gmath.MaxUint64-32 {
-        return 0, errGasUintOverflow
-    }
-
     if newMemSize == 0 {
         return 0, nil
     }
+    // The constant 0xffffffffe0 is the highest number that can be used
+    // without overflowing the gas calculation
+    if newMemSize > 0xffffffffe0 {
+        return 0, errGasUintOverflow
+    }

     newMemSizeWords := toWordSize(newMemSize)
     newMemSize = newMemSizeWords * 32
```

## How It Happens

1. An EVM opcode (e.g. `MSTORE`) requests memory expansion with a large offset
2. `memoryGasCost` is called with a large `newMemSize` (e.g. `0xfffbffe746d9c6c2`)
3. The value passes the `newMemSize > MaxUint64-32` guard (it's below the threshold)
4. `toWordSize()` converts it to `newMemSizeWords` ≈ `0x7ffdff3a36ce363`
5. `newMemSizeWords * newMemSizeWords` overflows `uint64` → wraps to a tiny value
6. Gas cost returned is near-zero → attacker allocates huge memory for free

## Reproduction Workflow

### 1. Build vulnerable EVM binary

> **Go version used**: go1.25.7 linux/amd64. Geth v1.6.0 is a pre-Go-modules project (2017, GOPATH era).
> Modern Go (≥1.16) defaults to module mode and will fail with *"cannot find main module"*.
> You **must** set `GO111MODULE=off` and use a GOPATH workspace layout.

```bash
# Set up Go workspace for geth v1.6.0 (GOPATH mode — required)
export GOPATH=/tmp/geth-160
export GO111MODULE=off
mkdir -p $GOPATH/src/github.com/ethereum
cd $GOPATH/src/github.com/ethereum
git clone https://github.com/ethereum/go-ethereum.git
cd go-ethereum
git checkout v1.6.0
```

#### Patch out the `go-stack` dependency (required for GDB)

Geth v1.6.0 vendors `github.com/go-stack/stack`, a library that performs runtime stack introspection by deliberately triggering a `sigpanic`. When GDB sets a breakpoint and the program starts, the Go runtime initializes — including the logging subsystem which calls into `go-stack`. GDB intercepts the deliberate SIGSEGV as a real crash, captures the wrong state (at the crash site inside `go-stack`, not at the target function), and produces an unusable memory dump.

The fix is to remove all `go-stack` usage from the three files that import it. This only affects log formatting (stack traces in log lines) and has no effect on EVM execution.

**File 1: `log/logger.go`** — Replace `stack.Call` type and remove `stack.Caller()`:

```diff
 import (
     "fmt"
     "os"
     "time"
-
-    "github.com/go-stack/stack"
 )

 // ...

 type Record struct {
     Time     time.Time
     Lvl      Lvl
     Msg      string
     Ctx      []interface{}
-    Call     stack.Call
+    Call     uintptr
     KeyNames RecordKeyNames
 }

 // ... in func (l *logger) write(msg string, lvl Lvl, ctx []interface{}) { ...

     l.h.Log(&Record{
         Time: time.Now(),
         Lvl:  lvl,
         Msg:  msg,
         Ctx:  newctx,
-        Call: stack.Caller(2),
+        Call: 0,
         KeyNames: RecordKeyNames{
```

**File 2: `log/handler.go`** — Remove `stack` import, `formatCall`, and stack-trace handling:

```diff
 import (
     "fmt"
     "io"
     "net"
     // ...
     "sync"
-
-    "github.com/go-stack/stack"
 )

 // ... remove the formatCall function entirely:
-func formatCall(format string, c stack.Call) string {
-    return fmt.Sprintf(format, c)
-}
// (delete this helper; any remaining call sites should be replaced with fmt.Sprintf)

 // ... in CallerStackHandler, remove the stack.Trace block:
 func CallerStackHandler(stackFormat string, fmtFormat string, h Handler) Handler {
     return FuncHandler(func(r *Record) error {
-        s := stack.Trace().TrimBelow(r.Call).TrimRuntime()
-        if len(s) > 0 {
-            r.Ctx = append(r.Ctx, "stack", fmt.Sprintf(fmtFormat, s))
-        }
         return h.Log(r)
     })
 }

 // ... in LazyHandler, remove the stack.CallStack cast block:
 func LazyHandler(h Handler) Handler {
     return FuncHandler(func(r *Record) error {
         // ...
         // inside the lazy evaluation block, delete this special-case:
-        if cs, ok := v.(stack.CallStack); ok {
-            v = cs.TrimBelow(r.Call).TrimRuntime()
-        }
         // ...
         return h.Log(r)
     })
 }
```

> If you see `undefined: fmt` after patching, it means `fmt` was removed from the imports but the file still uses it (common in geth v1.6.0). Re-add `import "fmt"`.
>
> If you see `undefined: formatCall`, it means you deleted the helper but not all its call sites. Replace every `formatCall(X, Y)` with `fmt.Sprintf(X, Y)` and re-run the build.
>
> **Fastest fix option (recommended for geth v1.6.0):** keep a tiny `formatCall` helper, but make it independent of `go-stack` by switching its argument type to `uintptr`:
>
> ```diff
> -func formatCall(format string, c stack.Call) string {
> -    return fmt.Sprintf(format, c)
> -}
> +func formatCall(format string, c uintptr) string {
> +    return fmt.Sprintf(format, c)
> +}
> ```

**File 3: `log/handler_glog.go`** — Two changes needed inside `func (h *GlogHandler) Log(r *Record) error`:

1. Add `"runtime"` to the import block (it was removed, but `runtime.Stack` is still used in the backtrace path).
2. Replace `r.Call.String()` with `fmt.Sprintf("%v", r.Call)` — `String()` no longer exists once `Call` is `uintptr`.

The two `sed` one-liners that apply both fixes at once:

```bash
cd /path/to/go-ethereum/log

# Fix 1: add runtime import after sync/atomic
sed -i '/"sync\/atomic"/a\\t"runtime"' handler_glog.go

# Fix 2: replace r.Call.String() with fmt.Sprintf
sed -i 's/match := h\.location == r\.Call\.String()/match := h.location == fmt.Sprintf("%v", r.Call)/' handler_glog.go
```

Verify nothing remains:

```bash
grep -n 'r\.Call\.String\|r\.Call\.PC\|go-stack' handler_glog.go
# should return no matches
```

> **Note**: `r.Call.PC()` cache writes are already replaced by `r.Call` in the version of the file you have.
> The `siteCache` field type (`map[uintptr]Lvl`) already matches `r.Call` being `uintptr`,
> so no further changes are needed there.

#### Build

```bash
# Build the standalone EVM binary with debug symbols
cd cmd/evm
go build -gcflags="all=-N -l" -o /tmp/geth-160/evm

# Verify the target function address
go tool nm /tmp/geth-160/evm | grep memoryGasCost
# T 7b1120 github.com/ethereum/go-ethereum/core/vm.memoryGasCost
```

### 2. Verify concrete execution

```bash
# Run benign EVM bytecode that triggers memoryGasCost:
# 0x60 0x42 = PUSH1 0x42 (push value 66)
# 0x60 0x00 = PUSH1 0x00 (push offset 0)
# 0x52      = MSTORE     (store 66 at memory offset 0 → triggers memoryGasCost)
/tmp/geth-160/evm --debug --code 6042600052 run
```

### 3. Run Zorya analysis

```bash
zorya /tmp/geth-160/evm \
  --mode function 0x7b6a40 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --arg "--code 6042600052 run" \
  --negate-path-exploration
```

**Parameters explained:**
- `--mode function 0x7b6a40` — target `memoryGasCost` directly (breakpoint at function entry; get the address with `go tool nm /tmp/geth-160/evm | grep memoryGasCost`)
- `--lang go --compiler gc` — tell Zorya the binary is a standard Go toolchain build
- `--thread-scheduling main-only` — restrict execution to the main goroutine
- `--arg "--code 6042600052 run"` — benign EVM bytecode (`PUSH1 0x42`, `PUSH1 0x00`, `MSTORE`) to establish concrete execution reaching the function
- `--negate-path-exploration` — explore alternative paths at symbolic branch points; both function arguments (`mem *Memory` and `newMemSize uint64`) are automatically made symbolic

> **Note:** The function address (`0x7b1120`) varies by build. Use `go tool nm /tmp/geth-160/evm | grep memoryGasCost` to find yours.

### 4. Zorya Detection Results

**Vulnerability Detected**: **YES** — 3 findings (including the integer overflow)

Zorya produced **3 successive findings** during the same run:

---

#### Finding 1 — NULL pointer dereference in `(*Memory).Len` (98s)

```
[*] SATISFIABLE STATE FOUND
  Timestamp: 2026-02-21 11:11:29 UTC
  Elapsed since start: 98.122s
  Instruction Address: 0x7cab55
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer

The program can panic if its inputs are the following:
  - The input 'mem_ptr' must be 0 (nil)
  - The input 'newMemSize' must be 2
```

Zorya proves that if `mem` is nil (and `newMemSize > 0`), calling `mem.Len()` panics at `0x7cab55`. This is a defensive finding — in practice `mem` is never nil when called from the EVM interpreter, but Zorya exhaustively covers all symbolic cases for the function's arguments.

---

#### Finding 2 — The actual bug: integer overflow in multiplication (120s)

```
[*] SATISFIABLE STATE FOUND
  Timestamp: 2026-02-21 11:11:51 UTC
  Elapsed since start: 119.991s
  Instruction Address: 0x7b6b03
  Opcode: INT_MULT
  Detection method: Integer overflow: the full-width product differs from the truncated product

The program can panic if its inputs are the following:
  - The input 'mem.store.len' must be 0x2049180867b11c0  (145401069180752320)
  - The input 'newMemSize'    must be 0xe2049180867b10c2 (16286302133676609730)
```

This is the **root cause finding**. Zorya's integer overflow detector proves that when `newMemSize = 0xe2049180867b10c2` (≈ 1.63 × 10¹⁹), the 128-bit product of `newMemSizeWords * newMemSizeWords` differs from the truncated 64-bit product — meaning the multiplication **silently overflows**. The Z3 model confirms:
- `newMemSize_RBX!146 = 0xe2049180867b10c2` — large size that passes the overflow guard but causes squaring overflow
- `mem_store_len!143 = 0x2049180867b11c0` — current memory length (smaller than `newMemSize`, so the fee computation path is taken)

**How the detector works**: at every `INT_MULT` P-Code instruction involving a tracked symbolic variable, Zorya zero-extends both 64-bit operands to 128 bits, multiplies at full width, and asks Z3: *"can the upper 64 bits be non-zero?"* If SAT, the multiplication can overflow and a vulnerability is reported with a concrete witness.

---

#### Finding 3 — NULL pointer dereference in `memoryGasCost` (138s)

```
[*] SATISFIABLE STATE FOUND
  Timestamp: 2026-02-21 11:12:09 UTC
  Elapsed since start: 138.252s
  Instruction Address: 0x7b6b46
  Opcode: LOAD
  Detection method: Exploring the current path with a symbolic check on the pointer

The program can panic if its inputs are the following:
  - The pointer 'mem.lastGasCost' must be NULL (nil)
  - The pointer 'mem.store.len'   must be NULL (nil)
  - The input  'newMemSize'       must be 0xffffefffffffffe2 (18446726481523507170)
```

Another NULL dereference — when `mem` is nil, accessing `mem.lastGasCost` panics later in the function at `0x7b6b46`. Same root cause as Finding 1 (nil receiver), but at a different access point deeper in the function.

---

### Symbolic Variable Trace

The link from symbolic initialization (`execution_log.txt`) to the satisfying model (`FOUND_SAT_STATE.txt`, finding 2):

| Symbolic var | FOUND_SAT_STATE (finding 2) | Meaning |
|---|---|---|
| `mem_ptr!141` | `0x0000000000000000` | mem pointer (nil in this model) |
| `mem_store_ptr!142` | `0x0000000000000000` | mem.store backing array |
| `mem_store_len!143` | `0x10707fcc481ac8e8` | mem.store length — current allocated memory |
| `mem_store_cap!144` | `0x0000000000000000` | mem.store capacity |
| `mem_lastGasCost!145` | `0x0000000000000000` | last gas cost cached |
| `newMemSize_RBX!146` | `0xfffbffe746d9c6c2` ← **overflow trigger** | requested memory size → causes squaring overflow |

---

## Comparison with Other Go Analysis Tools

All tools were run with **go1.25.7 linux/amd64**, `GO111MODULE=off`, from the geth v1.6.0 source tree (`$GOPATH/src/github.com/ethereum/go-ethereum`):

### 1. go vet (Standard Go Static Analyzer)

```bash
go vet ./core/vm/...
```

**Output**:
```
core/vm/interpreter.go:125:83: call to time.Since is not deferred
```

**Result**: **Did NOT detect the overflow**. `go vet` found 1 unrelated issue (a deferred call warning in the interpreter). It has no integer overflow analysis — silent wrapping in `uint64` arithmetic is standard Go behavior.

### 2. staticcheck (Enhanced Static Analysis)

```bash
staticcheck ./core/vm/...
```

**Output**:
```
core/vm/contract.go:142:7: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self" (ST1006)
core/vm/contract.go:149:7: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self" (ST1006)
core/vm/logger.go:32:7: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self" (ST1006)
core/vm/memory.go:54:7: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self" (ST1006)
core/vm/memory.go:70:7: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self" (ST1006)
core/vm/memory_table.go:64:6: func memoryCallCode is unused (U1000)
core/vm/stack.go:45:18: func (*Stack).pushN is unused (U1000)
core/vm/stack.go:67:18: func (*Stack).peek is unused (U1000)
```

**Result**: **Did NOT detect the overflow**. Found 8 issues: 5 style warnings about receiver names (`ST1006`) and 3 unused function warnings (`U1000`). `staticcheck` does not track arithmetic overflow in unsigned integer operations.

### 3. gosec (Security-focused Static Analyzer)

```bash
gosec ./core/vm/...
```

**Output** (abbreviated — 13 issues total, none related to the overflow):
```
[gosec] 2026/02/20 15:08:43 Including rules: default

[/tmp/geth-160/src/.../core/vm/gas_table.go:44] - G115 (CWE-190):
    integer overflow conversion int -> uint64 (Confidence: MEDIUM, Severity: HIGH)
  > 44: 	if newMemSize > uint64(mem.Len()) {

[/tmp/geth-160/src/.../core/vm/gas_table.go:277] - G115 (CWE-190):
    integer overflow conversion int -> uint64 (Confidence: MEDIUM, Severity: HIGH)
  > 277: 	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)

[/tmp/geth-160/src/.../core/vm/common.go:42] - G115 (CWE-190):
    integer overflow conversion uint64 -> int (Confidence: MEDIUM, Severity: HIGH)
  > 42: 	return common.RightPadBytes(data[s.Uint64():e.Uint64()], int(size.Uint64()))

[/tmp/geth-160/src/.../core/vm/memory.go:48-49] - G115 (CWE-190):
    integer overflow conversion int -> uint64 (2 instances)

[/tmp/geth-160/src/.../core/vm/contracts.go:101-132] - G115 (CWE-190):
    integer overflow conversion int -> uint64 (4 instances in RequiredGas methods)

[/tmp/geth-160/src/.../core/vm/contracts.go:119] - G406 (CWE-328):
    Use of deprecated weak cryptographic primitive (ripemd160)

[/tmp/geth-160/src/.../core/vm/contracts.go:27] - G507 (CWE-327):
    Blocklisted import golang.org/x/crypto/ripemd160

[/tmp/geth-160/src/.../core/vm/interpreter.go:119,177] - G104 (CWE-703):
    Errors unhandled (2 instances)

Summary:
  Gosec  : dev
  Files  : 26
  Lines  : 4581
  Nosec  : 0
  Issues : 13
```

**Result**: **Did NOT detect the overflow**. Found 13 issues across 26 files: 9× G115 (integer overflow in **type conversions** like `int → uint64`), 2× G104 (unhandled errors), 1× G406 (weak crypto), 1× G507 (blocklisted import). Notably, `gosec` flagged the `uint64(mem.Len())` conversion on line 44 of `gas_table.go` (a type conversion) but completely missed the `newMemSizeWords * newMemSizeWords` arithmetic overflow on line 45 — it only checks type conversions, not arithmetic operations.

### 4. govulncheck (Known Vulnerability Database)

```bash
govulncheck -mode binary /tmp/geth-160/evm
```

**Output**:
```
No vulnerabilities found.
```

**Result**: **No issues detected**. `govulncheck` matches against known CVEs/advisories. This specific overflow was never assigned a CVE — it was silently fixed. The binary was built with a modern Go toolchain, so stdlib CVEs don't match. `govulncheck` cannot discover unknown vulnerabilities.

### 5. nilaway (Nil Pointer Static Analyzer)

```bash
nilaway ./core/vm/...
```

**Output** (abbreviated):
```
core/vm/logger.go:121:3: error: Potential nil panic detected. Observed nil flow
    from source to dereference point:
    - vm/logger.go:121:3: deep read from field `changedValues` lacking guarding

core/vm/common.go:42:30: error: Potential nil panic detected. Observed nil flow
    from source to dereference point:
    - vm/noop.go:55:97: literal `nil` returned from `GetCode()` in position 0
    - vm/instructions.go:397:22: result 0 of `GetCode()` passed as arg `data` to `getData()`
    - vm/common.go:42:30: function parameter `data` sliced into

(+ 3 more nil panics in core/state/statedb.go via runtime.go)
```

**Result**: **Did NOT detect the overflow**. Found 5 potential nil panics (all valid nil-flow findings), but `nilaway` is a nil pointer analysis tool — it has no integer overflow detection capability.

### 6. go test -fuzz (Fuzzing)

#### Without oracle (naive — just checks for panics):

```go
func FuzzMemoryGasCostNaive(f *testing.F) {
    f.Add(uint64(32))
    f.Add(uint64(0))
    f.Add(uint64(0xffffffffffffffff))
    f.Add(uint64(0xffffffffe1))
    f.Fuzz(func(t *testing.T, newMemSize uint64) {
        mem := &Memory{}
        _, _ = memoryGasCost(mem, newMemSize)
        // No oracle — just checking if the function panics
    })
}
```

```bash
go test -fuzz=FuzzMemoryGasCostNaive -fuzztime=120s ./core/vm/
```

**Output**:
```
fuzz: elapsed: 0s, gathering baseline coverage: 0/4 completed
fuzz: elapsed: 0s, gathering baseline coverage: 4/4 completed, now fuzzing with 8 workers
...
fuzz: elapsed: 2m0s, execs: 10860850 (94770/sec), new interesting: 0 (total: 4)
PASS
ok  	github.com/ethereum/go-ethereum/core/vm	120.115s
```

**Result**: **Did NOT detect the overflow**. 10,860,850 executions in 120.115 s (~88–95k exec/s, 8 workers), 0 failures. The overflow is **silent** — Go does not panic on unsigned arithmetic overflow. Without a domain-specific oracle, the fuzzer has no way to know the result is wrong. The fuzzer was run for 120 seconds to match Zorya's detection time on this bug (119.991 s, finding 2). Run-to-run variance and CPU differences (this measurement was taken on an i7-1165G7) do not change the qualitative result: the fuzzer reports PASS regardless of the time budget because the overflow produces no crash signal.

#### With big.Int oracle (correct expected value):

```go
func FuzzMemoryGasCost(f *testing.F) {
    f.Add(uint64(32))
    f.Add(uint64(0))
    f.Add(uint64(0xffffffffffffffff))
    f.Add(uint64(0xffffffffe1))
    f.Fuzz(func(t *testing.T, newMemSize uint64) {
        mem := &Memory{}
        gas, err := memoryGasCost(mem, newMemSize)
        if err != nil || newMemSize == 0 {
            return
        }
        // Compute correct gas with big.Int (no overflow)
        words := new(big.Int).SetUint64(toWordSize(newMemSize))
        square := new(big.Int).Mul(words, words)
        quadCoef := new(big.Int).Div(square, big.NewInt(512))
        linCoef := new(big.Int).Mul(words, big.NewInt(3))
        expected := new(big.Int).Add(quadCoef, linCoef)
        actual := new(big.Int).SetUint64(gas)
        if expected.Cmp(actual) != 0 {
            t.Errorf("OVERFLOW BUG: newMemSize=%d, expected gas=%s, got gas=%d",
                newMemSize, expected.String(), gas)
        }
    })
}
```

```bash
go test -fuzz=FuzzMemoryGasCost -fuzztime=120s ./core/vm/
```

**Output**:
```
--- FAIL: FuzzMemoryGasCost (0.05s)
    --- FAIL: FuzzMemoryGasCost (0.00s)
        gas_table_fuzz_test.go:35: OVERFLOW BUG: newMemSize=1099511627745,
            expected gas=2305843112292909056, got gas=103079215104

FAIL
exit status 1
FAIL	github.com/ethereum/go-ethereum/core/vm	0.068s
```

**Result**: **Bug detected instantly** — but only because the seed `0xffffffffe1` (just above the fix threshold) was hand-crafted and the oracle recomputes the expected gas with `big.Int`. The naïve oracle (`gas < 1000`) used initially missed the bug even with the same seeds, because the linear coefficient `newMemSizeWords × 3` produces a large number despite the quadratic term overflowing — the gas is wrong but not obviously tiny.

**Key takeaway**: fuzzing requires **both** the right inputs **and** the right oracle. The overflow produces a silently wrong result, not a crash. Without domain-specific knowledge to write the oracle, fuzzing cannot detect this bug.

### Summary

| Tool | Detected | Notes |
|------|----------|-------|
| go vet | No | No arithmetic overflow analysis |
| staticcheck | No | Flags unused code and style issues only |
| gosec | No | Flags type-conversion overflows (G115) but misses arithmetic overflow in `*` |
| govulncheck | No | No CVE assigned; `govulncheck` returned "No vulnerabilities found" |
| nilaway | No | Nil pointer tool — wrong bug class |
| go test -fuzz (no oracle) | No | 10,860,850 executions in 120.115 s (= Zorya detection time), 0 failures — overflow is silent |
| go test -fuzz (big.Int oracle) | **Yes** | Detected instantly — but requires a hand-crafted domain oracle |
| GoLibAFL (no oracle) | **No** | Runs forever — overflow is silent, no crash signal |
| GoLibAFL (big.Int oracle) | **Yes** | `panic()` in oracle caught as SIGSEGV; detected quickly |
| **Zorya** | **Yes** | 3 findings: nil receiver (98s), integer overflow — the bug (120s), nil lastGasCost (138s) |
| BINSEC | No | 110 paths, 6994 SMT queries, 44 min — 0 assertions fired; nil paths cut as `non executable`, overflow is silent |
| SymQEMU | No | Output: `0x` (2 lines total); zero test cases generated — overflow is silent, no crash oracle |

---

## GoLibAFL Fuzzing

This bug is a **silent unsigned overflow** — Go does not panic on `uint64` wraparound. Without an oracle, no fuzzer (GoLibAFL or `go test -fuzz`) can detect it, because there is no crash signal to catch. The oracle requirement is identical to the `fasthttp-parseuint-overflow` case.

### Harness (no oracle — does NOT detect the bug)

```go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import "github.com/ethereum/go-ethereum/core/vm"

func harness(data []byte) {
    if len(data) < 8 {
        return
    }
    newMemSize := uint64(data[0]) | uint64(data[1])<<8 |
        uint64(data[2])<<16 | uint64(data[3])<<24 |
        uint64(data[4])<<32 | uint64(data[5])<<40 |
        uint64(data[6])<<48 | uint64(data[7])<<56
    mem := vm.NewMemory()
    _, _ = vm.MemoryGasCostExported(mem, newMemSize)
    // No oracle — overflow returns silently, no crash.
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

**Result**: Runs indefinitely — millions of executions, zero crashes. The overflowed gas value is accepted silently.

### Harness (with big.Int oracle — detects the bug)

```go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "math/big"

    "github.com/ethereum/go-ethereum/core/vm"
    "github.com/ethereum/go-ethereum/params"
)

func toWordSize(size uint64) uint64 {
    if size > (1<<64 - 32) { return 0 }
    return (size + 31) / 32
}

func harness(data []byte) {
    if len(data) < 8 {
        return
    }
    newMemSize := uint64(data[0]) | uint64(data[1])<<8 |
        uint64(data[2])<<16 | uint64(data[3])<<24 |
        uint64(data[4])<<32 | uint64(data[5])<<40 |
        uint64(data[6])<<48 | uint64(data[7])<<56

    mem := vm.NewMemory()
    gas, err := vm.MemoryGasCostExported(mem, newMemSize)
    if err != nil || newMemSize == 0 {
        return
    }

    // Oracle: recompute with big.Int (no overflow possible)
    words := new(big.Int).SetUint64(toWordSize(newMemSize))
    square := new(big.Int).Mul(words, words)
    quadCoef := new(big.Int).Div(square, big.NewInt(int64(params.QuadCoeffDiv)))
    linCoef := new(big.Int).Mul(words, big.NewInt(int64(params.MemoryGas)))
    expected := new(big.Int).Add(quadCoef, linCoef)
    actual := new(big.Int).SetUint64(gas)

    if expected.Cmp(actual) != 0 {
        panic("OVERFLOW: newMemSize=" + new(big.Int).SetUint64(newMemSize).String() +
            " expected=" + expected.String() + " got=" + actual.String())
    }
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

> **Note**: `memoryGasCost` is unexported. Either export it as `MemoryGasCostExported` in the vulnerable source tree, or use `//go:linkname` to access it from the same binary.

### Build and run (5-minute budget)

```bash
# 1. Clone GoLibAFL
git clone https://github.com/srlabs/golibafl
cd golibafl

# 2. Create harness directory (oracle version)
mkdir -p harnesses/evm-gascost-oracle
# paste the oracle main.go above into harnesses/evm-gascost-oracle/main.go

cd harnesses/evm-gascost-oracle
go mod init fuzz
# Point to the vulnerable geth source (before bae7565).
# geth v1.6.0 is a GOPATH-era project — run 'go mod init github.com/ethereum/go-ethereum'
# inside that directory first if it has no go.mod yet.
go mod edit -replace github.com/ethereum/go-ethereum=/tmp/geth-160/src/github.com/ethereum/go-ethereum
go mod tidy
cd ../..

# 3. Build and fuzz (5 minutes)
export HARNESS=harnesses/evm-gascost-oracle
cargo run --release -- fuzz --timeout 300

# 4. Replay a crash
cargo run -- run -i output/crashes/<crashfile>
```

**Result** (without seed, 5-minute budget): **Bug NOT detected** — 24 clients ran at ~3M exec/s for
5 minutes (~900M+ total executions), reaching 41 edges and a corpus of 99 entries, with
**0 objectives**. The overflow is silent: `memoryGasCost` returns a wrong-but-small gas value
without panicking, so there is no crash signal to chase. Every valid (non-overflowing) input
takes the *same code path* as an overflowing one — only 41 edges are ever covered, all stable
(100% stability) — giving the coverage-guided mutator no gradient toward the overflow threshold.

**Why the oracle alone is not enough**: the oracle `panic()` is compiled into the harness and
fires correctly when `expected ≠ actual`, but the fuzzer never generates a value in the
overflow range (`newMemSize ≥ 0x2000000001`). All ~900M sampled inputs either hit the
`newMemSize > MaxUint64-32` guard (early return) or land in the non-overflowing region
(oracle agrees, no panic, no new coverage edge).

**Fix — seed corpus**: a single 8-byte seed at the overflow boundary makes the bug detectable
immediately:

```bash
# newMemSize = 0xffffffffe1 in little-endian
mkdir -p seeds
printf '\xe1\xff\xff\xff\xff\x00\x00\x00' > seeds/overflow_trigger
rm -rf output   # clear the stale blind-run corpus
cargo run --release -- fuzz --input seeds/
```

With this seed the oracle comparison fires on the very first execution of every client — all
24 clients report an objective at execution 1, run time 0s:

```
[Objective #4]  run time: 0s, clients: 1,  corpus: 0, objectives: 1,  executions: 1
[Objective #6]  run time: 0s, clients: 2,  corpus: 0, objectives: 2,  executions: 2
...
[Objective #23] run time: 0s, clients: 24, corpus: 0, objectives: 24, executions: 24
```

Replaying the crash file confirms the overflow:

```
$ cargo run -- run -i output/crashes/35c6a09d38da5534
Running: output/crashes/35c6a09d38da5534
Go panic: OVERFLOW: newMemSize=1099511627745 expected=2305843112292909056 got=103079215104
goroutine 17 [running, locked to thread]:
...
main.harness(...)
        /home/kgorna/golibafl/harnesses/evm-gascost-oracle/main.go:42 +0x81f
Aborted (core dumped)
```

The numbers confirm the exact overflow:
- `newMemSize = 1099511627745` = `0xffffffffe1`
- `words = toWordSize(0xffffffffe1) = 2³⁵ = 34359738368`
- `words² = 2⁷⁰` — overflows `uint64` (max 2⁶⁴−1) → wraps to **0**
- `quadCoef = 0 / 512 = 0` (quadratic term completely lost)
- `got  = 0 + 3×2³⁵ = 103079215104` (only the linear term survives)
- `expected = 2⁷⁰/512 + 3×2³⁵ = 2305843009213693952 + 103079215104 = 2305843112292909056`

An attacker supplying `newMemSize ≈ 0xffffffffe1` would pay gas for `103 GWei`-equivalent
memory instead of the correct `2305 PetaWei`-equivalent — a **~22,000× undercharge**.

### Comparison with `go test -fuzz`

| Aspect | `go test -fuzz` (oracle) | GoLibAFL (oracle) |
|--------|--------------------------|-------------------|
| Instrumentation | Go native sancov | Go native sancov (same) |
| Signal | `t.Errorf` → test failure | `panic()` → SIGSEGV → crash file |
| Throughput | ~87k exec/s | ~3M exec/s across 24 clients |
| No-oracle result | PASS (silent) — 10,860,850 execs in 120.115 s (= Zorya detection time), 0 failures | 0 objectives — spins indefinitely |
| Oracle only, no seed | Not detected (same gradient problem) | **Not detected** — 0 objectives in 5 min / 900M+ execs |
| Oracle + seed `0xffffffffe1` | **Detected instantly** | **Detected instantly** |
| Setup complexity | Trivial | Requires Rust + Cargo; GOPATH-era geth needs `go mod init` + `go get btcd@v0.22.1` first |

**Conclusion**: Both tools require the same two ingredients — the domain-specific `big.Int`
oracle **and** a seed near the overflow threshold. Without the seed, coverage-guided fuzzing
has no gradient toward the overflow region: every valid input covers the same 41 edges
regardless of whether it causes arithmetic wrapping. GoLibAFL's ~35× higher throughput
(~3M exec/s vs ~87k exec/s, 900M+ executions in 5 min) gives no advantage here because the
bottleneck is not iteration speed but input-space navigation. This is a fundamental limitation
of coverage-guided fuzzing against silent integer overflow: the oracle turns the bug into a
detectable crash, but a seed is needed to place the fuzzer in the right region of the 64-bit
input space.

See also:
- [`binsec-findings/README-binsec.md`](./binsec-findings/README-binsec.md) — binary-level symbolic execution (**not detected**: silent overflow not reachable via crash-based assertion)
- [`symqemu-findings/README-symqemu.md`](./symqemu-findings/README-symqemu.md) — input-driven concolic execution (**not detected**: no crash oracle)

## Bug Classification

**Type:** Integer Overflow (Silent Arithmetic Wrapping)

- `memoryGasCost` computes a quadratic gas formula: `gas = words² / 512 + words × 3`
- The squaring `words²` overflows `uint64` when `words > ~2³²`
- Go does **not** panic on unsigned overflow — the result silently wraps
- The overflow guard (`newMemSize > MaxUint64-32`) only protects `toWordSize`, not the squaring
- An attacker can request ~2⁶⁴ bytes of memory while paying near-zero gas
- Fixed by tightening the overflow guard from `MaxUint64-32` to `0xffffffffe0`, preventing `newMemSizeWords` from exceeding `0x7ffffffff`

## References

- **Vulnerable version**: geth v1.6.0, release commit [facc47c](https://github.com/ethereum/go-ethereum/commit/facc47cb5cec97b22c815a0a6118816a98f39876)
- **Fix commit**: [bae7565](https://github.com/ethereum/go-ethereum/commit/bae7565231376bbd23474e2e91c99a21542ef47a) — *"core/vm: fix overflow in gas calculation formula"* (Martin Holst Swende, 2017-06-28)
- **File**: `core/vm/gas_table.go`
- **Function**: `memoryGasCost`
- **Analyzed function address**: `0x7b1120` (`github.com/ethereum/go-ethereum/core/vm.memoryGasCost`)
- **Overflow address (finding 2)**: `0x7b11e3`

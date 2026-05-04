# Binsec Analysis — geth-tracers-2024

Binary-level symbolic execution using Binsec on the geth `(*callTracer).OnTxEnd()` vulnerability.

## Key difference vs. geth-graphql-2025

`resolveHeader()` begins with `b.mu.Lock()`, which caused Binsec to immediately enter the VDSO / `futex` syscall and cut all paths before reaching the bug. **`OnTxEnd()` has no mutex** — it is a pure function that reads a receipt pointer and a slice, making it a much better target for Binsec.

## Commands Used

### 1. Create Memory Snapshot with GDB

Same 3-terminal setup as the main reproduction workflow:

**Terminal 1** — Start geth under GDB and break at `OnTxEnd` entry:
```bash
gdb --args ./build/bin/geth --dev --http --http.api eth,debug,web3
(gdb) break *0x1f36e80
(gdb) run
```
> Replace `0x1f36e80` with the address from `nm build/bin/geth | grep "callTracer.*OnTxEnd"`.

**Terminal 2** — Get the dev account and send a transaction:
```bash
ADDR=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' \
  http://localhost:8545 | jq -r '.result[0]')

TX_HASH=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"'$ADDR'","to":"'$ADDR'","value":"0x1"}],"id":1}' \
  http://localhost:8545 | jq -r '.result')
echo "TX_HASH: $TX_HASH"
```

**Terminal 3** — Trigger the tracer path (this hits the GDB breakpoint):
```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["'$TX_HASH'", {"tracer": "callTracer"}],"id":1}' \
  http://localhost:8545
```

Back in **Terminal 1** — once GDB breaks at `OnTxEnd`, save the snapshot and exit:
```bash
(gdb) generate-core-file core.snapshot
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_geth.ini` (see the file in this directory).

```ini
# Go register calling convention (Go 1.17+):
#   RAX = t  *callTracer           (receiver)
#   RBX = receipt *types.Receipt   ← symbolized (THE BUG)
#   RCX = err.type  (nil for nil error interface)
#   RDI = err.value (nil for nil error interface)

starting from core

# Symbolize receipt (RBX) — can be nil (the bug) or a valid pointer
rbx := nondet as receipt_ptr
assume receipt_ptr = 0 || (receipt_ptr >= 0x1000 && receipt_ptr <= 0x7fffffffffff)

# Keep err = nil so the early-return guard is not taken
rcx := 0   # err.type  = nil
rdi := 0   # err.value = nil

explore all

replace <fmt.Sprintf>, <fmt.Fprintf>, <fmt.Printf>, <fmt.Println> by
  return
end

replace <github.com/ethereum/go-ethereum/eth/tracers/native.clearFailedLogs> by
  return
end

abort at <runtime.panicmem>
abort at <runtime.gopanic>
abort at <runtime.panicdivide>
abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
```

### 3. Run Binsec

```bash
../binsec/_build/install/default/bin/binsec \
  -sse -sse-script ./binsec_geth.ini ./core.snapshot \
  -sse-depth 10000
```

## Key Design Choices

### Why symbolize `RBX` (receipt pointer)?

In Go's register-based calling convention (Go 1.17+), `OnTxEnd` receives:

| Register | Value |
|----------|-------|
| RAX | `t *callTracer` (receiver) |
| **RBX** | **`receipt *types.Receipt`** ← symbolic |
| RCX | `err.type` (itab ptr of error interface) |
| RDI | `err.value` (data ptr of error interface) |

The bug is triggered when `receipt = nil` (RBX = 0) and `err = nil` (RCX = RDI = 0). We keep `err` concrete nil so Binsec does not explore the early-return path; only `receipt` is made symbolic.

### Why no need to stub a backend?

Unlike `resolveHeader()`, `OnTxEnd()` does not call any backend. The receipt pointer is passed directly as a parameter — Binsec simply needs to explore the two cases: `receipt_ptr = 0` (bug) and `receipt_ptr ≠ 0` (safe).

### Why stub `clearFailedLogs`?

`clearFailedLogs` recursively traverses the callstack slice, which would cause significant path explosion. Stubbing it with `return` keeps the analysis focused on the nil-check bug.

### Why `abort at <runtime.panicIndex>`?

The bounds check on `t.callstack[0]` calls `runtime.panicIndex` when the slice is empty. Adding this abort point lets Binsec report the secondary bug (Finding 3: empty callstack) in addition to the nil receipt dereference.

## Results

Raw output: [`binsec-output.txt`](./binsec-output.txt)

### Key Finding — `runtime.panicIndex` detected

```
[sse:error]  Assertion failed @ 0x48d660 (<runtime.panicIndex>)
              --- Model ---
              # Variables
              receipt_ptr!1 : 0x000000002d357427
```

**Bug partially detected** — Binsec found one assertion failure: a path reaching `runtime.panicIndex` (the Go runtime's bounds-check panic). This corresponds to **Zorya's Finding 3** (index out of range on `t.callstack[0]` when the callstack is empty).

The model shows `receipt_ptr!1 = 0x000000002d357427` — receipt is **non-nil** on this path. The panic is not from the nil receipt dereference (Finding 2) but from the empty callstack bounds check. In the concrete snapshot, `t.callstack.len` was 0 (the tracer was snapshotted before the EVM pushed any frame), so Go's compiler-generated bounds check on `t.callstack[0]` fires first, regardless of the receipt value.

To reach the nil receipt panic (Finding 2), `t.callstack.len` would need to be symbolized as well, so Binsec can explore the path where `len ≥ 1` but `receipt = 0`.

### Statistics

```
SMT queries
  Preprocessing simplifications
    total     134       (all solved by simplification — no Z3 needed)
  Satisfiability queries
    total     99
    sat       40
    unsat     59
    unknown   0
    time      1789.25s  (≈ 30 min total SMT time)
    average   18.07s    (per query)

Exploration
  total paths                      49
  completed/cut paths              1    ← the panicIndex assertion failure
  pending paths                    29   ← analysis not exhaustive
  discontinued paths               19
  failed assertions                1
  branching points                 76
  max path depth                   369  (well within -sse-depth 10000)
  visited instructions (unrolled)  757
  visited instructions (static)    1345
```

### Path cut reasons

| Cut reason | Address(es) | Count | Meaning |
|---|---|---|---|
| `uninterpreted "0f 05 # syscall"` | `0x48ea53`, `0x48f0a1` | 4 | `futex`/`write` syscalls inside Go runtime error handling |
| `uninterpreted "KO"` | `0x417c8b` | 1 | Unrecognised instruction in geth code |
| `non executable` | `0x10000000000`, `0x203a...`, `0x1e066...`, `0x000000`, `0xc001d00008` | 5 | Jump-table dispatch hitting non-code addresses (indirect call targets from `explore all`) |
| `uninterpreted "cd 03 # int $0x3"` | `0x48d0c0` | 1 | GDB's `INT 3` breakpoint byte left in the core snapshot — Binsec reads the patched opcode |
| jump target enumeration limit | `0x1f36f0e`, `0x448382`, `0x48ce63`, `0x41d1b2`, `0x41d007`, `0x4524b9`, `0x48a44e`, `0x48b2a8` | 8 warnings | Indirect calls hit the default limit of 3 possible targets |

**Note on `INT 3` (`cd 03`)**: GDB inserts a software breakpoint (`0xCC`) at `0x1f36e80` to stop execution. When the core is dumped, this byte remains patched in the snapshot. Binsec reads `int $0x3` at that location, which it cannot interpret. Workaround: use `(gdb) delete breakpoints` before `generate-core-file`, or patch the byte back manually.

## Limitations

- **GDB `INT 3` in snapshot**: The breakpoint byte patches the snapshot, causing Binsec to cut one path with `uninterpreted "cd 03 # int $0x3"`. Fix: `(gdb) delete breakpoints` before generating the core file.
- **Concrete callstack length**: In the snapshot, `t.callstack.len = 0` (snapshotted before the EVM pushed the first frame). This causes the bounds check to fire before the nil receipt check. To also detect Finding 2, add `@[rax + 0x08, 8] := nondet as callstack_len` to the ini script (assuming callstack.len is 8 bytes at offset 8 of the slice header pointed to by RAX).
- **29 pending paths**: The analysis was not exhaustive — Binsec printed statistics while 29 paths were still queued. Increasing `-sse-depth` or running longer may find additional issues.
- **Jump enumeration limit**: Indirect calls (function pointers in the tracer dispatch) hit the default limit of 3 targets. Use `-sse-jump-enum N` with a higher N to explore more targets.

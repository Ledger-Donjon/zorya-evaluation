# Binsec Analysis

Binary-level symbolic execution using Binsec on the geth `(*Block).resolveHeader()` vulnerability.

## Commands Used

### 1. Create Memory Snapshot with GDB

Same 3-terminal setup as the main reproduction workflow:

**Terminal 1** — Start geth under GDB and break at `resolveHeader`:
```bash
gdb --args ./build/bin/geth --dev --http --graphql --http.api eth,web3,net,miner
(gdb) break *0x1a3acc0
(gdb) run
```

**Terminal 2** — Send a transaction to get a tx hash:
```bash
./build/bin/geth attach http://localhost:8545

# In the geth console:
var txHash = eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[0], value: 1})
console.log("MY_TX_HASH: " + txHash)
# MY_TX_HASH: 0xf2a1e49ccfac253639fd75d263ec521270d2ddccb04ad722298104e4699abd86
```

**Terminal 3** — Trigger the vulnerable GraphQL path (this hits the breakpoint):
```bash
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"query": "{ transaction(hash: \"0xf2a1e49ccfac253639fd75d263ec521270d2ddccb04ad722298104e4699abd86\") { block { number } } }"}' \
     http://localhost:8545/graphql
```

Back in GDB (once the breakpoint is hit at `resolveHeader` entry):
```bash
(gdb) generate-core-file core.snapshot
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_geth.ini`

```ini
# Block struct layout (offset from RAX):
#   0x00: r             *Resolver          (8 bytes)
#   0x08: numberOrHash  *BlockNumberOrHash (8 bytes)
#   0x10: mu            sync.Mutex         (8 bytes)
#   0x18: hash          common.Hash       (32 bytes)
#   0x38: header        *types.Header      (8 bytes)  ← BUG
#   0x40: block         *types.Block       (8 bytes)

starting from core

# Make b.header symbolic (the pointer that is nil when block is not found)
@[rax + 0x38, 8] := nondet as b_header
assume b_header = 0 || (b_header >= 0x1000 && b_header < 0x7fffffffffff)

# Stub HeaderByNumberOrHash to return (nil, nil)
# Go 1.17+ register ABI: (*types.Header, error) → RAX=0, RBX=0, RCX=0
replace <github.com/ethereum/go-ethereum/eth.(*EthAPIBackend).HeaderByNumberOrHash> by
  rax := 0
  rbx := 0
  rcx := 0
  return
end

explore all

replace <fmt.Sprintf>, <fmt.Fprintf>, <fmt.Printf>, <fmt.Println> by
  return
end

abort at <runtime.panicmem>
abort at <runtime.gopanic>
```

### 3. Run Binsec

```bash
../binsec/_build/install/default/bin/binsec \
  -sse -sse-script ./binsec_geth.ini ./core.snapshot \
  -sse-depth 10000
```

## Key Design Choices

### Why `@[rax + 0x38, 8]`?

The `Block` struct has the following layout (confirmed in `execution_log.txt` lines 125–155):

| Offset | Field          | Type                     | Size     |
|--------|----------------|--------------------------|----------|
| 0x00   | `r`            | `*Resolver`              | 8 bytes  |
| 0x08   | `numberOrHash` | `*BlockNumberOrHash`     | 8 bytes  |
| 0x10   | `mu`           | `sync.Mutex`             | 8 bytes  |
| 0x18   | `hash`         | `common.Hash`            | 32 bytes |
| 0x38   | `header`       | `*types.Header`          | 8 bytes  |
| 0x40   | `block`        | `*types.Block`           | 8 bytes  |

The receiver `b *Block` is passed in `RAX`. `b.header` is therefore at `[RAX + 0x38]`.

### Why stub `HeaderByNumberOrHash`?

The bug is not triggered by `b.header` being nil at function entry — the first `if b.header != nil` guard would just skip the fetch. The panic occurs **after** `HeaderByNumberOrHash` returns nil. To make Binsec reach that code path:

1. `b.header` must be nil at entry (not yet cached) → kept concrete nil from snapshot
2. `HeaderByNumberOrHash` must return nil → stubbed to return `(0, 0, 0)` in registers
3. Binsec then explores the path where `b.header` remains nil and reaches `b.header.Hash()` → abort at `runtime.panicmem`

## Results

### Statistics

```
[sse:info] Empty path worklist: halting ...
[sse:info] SMT queries
             Preprocessing simplifications
               total          2885
               sat            2885
               unsat          0
               time           0.01

             Satisfiability queries
               total          2838
               sat            29
               unsat          2809
               unknown        0
               time           0.86
               average        0.00

           Exploration
             total paths                      30
             completed/cut paths              0
             pending paths                    0
             discontinued paths               30
             failed assertions                0
             branching points                 9689
             max path depth                   10003
             visited instructions (unrolled)  40590
             visited instructions (static)    1645

[sse:warning] Threat to completeness :
              - 4 paths have reached the maximal depth and have been cut (-sse-depth)
```

### Key Finding

**Bug NOT detected** — all 30 paths were discontinued before reaching the nil pointer dereference.

The two root causes visible in the output:

| Cut reason | Address | Count | Meaning |
|---|---|---|---|
| `uninterpreted "0f 05 # syscall"` | `0x7ffff7fc3bb0`, `0x48f773` | 16 | `futex` syscall inside `sync.Mutex.Lock()` — Binsec cannot model kernel calls |
| `uninterpreted "KO"` | `0x7ffff7fc3707`, `0x7ffff7fc3b00`, … | 10 | Unrecognised VDSO instructions (e.g. `vdso_clock_gettime`, atomic primitives) |
| `max depth` | various VDSO addresses | 4 | Path budget (10 000 instructions) exhausted inside the mutex runtime |

All cut addresses (`0x7ffff7fc3xxx`) are in the Linux **VDSO** — the kernel-mapped page that implements `clock_gettime`, `futex`, etc. Binsec enters this code as soon as `b.mu.Lock()` is called (the very first instruction of `resolveHeader`), and never returns from it.

### Root Cause of Failure

`resolveHeader` starts with:
```go
b.mu.Lock()
defer b.mu.Unlock()
```

At the binary level, `sync.Mutex.Lock()` compiles to an atomic `CMPXCHG` followed by a `futex(FUTEX_WAIT, ...)` syscall (`0f 05`) on the slow path. Binsec:
1. Forks paths for all branches inside the mutex implementation
2. Enters the VDSO to execute the `futex` syscall
3. Hits `uninterpreted "0f 05 # syscall"` and cuts every path

The nil dereference at `b.header.Hash()` is **never reached** because all paths are killed inside `Lock()`. The stub for `HeaderByNumberOrHash` is therefore never exercised.

### Limitations

- **`sync.Mutex` is opaque to Binsec**: Go's mutex uses kernel-level futex syscalls on the slow path, which Binsec cannot interpret. A workaround would be to add `replace <sync.(*Mutex).Lock>, <sync.(*Mutex).Unlock> by return end` to the ini script, but this carries a risk of masking other issues.
- **VDSO instructions**: Addresses in `0x7ffff7fc3xxx` belong to the kernel VDSO page and contain instructions Binsec marks as `KO`.
- **4 paths hit max depth** inside the VDSO, confirming the mutex is the bottleneck.
- **No `failed assertions`**: neither `runtime.panicmem` nor `runtime.gopanic` was ever reached.

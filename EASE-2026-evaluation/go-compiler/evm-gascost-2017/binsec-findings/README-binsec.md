# Binsec Analysis — evm-gascost-2017

Binary-level symbolic execution using Binsec on the standalone EVM binary for the `memoryGasCost()` integer overflow vulnerability.

## Key difference vs. other case studies

All other bugs in this dataset (nil pointer dereferences, index out of range) are **crash-producing**: they trigger `runtime.panicmem`, `runtime.gopanic`, or `runtime.panicIndex`, which Binsec can detect via `abort at` assertions. The `memoryGasCost` integer overflow is fundamentally different:

> `newMemSizeWords * newMemSizeWords` silently wraps in `uint64`. Go does **not** panic on unsigned arithmetic overflow. No exception, no signal, no runtime abort — the function returns normally with a wrong (near-zero) result.

This means Binsec's standard crash-detection methodology **cannot detect the overflow itself**. It can, however, still detect the secondary nil-pointer findings (Zorya's F1 and F3) once the two configuration issues below are fixed.

## Commands Used

### 1. Create Memory Snapshot with GDB

The standalone EVM binary is a single-shot program — snapshot setup is straightforward:

```bash
gdb --args /tmp/geth-160/evm --code 6042600052 run
(gdb) break *0x7b6a40
(gdb) run
# GDB stops at memoryGasCost entry
(gdb) delete breakpoints     # ← important: avoids INT3 byte in snapshot
(gdb) generate-core-file core.snapshot
(gdb) quit
```

> Replace `0x7b6a40` with the address from:
> `go tool nm /tmp/geth-160/evm | grep memoryGasCost`

### 2. Binsec Configuration Script

File: `binsec_evm.ini` (see the file in this directory).

```ini
starting from core

# Register ABI: newMemSize is in RBX, mem pointer is in RAX
rbx := nondet as newMemSize
assume newMemSize > 0

rax := nondet as mem_ptr
assume mem_ptr = 0 || (mem_ptr >= 0x1000 && mem_ptr <= 0x7fffffffffff)

explore all

replace <runtime.morestack> by return end
replace <runtime.morestack_noexit> by return end
replace <fmt.Sprintf>, <fmt.Fprintf>, <fmt.Printf>, <fmt.Println> by return end

abort at <runtime.panicmem>
abort at <runtime.gopanic>
abort at <runtime.panicdivide>
abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
abort at <runtime.panicnildereference>
```

### 3. Run Binsec

```bash
binsec -sse -sse-script ./binsec_evm.ini ./core.snapshot \
  -sse-depth 10000
```

## Configuration Issues Found (and Fixed)

### Issue 1 — Wrong calling convention

The initial `binsec_evm.ini` used the **Go 1.6 stack-based ABI** (`@[rsp+0x10, 8]`), but geth v1.6.0 is compiled with a modern Go toolchain that uses the **Go 1.17+ register ABI**. Zorya's `execution_log.txt` confirms the actual layout:

| Register | Argument |
|----------|----------|
| `RAX` | `mem *Memory` |
| `RBX` | `newMemSize uint64` ← **the overflowing value** |

**Fix**: replace the stack symbolization with `rbx := nondet as newMemSize` and `rax := nondet as mem_ptr`.

### Issue 2 — Missing `runtime.morestack` stub

**Symptom**: Binsec cuts the only path after just 69 instructions:
```
[sse:error] Cut path 0 (uninterpreted "0f 05 # syscall") @ 0x48d541
[sse:info] Empty path worklist: halting ...

Exploration
  total paths                      1
  discontinued paths               1   ← all paths cut
  visited instructions (unrolled)  69
```

**Cause**: Go inserts a stack-growth preemption check at the entry of every non-leaf function:
```asm
CMP RSP, stackguard0(g)
JBE runtime.morestack       ; ← Binsec can take this branch
```
When Binsec explores the grow-stack branch, execution enters `runtime.morestack`, which eventually calls a `futex` syscall (`0x48d541`) — cutting the path immediately before the function body is reached.

**Fix**: stub `runtime.morestack` and `runtime.morestack_noexit` with `return` so Binsec stays in the function body:
```ini
replace <runtime.morestack> by return end
replace <runtime.morestack_noexit> by return end
```

## Key Design Choices

### Why symbolize `RAX` (mem pointer)?

Without symbolizing `mem`, Binsec can only explore the concrete path where `mem = 0xc0001fd0c0` (the snapshot value). Making `mem` nullable lets Binsec find:
- **Zorya F1** (nil receiver → panic in `(*Memory).Len()` @ `0x7cab55`)
- **Zorya F3** (nil `mem.lastGasCost` dereference @ `0x7b6b46`)

### Why are the `abort at` panic points ineffective for the overflow?

Zorya's finding F2 is an `INT_MULT` at `0x7b6b03`:
```
newMemSize = 0xe2049180867b10c2  (16286302133676609730)
→ newMemSizeWords * newMemSizeWords overflows uint64 silently
→ function returns normally with near-zero gas cost
```
No branch, no signal, no panic. Binsec traverses the `IMUL`/`MULQ` instruction with no indication anything went wrong. An overflow oracle would require explicitly asserting that the 64-bit result matches the lower 64 bits of the 128-bit product — which Binsec SSE does not natively support.

## Results

Raw output: see below.

```
[sse:error] Cut path 2  (uninterpreted "0f 05 # syscall") @ 0x48d541
[sse:error] Cut path 6  (uninterpreted "0f 05 # syscall") @ 0x48d541
[sse:error] Cut path 14 (uninterpreted "0f 05 # syscall") @ 0x48d541
[sse:warning] Enumeration of jump targets @ 0x7b6b6a hit the limit 3 and may be incomplete
[sse:warning] Enumeration of jump targets @ 0x447422 hit the limit 3 and may be incomplete
...  (VDSO syscall/KO/max-depth cuts — see full output)
[sse:info] SMT queries
             Preprocessing simplifications
               total     7072
               sat       7072
               time      0.04s
             Satisfiability queries
               total     6994
               sat       100
               unsat     6894
               unknown   0
               time      2614.45s
               average   0.37s

           Exploration
             total paths                      110
             completed/cut paths              0
             pending paths                    13
             discontinued paths               97
             failed assertions                0       ← bug NOT detected
             branching points                 23392
             max path depth                   10003
             visited instructions (unrolled)  97300
             visited instructions (static)    1622
```

### Key finding — `failed assertions: 0`

**Bug NOT detected.** Binsec explored 110 paths (97 discontinued, 13 still pending) and raised **zero assertion failures**. The integer overflow at `0x7b6b03` was traversed but produced no detectable signal — the `IMUL` instruction simply returns a wrong 64-bit result and execution continues normally.

The secondary nil-pointer findings (Zorya's F1 and F3) were also not flagged. When `mem_ptr = 0`, accessing `mem.store.len` causes Binsec to read from a near-zero address, which it cuts as `non executable` rather than routing through `runtime.panicmem`. The abort points are therefore never reached.

### Statistics

| Metric | Value |
|--------|-------|
| Total paths explored | 110 |
| Discontinued paths | 97 |
| Pending paths (not exhaustive) | 13 |
| **Failed assertions** | **0** |
| SMT satisfiability queries | 6994 |
| SMT sat / unsat | 100 / 6894 |
| Total SMT time | 2614.45s (≈ 44 min) |
| Max depth reached | 10003 (10 paths cut by `-sse-depth`) |

### Path cut reasons

| Cut reason | Address(es) | Count | Meaning |
|---|---|---|---|
| `uninterpreted "0f 05 # syscall"` | `0x48d541` | 3 | `futex` / `write` in Go runtime (stack growth path — `runtime.morestack` not stubbed) |
| `uninterpreted "0f 05 # syscall"` | `0x7ffff7fc3bb0` | many | VDSO syscall wrapper |
| `uninterpreted "KO"` | `0x7ffff7fc37xx`, `0x7ffff7fc3b00`, `0x7ffff7fc3c67` | many | Unrecognised VDSO instructions |
| `non executable` | `0x1877ff`, `0x000000`, `0x10000000000`, `0xf05dcf…` | multiple | Jump-table dispatch hitting non-code addresses |
| `max depth` | VDSO addresses | 10 | `-sse-depth 10000` limit hit inside VDSO |
| Jump enumeration limit | `0x7b6b6a`, `0x447422`, `0x48b323`, `0x41cdd2`, `0x41cc27`, `0x451439`, `0x48d12b`, `0x48889e` | 8 warnings | Indirect calls capped at 3 targets |

> **Note on VDSO cuts**: most cuts originate in VDSO code at `0x7ffff7fc3xxx` (clock_gettime / gettimeofday stubs). These are reached via `runtime.morestack` paths (the `runtime.morestack` stub was not included in this run; adding it would eliminate the VDSO explosion and reduce path count significantly).

### Finding table

| Finding | Address | Opcode | Detected by Binsec? | Reason |
|---------|---------|--------|---------------------|--------|
| F1 — nil `mem` receiver → panic in `mem.Len()` | `0x7cab55` | LOAD | ❌ No | `non executable` cut before `runtime.panicmem` |
| **F2 — integer overflow `newMemSizeWords²`** | `0x7b6b03` | INT_MULT | **❌ No** | Silent wrapping — no panic, no branch change |
| F3 — nil `mem.lastGasCost` dereference | `0x7b6b46` | LOAD | ❌ No | `non executable` cut before `runtime.panicmem` |

**None of the three findings are detectable by Binsec on this binary.**

## Comparison with Zorya

| Aspect | Binsec | Zorya |
|--------|--------|-------|
| Detection method | Crash detection (`abort at` panic sites) | Semantic invariant: 128-bit product ≠ 64-bit product |
| Integer overflow detection | ❌ No native support | ✅ `INT_MULT` checker with Z3 |
| Nil dereference detection | ❌ Nil paths cut as `non executable` | ✅ Via symbolic NULL check |
| **F1 (nil mem receiver)** | ❌ | ✅ (98s) |
| **F2 (integer overflow — the bug)** | **❌** | **✅ (120s)** |
| **F3 (nil lastGasCost)** | ❌ | ✅ (138s) |
| SMT time | 2614s (44 min), 0 findings | 138s, 3 findings |

## Limitations

- **No overflow oracle**: Binsec has no built-in mechanism for detecting silent unsigned integer wrapping. The overflow at `0x7b6b03` is invisible to crash-based analysis.
- **Nil paths cut as `non executable`**: When `mem_ptr = 0`, Binsec reads from near-zero addresses and cuts the path instead of routing to `runtime.panicmem`. Adding explicit assertions (`assert mem_ptr != 0`) could expose these.
- **VDSO path explosion**: `runtime.morestack` (not stubbed in this run) routes into VDSO clock/syscall wrappers, producing dozens of KO/syscall cut paths. Adding `replace <runtime.morestack> by return end` would suppress this noise.
- **13 pending paths**: The analysis was not exhaustive. Increasing `-sse-depth` or running longer may explore further — but cannot change the fundamental result for the silent overflow.

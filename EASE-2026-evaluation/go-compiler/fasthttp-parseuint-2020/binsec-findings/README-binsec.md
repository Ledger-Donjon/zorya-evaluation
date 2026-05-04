# BINSEC Analysis — fasthttp-parseuint-overflow

Binary-level symbolic execution using BINSEC on the `fasthttp` helloworldserver binary targeting the `parseUintBuf` silent integer overflow.

## Key difference vs. other case studies

All crash-producing bugs in this dataset (nil pointer dereferences, index out-of-range panics) can in principle be detected by BINSEC via `abort at <runtime.gopanic>` assertions. The `parseUintBuf` overflow is fundamentally different:

> `vNew := 10*v + int(k)` silently wraps in `int64`. Go does **not** panic on signed arithmetic overflow. No exception, no signal, no runtime abort — the function returns normally with a wrong (negative or small) integer value.

This means BINSEC's standard crash-detection methodology **cannot detect the overflow itself**. There is no reachable `abort` target that corresponds to the bug.

## Commands Used

### 1. Create Memory Snapshot with GDB

```bash
gdb /tmp/fasthttp-server
(gdb) break *0x62fd80           # parseUintBuf entry — confirm with go tool nm
(gdb) run

# In a separate terminal, trigger the breakpoint:
#   curl -d "hello" http://localhost:8080/

# GDB stops at parseUintBuf
(gdb) delete breakpoints         # avoid INT3 byte in snapshot
(gdb) generate-core-file core.snapshot
(gdb) quit
```

> **Note**: The server must be running and must have received a POST request before the
> snapshot is taken. Use `(sleep 5 && curl -d "hello" http://localhost:8080/) &` before
> launching GDB, or send curl from a second terminal while GDB is waiting.

### 2. BINSEC Configuration Script

```ini
starting from core

; Go register ABI (Go 1.17+): slice header is in (RAX=ptr, RBX=len, RCX=cap)
; RBX holds b.len — make it symbolic so BINSEC explores different lengths
rbx := nondet as b_len
assume b_len >= 0 && b_len <= 32

; RAX holds b.ptr — treat as a concrete pointer (we cannot symbolize heap contents)
; Symbolizing RAX would require also symbolizing the bytes at that address,
; which BINSEC cannot do automatically for heap-allocated buffers.

explore all

; Stub Go runtime functions that trigger syscalls and cause early path cuts
replace <runtime.morestack>         by return end
replace <runtime.morestack_noexit>  by return end
replace <runtime.growslice>         by return end

; Standard panic abort targets
abort at <runtime.panicmem>
abort at <runtime.gopanic>
abort at <runtime.panicdivide>
abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
abort at <runtime.panicnildereference>
```

### 3. Run BINSEC

```bash
binsec -sse -sse-script binsec_parseuint.ini \
       -sse-depth 10000 \
       -sse-timeout 600 \
       core.snapshot
```

## Why BINSEC Cannot Detect This Bug

### 1. No crash target for arithmetic overflow

BINSEC's bug-detection model relies on reachable `abort` sites (panic functions, `__assert_fail`, etc.). The `parseUintBuf` overflow sets `v` to a wrong value and returns normally with `err = nil`. There is no abort to reach.

To detect it, BINSEC would need either:
- An explicit assertion `assert v >= 0` after the multiplication (not present in the code), or
- A semantic invariant oracle (analogous to the `big.Int` oracle in the fuzz harness)

Neither exists in the binary.

### 2. Heap content is not symbolized

The slice bytes at `b.ptr` (RAX = `0xc0000b005c`) are **concrete** in the snapshot — they contain `0x35` (`'5'`). BINSEC, like Zorya, symbolizes registers but does not automatically extend symbolization to the heap memory a register points to.

Even with symbolic `b.len`, BINSEC reads concrete bytes from the heap when evaluating `b[i]`, so the loop body never sees symbolic digit values and no overflow is triggered.

### 3. Loop depth and runtime path explosion

`parseUintBuf` contains a loop of up to `b.len` iterations. With symbolic `b.len` and concrete bytes, BINSEC unrolls the loop concretely (all iterations read `'5'`). Detecting the overflow requires at least 19 symbolic iterations with specific digit patterns — infeasible without heap symbolization.

Additionally, the first SWI encountered inside `parseUintBuf` (from the Go stack growth prologue) causes an early path cut unless `runtime.morestack` and `runtime.growslice` are stubbed.

## Results

| Property | Outcome |
|----------|---------|
| Bug detected | **No** |
| Reason | Silent overflow — no abort target; heap bytes are concrete |
| Path cuts | SWI from `runtime.morestack` / `runtime.growslice` (mitigated with stubs) |
| Secondary findings | None (no nil pointers, no slice panics in this function) |

## Conclusion

BINSEC cannot detect the `parseUintBuf` silent integer overflow for the same structural reason it cannot detect `memoryGasCost`: both are arithmetic overflows with no observable crash. BINSEC's `abort at` methodology is fundamentally crash-oriented. Detecting silent overflows at the binary level requires semantic invariant injection (e.g., checking that the mathematical value of the parsed string matches the returned integer) — which must be provided externally and is not present in the binary.

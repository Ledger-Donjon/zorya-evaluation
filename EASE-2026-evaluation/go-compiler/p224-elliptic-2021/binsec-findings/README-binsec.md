# Binsec Analysis — p224-elliptic-2021

Binary-level symbolic execution using Binsec on the standalone p224 driver
binary for the `p224Contract` carry bug (CVE-2021-3114).

## Key difference vs. other case studies

Most bugs in this dataset (nil pointer dereferences, index out of range) are
**crash-producing**: they trigger `runtime.panicmem`, `runtime.gopanic`, or
`runtime.panicIndex`, which Binsec can detect via `abort at` assertions.

The p224 carry bug is fundamentally different:

> BUG1 (inverted `out3GT` mask) and BUG2 (missing carry-down loop) both cause
> `p224Contract` to return a **silently wrong `[8]uint32`** field element.
> Go does **not** panic on integer underflow or wrong bit-mask values.
> No exception, no signal, no runtime abort — the function returns normally
> with a mathematically incorrect result.

This means Binsec's standard crash-detection methodology **cannot detect the
bugs themselves**. Additionally, `runtime.memmove` — called by the `copy` at
the very start of the function — is a significant execution barrier.

## Commands Used

### 1. Create Memory Snapshot with GDB

```bash
gdb --args /tmp/p224-driver 0000000000000000000000000001
(gdb) break *0x4d7840
(gdb) run
# GDB stops at the p224Contract entry point
(gdb) delete breakpoints    # important: avoids leaving INT3 bytes in the snapshot
(gdb) generate-core-file /tmp/p224-core.snapshot
(gdb) quit
```

> Replace `0x4d7840` with the address from:
> ```
> go tool nm /tmp/p224-driver | grep p224Contract
> ```

### 2. Binsec Configuration Script

File: `binsec_p224.ini` (see this directory).

Key choices:

```ini
starting from core

# Symbolize in[0..7] (the 8 limbs at *rbx)
@[rbx+0x00, 4] := nondet as limb0
# ... (limb1 through limb7)
assume limb0 <= 0x1fffffff   # restrict to 29-bit precondition

# Pre-seed *rax with the same symbols (simulates the copy that memmove does)
@[rax+0x00, 4] := limb0
# ...

explore all

replace <runtime.memmove> by return end   # ← critical stub

abort at <runtime.panicmem>
abort at <runtime.gopanic>
abort at <runtime.panicdivide>
abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
```

Note: `runtime.morestack` is **not** stubbed. Binsec explored 1135 instructions
before the morestack slow path was eventually taken and cut on its `futex` syscall.

### 3. Run Binsec

```bash
../binsec/_build/install/default/bin/binsec -sse \
       -sse-script binsec_p224.ini \
       -sse-depth 10000 \
       /tmp/p224-core.snapshot
```

## Configuration Issues and Design Choices

### Issue 1 — `runtime.memmove` blocks exploration (fixed by stub)

**Without the stub**: Binsec enters `runtime.memmove` immediately (first call
after function entry), encounters a SIMD or `rep movsb` instruction it cannot
interpret, and cuts the only path after ≈20 instructions — the same failure
point hit by Zorya (`Address: 4659e0, Symbol: runtime.memmove`).

**Fix**: stub `runtime.memmove` with `return` and pre-seed `*rax` with the
same symbolic limb values as `*rbx`, simulating what the copy would have done.

**Effect**: with the stub in place, Binsec explored **1135 instructions** and
**121 branching points** inside the carry arithmetic — confirming that the stub
successfully allowed execution to proceed deep into the function body.

### Issue 2 — `runtime.morestack` cuts the remaining path

Go inserts a stack-growth preemption check at every function entry and at some
back-edges:

```asm
CMP RSP, stackguard0(g)
JBE runtime.morestack        ; ← Binsec can take this symbolic branch
```

After 1135 instructions, Binsec eventually took the morestack branch and hit
the `futex` syscall (`0f 05`) inside `runtime.morestack` at address `0x4669a1`,
cutting the path:

```
[sse:error] Cut path 0 (uninterpreted "0f 05 # syscall") @ 0x4669a1
```

`runtime.morestack` is **not** stubbed in this configuration. Adding
`replace <runtime.morestack> by return end` would eliminate this cut and
allow full exploration of all carry-arithmetic paths, but it would not change
the fundamental conclusion — the bugs remain invisible without an oracle.

### Issue 3 — No arithmetic-correctness oracle

Even with full exploration of the carry arithmetic, Binsec traverses the buggy
instructions with no observable signal:

- **BUG1**: `out[3] - 0xffff000` (wrong direction) produces a different
  bitmask than the correct `0xffff000 - out[3]`, but no branch changes and no
  panic result.
- **BUG2**: `out[0] -= 1` when `out[0] == 0` wraps silently to `0xFFFFFFFF` —
  Go never traps unsigned underflow.

Detecting either bug would require an explicit postcondition assertion:

```ini
# Assert the output is fully reduced after the function body:
assert @[rax+0x00, 4] < 0x10000000   # out[0] < 2^28 (no underflow residue)
assert @[rax+0x0c, 4] <= 0x0ffff000  # out[3] fully reduced
```

Such assertions are not part of a standard crash-based Binsec configuration.

## Results

Full raw output: [`binsec-output.txt`](./binsec-output.txt)

```
[sse:error] Cut path 0 (uninterpreted "0f 05 # syscall") @ 0x4669a1
[sse:info] Empty path worklist: halting ...
[sse:info] SMT queries
             Preprocessing simplifications
               total          9
               sat            9
               unsat          0
               time           0.00

             Satisfiability queries
               total          4
               sat            4
               unsat          0
               unknown        0
               time           0.00
               average        0.00

           Exploration
             total paths                      1
             completed/cut paths              0
             pending paths                    0
             discontinued paths               1
             failed assertions                0
             branching points                 121
             max path depth                   1135
             visited instructions (unrolled)  1135
             visited instructions (static)    766
```

**`failed assertions: 0` — Bug NOT detected.**

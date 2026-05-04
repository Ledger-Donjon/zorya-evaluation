# Binsec Analysis

Binary-level symbolic execution using Binsec on the kubelet `RegisterWithTaintsVar.String()` vulnerability.

## Commands Used

### 1. Create Memory Snapshot with GDB

```bash
gdb --args /path/to/kubelet --help
(gdb) break *0x38152a0
(gdb) run
(gdb) generate-core-file core.snapshot
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_kubelet.ini`

```ini
starting from core

# Make the receiver 't' symbolic (passed in RAX)
# t.Value is at offset 0 of RegisterWithTaintsVar struct
@[rax, 8] := nondet as t_ptr

# Allow t_ptr to be 0 (nil) or a valid pointer
# This forces exploration of the nil pointer case
assume t_ptr = 0 || (t_ptr >= 0x1000 && t_ptr < 0x7fffffffffff)

explore all

halt at @[rsp, 8]

abort at <runtime.panicmem>
abort at <runtime.gopanic>

```

### 3. Run Binsec

```bash
binsec -sse -sse-script ./binsec_kubelet.ini ./core.snapshot -sse-depth 10000 -sse-engine multi-checks
```

## Results

### Statistics

```
Satisfiability queries:
  total:    1648
  sat:      622
  unsat:    849
  unknown:  177
  time:     2253.83s (~37.5 minutes)

Exploration:
  total paths:         402
  completed/cut:       2
  stale paths:         400
  branching points:    9534
  max path depth:      3763
```

### Key Finding

**Bug NOT conclusively detected** - While the `assume` constraint successfully forced exploration of paths where `t_ptr = 0`, Binsec did not detect the actual nil pointer dereference.

The warnings about address `0x00000000`:
```
[sse:warning] Cut path 13 (non executable) @ 0x00000000
[sse:warning] Cut path 16 (non executable) @ 0x00000000
...
```

These indicate attempts to **execute code at address 0** (invalid jump targets), not attempts to **load/store data from address 0** (which would be the nil pointer dereference when accessing `*t.Value`).

No abort at panic handlers was recorded, and the actual memory access violation wasn't detected.

### Limitations

- Many paths cut due to uninterpreted floating-point instructions (`ucomisd`)
- Syscalls can't be symbolically executed
- Indirect jumps enumeration limited (Go interfaces, closures, defer)
- 254 SMT queries remained unsolved

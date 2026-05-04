# Binsec Analysis — ksm-oob-2025

Binary-level symbolic execution using Binsec on the kube-state-metrics `compilePath.func2` off-by-one vulnerability.

## Key Characteristic

Unlike the nil pointer bugs in `geth-graphql-2025` and `geth-tracers-2024`, this is an **off-by-one index out-of-range** bug. The panic is `runtime.panicIndex` (slice bounds check), not `runtime.panicmem` (nil dereference). Binsec can detect this by symbolizing the `len` field of the slice and checking if the concrete index `i` equals `len(s)`.

## Commands Used

### 1. Create Memory Snapshot with GDB

**Terminal 1** — Start kube-state-metrics under GDB and break at `compilePath.func2`:
```bash
gdb --args ./kube-state-metrics \
    --kubeconfig=/root/.kube/config \
    --custom-resource-state-config-file=/home/kgorna/go-projects/kube-state-metrics/ksm-config.yaml \
    --custom-resource-state-only

(gdb) break *0x2b04e00
(gdb) run
```
> Replace `0x2b04e00` with the address from `nm kube-state-metrics | grep "compilePath.func2"`.

Once GDB breaks at the closure entry (triggered when KSM evaluates the CR path), save the snapshot:
```bash
(gdb) delete breakpoints    # remove INT 3 patch to avoid 'cd 03' cut in Binsec
(gdb) generate-core-file core.snapshot
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_ksm.ini` (see this directory).

```ini
starting from core

# Symbolize the slice length (at offset 0x08 from the slice data pointer in RBX)
@[rbx + 0x08, 8] := nondet as slice_len
assume slice_len >= 0 && slice_len <= 16

explore all

replace <fmt.Sprintf>, <fmt.Errorf>, <fmt.Fprintf>, <fmt.Printf>, <fmt.Println> by
  return
end

abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
abort at <runtime.panicmem>
abort at <runtime.gopanic>
```

### 3. Run Binsec

```bash
../binsec/_build/install/default/bin/binsec \
  -sse -sse-script ./binsec_ksm.ini ./core.snapshot \
  -sse-depth 10000
```

## Key Design Choices

### Why symbolize `@[rbx + 0x08, 8]` (slice length)?

The concrete index `i` (parsed from the path component `"1"`) is fixed in the snapshot. The off-by-one occurs when `i == len(s)`. Since `i` is concrete (e.g., `1`), we need to explore paths where `len(s) = 1` (one element, making index 1 equal to the length). Making the `len` field of the slice symbolic achieves this.

In Go's slice representation in memory (at the address held in the data pointer `rbx`):
```
0x00: ptr  uintptr  — pointer to backing array
0x08: len  int      — number of elements  ← symbolized
0x10: cap  int      — capacity
```

### Why `abort at <runtime.panicIndex>`?

`s[i]` when `i == len(s)` triggers `runtime.panicIndex` (the Go runtime's bounds check panic). This is different from the nil pointer bugs which trigger `runtime.panicmem`. Adding this abort point lets Binsec report the path reaching the out-of-bounds access.

### Why `assume slice_len >= 0 && slice_len <= 16`?

This constrains the symbolic length to a reasonable range (a KSM CR list rarely has more than 16 elements), preventing Binsec from exploring unbounded symbolic values that would slow down SMT solving.

## Expected Results

| Finding | Condition | Panic function |
|---------|-----------|---------------|
| 1 | `slice_len = 1`, concrete `i = 1` (i.e., `i == len(s)`) | `runtime.panicIndex` — off-by-one |

This matches the root-cause finding from Zorya (to be confirmed after run).

## Results

> To be completed after running Binsec. Update this section with the actual output and copy the raw log to `binsec-output.txt`.

## Comparison with Other Bug Binsec Runs

| Aspect | geth-graphql-2025 | geth-tracers-2024 | ksm-oob-2025 |
|--------|-------------------|-------------------|--------------|
| Bug type | nil pointer dereference | nil pointer dereference | off-by-one index |
| First instruction | `sync.Mutex.Lock()` | direct struct access | direct slice access |
| VDSO/mutex problem | Yes — all paths killed | No | No |
| Symbolic target | `b.header` pointer | `receipt` pointer | `slice.len` integer |
| Expected panic | `runtime.panicmem` | `runtime.panicIndex` (Finding 3) | `runtime.panicIndex` |
| Expected detection | Not detected | Partially | Expected to detect |

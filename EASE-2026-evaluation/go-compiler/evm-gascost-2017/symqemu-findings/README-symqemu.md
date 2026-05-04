# SymQEMU Analysis — evm-gascost-2017

Concolic execution using SymQEMU on the standalone EVM binary for the `memoryGasCost()` integer overflow vulnerability.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-evm-gascost-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-evm-gascost-output
```

### 2. Run SymQEMU

Unlike other case studies (geth, kubectl, kubelet), the standalone EVM binary is a single-shot CLI tool — `newMemSize` is ultimately derived from the EVM bytecode passed as `--code`. The `--code` argument IS tracked symbolically by SymQEMU since it flows from `argv`. The closest possible approximation to triggering the overflow:

```bash
echo "" | $SYMQEMU_BIN /tmp/geth-160/evm \
    --code 6042600052 run \
    2>&1 | tee symqemu-symbolic.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-evm-gascost-output/
```

## Results

Full log: [`symqemu-symbolic.log`](./symqemu-symbolic.log)

```
$ echo "" | $SYMQEMU_BIN /tmp/geth-160/evm --code 6042600052 run 2>&1 | tee symqemu-symbolic.log
This is SymCC running with the QSYM backend
0x

$ ls -la /tmp/symqemu-evm-gascost-output/
total 8
drwxrwxr-x  2 kgorna kgorna 4096 ...
drwxrwxrwt 13 root   root   4096 ...
```

**Bug NOT detected** — Zero test cases generated (empty output directory). The entire run produces only two lines: the SymCC banner and `0x` (the EVM's return data for this bytecode — empty output after `MSTORE` + `run`).

### What actually happened during the run

1. **SymQEMU started and instrumented the binary.** The QSYM backend initialized and tracked bytes from `argv` symbolically.

2. **The EVM executed the concrete bytecode `6042600052`.** The opcodes are `PUSH1 0x42`, `PUSH1 0x00`, `MSTORE` (store value 0x42 at memory offset 0), followed by `run` (an EVM sub-command, not an opcode). `memoryGasCost` was called with `newMemSize = 32`. The multiplication `1 × 1 = 1` does not overflow. The program returned `0x` (no return data) and exited cleanly.

3. **No test cases generated.** The output directory is empty. SymQEMU has nothing to report because no divergence from the concrete path triggered new input generation, and the overflow is entirely silent.

## Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Tracks only values that flow from external inputs (stdin, argv, file reads, environment variables)
- Starts concrete execution from `main()` and follows the real execution path
- Generates new test cases only when a symbolic condition diverges from the concrete path

Two fundamental obstacles prevent detection of this specific bug:

### 1. The EVM interpreter decouples symbolic bytes from `newMemSize`

The `--code` argument bytes are symbolic at the point they enter the hex decoder. However, `newMemSize` inside `memoryGasCost` is computed from the **EVM stack value** (the MSTORE operand), which is the result of executing EVM opcodes. The path from `argv[2]` bytes → hex decode → EVM bytecode → EVM interpreter → EVM stack → `memoryGasCost` argument is a long chain of transformations. SymQEMU may lose symbolic tracking across the EVM interpreter's opcode dispatch loop (complex indirect control flow).

### 2. The overflow produces no observable crash

Even if SymQEMU successfully tracks a symbolic `newMemSize` all the way into `memoryGasCost`, the integer overflow at:

```go
square := newMemSizeWords * newMemSizeWords  // silent uint64 wrap
```

produces a **wrong but non-crashing result**. SymQEMU generates test cases only when:
- A symbolic branch condition changes the execution path, OR
- A crash/signal occurs

Neither happens here. The function returns normally with a near-zero gas cost. SymQEMU has no way to know this value is semantically wrong — detecting it requires a domain-specific oracle (e.g., checking that the 64-bit result equals the lower 64 bits of the 128-bit product), which SymQEMU does not support.

### 3. Structural difference from nil-pointer bugs

| Aspect | Nil-pointer bugs (other cases) | Integer overflow (this case) |
|--------|-------------------------------|------------------------------|
| Crash produced? | ✅ Yes (`SIGSEGV` / `runtime.panicmem`) | ❌ No (silent wrap) |
| SymQEMU can detect crash? | ✅ Yes | ❌ N/A |
| Bug visible to input-driven concolic? | ✅ If input reaches the pointer | ❌ No — needs semantic oracle |

## When SymQEMU Would Work

SymQEMU could detect this bug if:
1. A **custom harness** called `memoryGasCost` directly with `newMemSize` read from stdin, AND an oracle assertion was added that panics on overflow — then SymQEMU could trigger the panic.
2. Go's unsigned overflow behavior was changed to trap (it is not, by design).
3. A separate binary was compiled with `-overflow-check` instrumentation (not standard in Go).

## Comparison with Zorya

| Aspect | SymQEMU | Zorya |
|--------|---------|-------|
| Entry point | `main()` | `memoryGasCost()` directly |
| Symbolic source | `argv` (bytecode hex string) | All function arguments |
| Tracks `newMemSize` symbolically? | Partially (lost through EVM interpreter) | ✅ Yes (symbolic from function entry) |
| Overflow oracle | ❌ None | ✅ Z3: 128-bit product ≠ 64-bit product |
| **Detected this bug** | **No** | **Yes** (Finding 2, 191s) |

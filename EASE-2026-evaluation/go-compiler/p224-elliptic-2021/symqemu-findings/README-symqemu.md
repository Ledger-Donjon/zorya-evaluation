# SymQEMU Analysis — p224-elliptic-2021

Concolic execution using SymQEMU on the standalone p224 driver binary for
the `p224Contract` carry bug (CVE-2021-3114).

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-p224-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-p224-output
```

### 2. Run SymQEMU

The driver binary reads the P-224 scalar from `argv[1]` as a hex-encoded
string and computes a P-224 scalar multiplication, printing the resulting
curve point as `x=...` / `y=...`. SymQEMU tracks all `argv` bytes
symbolically from the start.

```bash
echo "" | $SYMQEMU_BIN /tmp/p224-driver \
    0000000000000000000000000001 \
    2>&1 | tee symqemu-findings/symqemu-symbolic.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-p224-output/
```

## Results

Full log: [`symqemu-symbolic.log`](./symqemu-symbolic.log)

```
$ echo "" | $SYMQEMU_BIN /tmp/p224-driver 0000000000000000000000000001
This is SymCC running with the QSYM backend
x=3859ecf659e2a2532897a3ebdcffb603bf3c60c091570d5075ec7a9a
y=7b7cb65024250ec781348fbbd758dd010c0df79eee98c15487f343bc

$ ls -la /tmp/symqemu-p224-output/
total 8
drwxrwxr-x  2 kgorna kgorna 4096 ...
drwxrwxrwt 13 root   root   4096 ...
```

**Bug NOT detected** — Zero test cases generated (empty output directory).

The driver ran to completion under SymQEMU. It performed a P-224 scalar
multiplication and printed the resulting curve point coordinates (`x`, `y`),
then exited cleanly with code 0. SymQEMU generated no new inputs.

Note: the `tee` command above reported `No such file or directory` when run
from a directory without a `symqemu-findings/` subdirectory; the log shown
above was captured from stdout.

## Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Tracks only values that flow from external inputs (stdin, `argv`, file
  reads, environment variables)
- Starts concrete execution from `main()` and follows the real execution path
- Generates new test cases only when a symbolic branch diverges from the
  concrete path, or when a crash/signal occurs

Three fundamental obstacles prevent detection:

### 1. The bug produces no crash

The driver executed the full P-224 scalar multiplication — internally calling
`p224Contract` (the vulnerable function) multiple times — and printed
coordinates `x` and `y` without panicking. The wrong field element produced
by the buggy carry arithmetic propagates silently through the computation:

- No branch divergence observable by SymQEMU
- No signal (`SIGSEGV`, `SIGFPE`, etc.)
- No non-zero exit code

SymQEMU's mutation engine has no feedback from the output values — the wrong
curve point is printed to stdout and SymQEMU has no way to know it is
mathematically incorrect.

### 2. The bug is invisible across the full scalar multiplication

The driver computes a point on the P-224 curve using the input scalar. The
arithmetic path is entirely deterministic and branchless — both the buggy and
the correct version follow the same conditional branches for any given input.
SymQEMU generates new inputs only when a symbolic condition causes a
**different branch** from the concrete execution. Since the bug affects only
the output value (not which branches are taken), no divergence is ever
observed.

### 3. Hex-parsing decouples argv bytes from field-element values

The driver converts `argv[1]` from a hex string to a scalar through a
multi-step decode: hex characters → nibbles → bytes → big-endian integer.
Symbolic tracking across this chain can be lossy at:

- Indexed array reads with symbolic indices (Go slice bounds checks with
  symbolic lengths may fork paths that SymQEMU's linearization cannot merge)
- The byte-to-integer assembly step (bytes shifted and ORed into a `uint32`)

Even if tracking survives intact, the absence of a crash means no useful test
case is ever emitted.


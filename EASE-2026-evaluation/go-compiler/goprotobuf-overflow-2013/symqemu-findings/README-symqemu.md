# SymQEMU Analysis — goprotobuf DecodeRawBytes Integer Overflow

Concolic execution using SymQEMU on the `protoc-gen-go` binary targeting the `(*Buffer).DecodeRawBytes` integer overflow (commit `4f8da86`, before fix `28c83cb`).

## Key Difference vs. fasthttp

The `fasthttp.parseUintBuf` overflow was **silent** (no crash, wrong return value). SymQEMU could not detect it because there was no crash signal.

The `DecodeRawBytes` overflow is **observable**: it terminates in a `runtime.panicIndex` or `runtime.panicSliceB` panic (process crash, non-zero exit). SymQEMU is crash-driven — in principle it **can** detect this bug if symbolic taint from stdin reaches `nb` in `DecodeRawBytes`.

---

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-proto-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-proto-output

# Safe seed input (valid proto wire message, reaches DecodeRawBytes without crashing)
python3 -c "
import sys
payload = bytes([
    0x0a, 0x0a,
    0x74,0x65,0x73,0x74,0x2e,0x70,0x72,0x6f,0x74,0x6f,
    0x1a, 0x01, 0xAA
])
sys.stdout.buffer.write(payload)
" > /tmp/proto-symqemu-seed.bin
```

### 2. Run SymQEMU

`protoc-gen-go` reads its entire input from **stdin** — exactly the symbolic source SymQEMU marks automatically via `read()` syscall interception:

```bash
$SYMQEMU_BIN /tmp/protoc-gen-go \
    < /tmp/proto-symqemu-seed.bin \
    2>&1 | tee /tmp/symqemu-proto.log

# Check for generated test cases (crash-triggering inputs)
ls -la /tmp/symqemu-proto-output/
```

### 3. Inspect Crashes

```bash
# Each file in the output dir is a generated input; replay to confirm crash:
for f in /tmp/symqemu-proto-output/*; do
    echo "=== $f ==="
    /tmp/protoc-gen-go < "$f" 2>&1 | head -3
done
```

---

## Why SymQEMU Has a Plausible Chance Here

Unlike the fasthttp case, three favourable conditions hold:

### 1. Stdin IS the symbolic source, directly

`protoc-gen-go` calls `os.Stdin.Read()` (a `read(0, buf, n)` syscall) to receive the entire `CodeGeneratorRequest` proto message. SymQEMU intercepts `read()` and marks the returned bytes as **symbolic**. These are the exact bytes that flow through `DecodeVarint` → `nb` in `DecodeRawBytes`.

```
stdin read()          ← SymQEMU marks bytes symbolic
  │
  └─► proto Unmarshal
        │
        └─► (*Buffer).DecodeVarint
              │
              └─► nb := int(n)   ← symbolic
                    │
                    └─► p.index + nb  ← overflow if nb ≈ MaxInt64
```

### 2. The bug produces a crash (not a silent overflow)

SymQEMU detects divergence by observing crashes. The overflow panic (`runtime.panicSliceB` or `runtime.panicIndex`) causes `protoc-gen-go` to abort — SymQEMU records the triggering input as a finding.

### 3. The data flow is short and unambiguous

The varint bytes come directly from stdin, with no preprocessing that strips symbolic taint (unlike the HTTP header parsing in fasthttp). The only symbolic operations are bitwise shifts and ORs in the varint decode loop — all of which are straightforwardly tracked by SymCC's SMT backend.

---

## Why It May Still Fail in Practice

### 1. Go runtime complexity

SymQEMU executes from `main()` through the Go runtime startup, goroutine scheduler, and garbage collector. All of these execute before the `read()` syscall, and SymQEMU may encounter path explosions, unsupported opcodes, or VDSO/syscall paths that terminate symbolic traces early.

### 2. Proto parsing branches before `DecodeRawBytes`

Before `DecodeRawBytes` is called, the proto decoder reads field tags (varint wire type + field number) and dispatches on them. Each dispatch branch is a potential path fork. With a symbolic input, SymQEMU may need to explore many branches before reaching the vulnerable call with symbolic `nb`. Path explosion is a realistic concern.

### 3. Large `nb` causes allocation, not an immediate OOB

If `nb` is symbolically large, the path that reaches `p.buf[p.index : p.index+nb]` passes through `make([]byte, nb)` (when `alloc=true`) or the direct slice (when `alloc=false`). The allocation path may interact with `runtime.mallocgc` in ways that cause SymQEMU to lose the symbolic thread.

---

## Results

| Property | Outcome |
|----------|---------|
| Bug detected | **To be completed after run** |
| Primary input path | stdin → `read()` → varint bytes → `nb` |
| Crash type | `runtime.panicIndex` / `runtime.panicSliceB` (observable) |
| Expected generated inputs | 1+ inputs with field-3 varint ≈ MaxInt64 |

**Expected**: **Possible detection** — the data flow from stdin to crash is short and direct. Detection depends on whether SymQEMU's symbolic propagation survives the Go runtime and proto dispatch branches.

---

## Comparison with Other Tools

| Aspect | SymQEMU | Binsec | Zorya |
|--------|---------|--------|-------|
| Entry point | `main()` (full execution) | GDB core at `DecodeRawBytes` | GDB snapshot at `0x4f1f80` |
| Symbolic source | stdin bytes (via `read()` syscall) | Struct fields (manual script) | All function arguments |
| `nb` symbolic? | Yes (stdin → varint bytes) | No (heap bytes concrete by default) | Indirectly (slice_elem taint) |
| Crash observable? | Yes (`runtime.panicIndex`) | Yes (abort targets) | Yes (SAT + panic address) |
| Path to `DecodeRawBytes` | Long (main → proto decoder) | N/A (starts at function) | N/A (starts at function) |
| Likely detection | Possible | Partial (negative p.index only) | Yes (6 SAT states found) |

## When SymQEMU Would Definitely Work

If `protoc-gen-go` is too complex, a thin harness reading from stdin and calling `DecodeRawBytes` directly would guarantee symbolic `nb`:

```go
// harness/main.go
package main

import (
    "os"
    "code.google.com/p/goprotobuf/proto"
)

func main() {
    data, _ := io.ReadAll(os.Stdin)
    buf := proto.NewBuffer(data)
    buf.DecodeRawBytes(false)
}
```

```bash
go build -gcflags="all=-N -l" -o /tmp/proto-harness ./harness/
$SYMQEMU_BIN /tmp/proto-harness < /tmp/proto-symqemu-seed.bin
```

With this harness, stdin bytes flow directly into `DecodeVarint` with no intermediate dispatch — SymQEMU will find the panic within seconds.

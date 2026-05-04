# Binsec Analysis — goprotobuf DecodeRawBytes Integer Overflow

Binary-level symbolic execution using Binsec on the `protoc-gen-go` binary targeting the `(*Buffer).DecodeRawBytes` integer overflow.

## Key Characteristic vs. fasthttp

Unlike `fasthttp.parseUintBuf` (silent overflow, no crash), the `DecodeRawBytes` bug produces **observable crashes**:

- Negative `p.index` → `DecodeVarint` calls `p.buf[p.index]` → `runtime.panicIndex`
- `p.index + nb` overflow (wraparound) → `p.buf[p.index : p.index+nb]` → `runtime.panicSliceB`

Because the bug materialises as a panic (`runtime.panicIndex` or `runtime.panicSliceB`), Binsec's standard `abort at` methodology **can** detect it — provided the right inputs are symbolised.

---

## Commands Used

### 1. Create Memory Snapshot with GDB

Take the snapshot at `DecodeRawBytes` entry (`0x4f1f80`) using the safe stdin payload so GDB actually reaches the breakpoint:

```bash
# Generate safe stdin (field 1 = "test.proto", field 3 with nb=1)
python3 -c "
import sys
payload = bytes([
    0x0a, 0x0a,
    0x74,0x65,0x73,0x74,0x2e,0x70,0x72,0x6f,0x74,0x6f,
    0x1a, 0x01, 0xAA
])
sys.stdout.buffer.write(payload)
" > /tmp/proto-safe-input.bin

# Break at DecodeRawBytes entry and snapshot
gdb /tmp/protoc-gen-go
(gdb) break *0x4f1f80
(gdb) run < /tmp/proto-safe-input.bin
# GDB stops at DecodeRawBytes — take snapshot
(gdb) delete breakpoints
(gdb) generate-core-file /tmp/binsec-proto.core
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_proto.ini`

```ini
starting from core

; Go register ABI (gc compiler):
;   RAX = p_ptr  (*Buffer receiver)
;   RBX = alloc  (bool argument)
;
; proto.Buffer struct layout (proto/lib.go at commit 4f8da86):
;   +0x00  buf       []byte  (ptr 8B, len 8B, cap 8B)
;   +0x18  index     int
;   +0x20  freelist  [][]byte
;   +0x38  nfreelist int
;   (further fields: int32s, uint32s, … — not relevant here)
;
; Symbolize the fields that govern DecodeRawBytes behaviour:

@[rax + 0x00, 8] := nondet as p_buf_ptr   ; p.buf data pointer
@[rax + 0x08, 8] := nondet as p_buf_len   ; p.buf length
@[rax + 0x10, 8] := nondet as p_buf_cap   ; p.buf capacity
@[rax + 0x18, 8] := nondet as p_index     ; p.index (signed int)

; Reasonable constraints
assume p_buf_len >= 0 && p_buf_len <= 0x10000
assume p_buf_cap >= p_buf_len
; Allow full signed int64 range for p.index (including negative values)
assume p_index >= -0x8000000000000000 && p_index <= 0x7fffffffffffffff

rbx := nondet as alloc   ; also symbolize the bool argument

explore all

; Stub Go runtime stack-growth / slice-growth helpers that cause early path cuts
replace <runtime.morestack>            by return end
replace <runtime.morestack_noexit>     by return end
replace <runtime.growslice>            by return end

; Panic abort targets
abort at <runtime.panicIndex>
abort at <runtime.panicSliceB>
abort at <runtime.panicmem>
abort at <runtime.gopanic>
abort at <runtime.panicOverflow>
abort at <runtime.panicdivide>
```

### 3. Run Binsec

```bash
binsec -sse -sse-script binsec_proto.ini \
       -sse-depth 20000 \
       -sse-timeout 600 \
       /tmp/binsec-proto.core
```

---

## What Binsec Can and Cannot Find

### ✅ Detectable — Negative `p.index` → `runtime.panicIndex`

`p.index` is a struct field read from memory at `rax + 0x18`. Binsec symbolises it directly. When `p.index < 0`:

```
DecodeVarint:
  i := p.index        // i < 0
  if i >= len(p.buf)  // negative < 0  →  FALSE (no early return)
  p.buf[i]            // runtime.panicIndex  💥
```

The `if i >= l` guard silently passes for negative `i`. Binsec's symbolic engine explores `p_index < 0` and finds the panic path to `runtime.panicIndex`.

**Predicted finding**: SAT with `p_index = INT64_MIN` (or any negative value).

### ❌ Likely Not Detectable — `p.index + nb` Overflow

The `nb` value is decoded by `DecodeVarint` by reading bytes from `p.buf` (the heap backing array pointed to by `p_buf_ptr`). These bytes are **concrete** in the GDB snapshot (they contain the safe payload `0xAA, 0x01, ...`). Binsec symbolises registers and named struct fields but does **not** automatically extend symbolisation to the heap bytes at an arbitrary pointer.

Without symbolic heap bytes, `nb` decodes to a concrete value (e.g., `1`). The overflow `p.index + nb > MaxInt` then requires `p.index` to be near `MaxInt - 1`, which Binsec may explore — but the combination of a concrete small `nb` and a large `p.index` may not yield the exact overflow path the fix addresses (large `nb`, any `p.index`).

To force detection of the `nb`-overflow path, the heap bytes at `p_buf_ptr` would need to be symbolised manually:

```ini
; Symbolize the first 16 bytes of p.buf (the varint bytes)
; Requires knowing the concrete value of p_buf_ptr from the snapshot (e.g., via GDB 'info registers')
@[0xC000XXXX, 16] := nondet as proto_wire_bytes
```

This is technically possible but requires reading the concrete `p_buf_ptr` value from the snapshot and patching the script accordingly.

---

## Results

| Finding | Condition | Panic function | Detectable? |
|---------|-----------|---------------|-------------|
| Negative `p.index` | `p_index < 0`, `p_buf_len >= 0` | `runtime.panicIndex` | **Yes** (struct field symbolised) |
| `p.index + nb` overflow | `p_index + nb > MaxInt64` | `runtime.panicSliceB` | **Partially** (requires heap symbolisation) |

## Comparison with Zorya

| Aspect | Binsec | Zorya |
|--------|--------|-------|
| Entry point | GDB core snapshot at `DecodeRawBytes` | GDB snapshot at `0x4f1f80` via `--mode function` |
| Symbolic source | Struct fields (`rax+offset`) | All function arguments + struct fields |
| Heap bytes symbolic? | No (manual script patch required) | No (varint loop taint via `slice_elem`) |
| Negative `p.index` crash | **Detectable** | Found (Findings 1–4) |
| `nb`-overflow crash | Partial (needs heap patch) | Partially (Finding 3 via large `p.index`) |
| Silent overflow detection | N/A (crash here, not silent) | N/A |

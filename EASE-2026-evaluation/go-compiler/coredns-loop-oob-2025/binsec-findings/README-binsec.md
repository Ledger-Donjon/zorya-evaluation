# BINSEC Analysis — CoreDNS Loop Plugin OOB Panic

## Overview

Unlike silent arithmetic bugs (p224, fasthttp overflow), the CoreDNS loop plugin bug
produces a **hard crash** (`runtime.panicIndex`). No arithmetic oracle is needed — aborting
at `<runtime.panicIndex>` is sufficient.

## Commands

```bash
# 1. Build the vulnerable binary
cd /home/kgorna/go-projects/coredns && git checkout 0d05791
GO111MODULE=on go build -gcflags="all=-N -l" -o /tmp/coredns-vulnerable .

# 2. Create a benign Corefile
cat > /tmp/Corefile.benign << 'EOF'
example.com:5353 {
    loop
    forward . 8.8.8.8
}
EOF

# 3. Take a GDB core snapshot at parse() entry
gdb -q /tmp/coredns-vulnerable \
  -ex "set confirm off" \
  -ex "break 'github.com/coredns/coredns/plugin/loop.parse'" \
  -ex "run -conf /tmp/Corefile.benign" \
  -ex "generate-core-file /tmp/coredns-loop.snapshot" \
  -ex "quit"
# Actual output: Breakpoint 1 at 0x2f73533: file plugin/loop/setup.go, line 63.
# Saved corefile /tmp/coredns-loop.snapshot

# 4. Find the controller pointer (RAX at parse() entry)
RAX=$(gdb -q /tmp/coredns-vulnerable /tmp/coredns-loop.snapshot -batch \
  -ex "frame 0" \
  -ex "info register rax" 2>/dev/null \
  | grep "^rax" | awk '{print $2}')
echo "Controller pointer: $RAX"
# Actual output: Controller pointer: 0xc00027cbd0

# 5. Find the concrete data pointer of "example.com:5353" in the snapshot
gdb -q /tmp/coredns-vulnerable /tmp/coredns-loop.snapshot -batch \
  -ex "x/s 0xc000154ed0" \
  -ex "x/s 0xc000154eee" \
  -ex "x/s 0xc0002c5000" \
  -ex "x/s 0xc00038bde0" \
  -ex "x/s 0xc00038be20" \
  -ex "x/s 0xc00038be30" \
  -ex "x/s 0xc000863000" \
  2>/dev/null | grep -E "^0xc|example"
# Actual result includes:
#   0xc000154ed0: "example.com:5353"
# Use 0xc000154ed0 as sbk_data_ptr.

# 6. Patch the ini file
SBK_PTR=0xc000154ed0
sed -i "s/0xc000REPLACE/${SBK_PTR}/g" /home/kgorna/tests/binsec_loop.ini

# 7. Run BINSEC
cd /home/kgorna/tests
../binsec/_build/install/default/bin/binsec \
  -sse \
  -sse-script binsec_loop.ini \
  -sse-depth 20000 \
  /tmp/coredns-loop.snapshot
```

## Why `0xc000REPLACE` caused the parse error

```
[sse:fatal] Parse error at word `REPLACE+0x00, '
"@[0xc000REPLACE+0x00, 1] := nondet as sb0"
```

`0xc000REPLACE` is a placeholder in `binsec_loop.ini`. BINSEC requires a **literal hex
address** (for this snapshot: `0xc000154ed0`) — it cannot evaluate placeholders.

## Key Design Choices

### Starting point: `parse()` entry (0x2f73533)
The concrete snapshot provides a valid `c *caddy.Controller` (at `0xc00027cbd0`) with
all Caddy framework state already initialised.

### Symbolizing `c.ServerBlockKeys[0]`
The first 7 bytes of the zone string determine whether `NormalizeExact()` returns an empty
slice. We symbolize those bytes to explore both the `"unix://"` path (empty return →
`zones[0]` panics) and the normal zone path.

### Abort at `runtime.panicIndex`
```
zones[0]  →  runtime.panicIndex  (when len(zones) == 0)
```
No postcondition oracle needed — the crash is the observable event.

## Actual BINSEC Output

```
[sse:info] TTY: press [space] to switch between log and monitor modes.
[sse:error] Cut path 11 (uninterpreted "f2 48 0f 2a c1 # cvtsi2sd %rcx,%xmm0") @ 0x41eafc
[sse:info] SMT queries
             Preprocessing simplifications
               total          70
               sat            70
               unsat          0
               time           0.00

             Satisfiability queries
               total          40
               sat            15
               unsat          25
               unknown        0
               time           1328.23
               average        33.21

           Exploration
             total paths                      16
             completed/cut paths              0
             pending paths                    15
             discontinued paths               1
             failed assertions                0
             branching points                 144
             max path depth                   1284
             visited instructions (unrolled)  1335
             visited instructions (static)    4328
```

Interpretation:
- BINSEC did **not** reach `abort at <runtime.panicIndex>` in this run (`failed assertions: 0`).
- One path was discontinued due an uninterpreted instruction (`cvtsi2sd`) at `0x41eafc`.
- The run ended with many pending paths (`15`), so this result is **inconclusive / not detected yet** for this configuration.

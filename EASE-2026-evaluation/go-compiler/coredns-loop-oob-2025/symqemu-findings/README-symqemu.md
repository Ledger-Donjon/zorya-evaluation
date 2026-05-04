# SymQEMU Analysis — CoreDNS Loop Plugin OOB Panic

## Overview

Unlike the p224 elliptic-curve carry bug (where SymQEMU produced zero test cases because there was no crash to guide new input generation), the CoreDNS loop plugin bug causes a **hard `runtime.panicIndex` crash**. This means SymQEMU's concolic engine has a clear signal — a diverging branch or a crashing execution — to drive input mutation. In principle, SymQEMU should find this bug.

## Commands

```bash
# Environment setup
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-coredns-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-coredns-output

# Build the vulnerable CoreDNS binary
cd coredns && git checkout 0d05791
go build -gcflags="all=-N -l" -o /tmp/coredns-vulnerable .

# Create the trigger Corefile
cat > /tmp/Corefile.trigger << 'EOF'
unix:///tmp/coredns.sock {
    loop
    forward . 8.8.8.8
}
EOF

# Run SymQEMU — pass the Corefile path as an argument
$SYMQEMU_BIN /tmp/coredns-vulnerable -conf /tmp/Corefile.trigger \
  2>&1 | tee symqemu-findings/symqemu-symbolic.log
```

## How the Bug Reaches SymQEMU

The Corefile is read from disk by CoreDNS at startup via Caddy's configuration parser. The **input to symbolize** is the content of `/tmp/Corefile.trigger` — specifically the server block key `unix:///tmp/coredns.sock`.

However, SymQEMU's default mode symbolizes **stdin or `argv`** — not files read via `open()`. Since CoreDNS reads the Corefile by filename from `argv[2]` (`-conf <path>`), SymQEMU would need to:

1. Symbolize the Corefile content via a named pipe or `/dev/stdin` trick, **or**
2. Rely on branch coverage from the concrete execution to generate new inputs that mutate the Corefile path/content

## Actual Behaviour (observed)

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-coredns-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-coredns-output

$SYMQEMU_BIN /tmp/coredns-vulnerable -conf /tmp/Corefile.benign
```

```
This is SymCC running with the QSYM backend
maxprocs: Leaving GOMAXPROCS=24: CPU quota undefined
example.com.:5353
CoreDNS-1.12.4
linux/amd64, go1.24.0,
^C[INFO] SIGINT: Shutting down
```

```bash
ls /tmp/symqemu-coredns-output/
# (empty — no test cases generated)
```

**Result: zero test cases generated.** SymQEMU ran successfully (CoreDNS started and served DNS) but produced no new inputs. The Corefile bytes are read from disk via `open()`/`read()` syscalls; SymQEMU does not symbolize file reads by default, so the configuration bytes remain **concrete** throughout execution. With no symbolic branch to solve, the QSYM backend generates no alternative inputs and the bug is not found.


## Challenge: File-Based Input

The main challenge for SymQEMU is that CoreDNS reads its configuration from a **file path** argument, not from stdin or a command-line string. SymQEMU must track taint through the `open`/`read` syscalls for the Corefile. Some SymQEMU configurations mark all `read()` returns as symbolic by default; others require explicit taint source specification.

If SymQEMU does not taint file reads by default, the Corefile bytes will remain concrete and SymQEMU will produce zero new inputs (same as the p224 case, but for a different reason).

A `/dev/stdin` workaround was attempted to force bytes through a pipe (which SymQEMU can
symbolize via `read` on fd 0):

```bash
echo 'unix:// {
    loop
    forward . 8.8.8.8
}' | $SYMQEMU_BIN /tmp/coredns-vulnerable -conf /dev/stdin \
  2>&1 | tee symqemu-findings/symqemu-symbolic.log
```

**Actual output:**

```
This is SymCC running with the QSYM backend
maxprocs: Leaving GOMAXPROCS=24: CPU quota undefined
error inspecting server blocks: expecting data after last colon: ""
```

**Why it still fails**: `unix://` (bare, without a socket path) is rejected by Caddy's
Corefile parser as syntactically invalid *before* the loop plugin's `parse()` is ever called.
The vulnerable `zones[0]` line is never reached. The real trigger requires Caddy to internally
normalize a valid unix-socket server block (e.g. `unix:///tmp/coredns.sock`) into the bare
`"unix://"` key that is then stored in `c.ServerBlockKeys` — a transformation that happens
*inside* Caddy's own parser, deep in the Go call stack, with no clean way to inject a
symbolized equivalent via stdin or argv.

**Conclusion**: SymQEMU cannot find this bug due to two independent blockers:
1. File-based Corefile input is not symbolized by default (zero new inputs from `-conf file`)
2. The `/dev/stdin` bypass is rejected by the Caddy parser before the vulnerable code is reached

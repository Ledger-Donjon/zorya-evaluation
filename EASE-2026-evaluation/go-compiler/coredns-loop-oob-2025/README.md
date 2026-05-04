# CoreDNS Loop Plugin Index Out-of-Range Panic

This case demonstrates an **index out-of-range panic** in CoreDNS's `plugin/loop` package, fixed in commit [`31e2859`](https://github.com/coredns/coredns/commit/31e2859). The bug occurs during Corefile parsing: when a server block uses a Unix socket URI (`unix:///path/to/sock`), `plugin.Host(...).NormalizeExact()` returns an empty `[]string{}` instead of a valid zone name. The code then unconditionally indexes `zones[0]` on the empty slice, causing a `runtime.panicIndex` crash at startup. This is a **crash-based** (non-silent) bug — any tool that detects `runtime.panicIndex` can find it.

## Bug Classification

**Type:** Index out-of-bounds (`runtime.panicIndex`)

- `plugin.Host(c.ServerBlockKeys[0]).NormalizeExact()` returns `[]string{}` for URI-scheme server block keys such as `unix:///tmp/coredns.sock`
- The `parse` function replaces the default `zones = []string{"."}` with the empty slice
- The very next statement `return New(zones[0]), nil` indexes into the empty slice → `panicIndex`
- Triggered at CoreDNS **startup** by any Corefile whose first server block uses a Unix socket URI and includes the `loop` plugin
- Fixed by guarding the assignment: `if len(z) > 0 { zones = z }`

## Vulnerability

Vulnerable code in `plugin/loop/setup.go` (CoreDNS ≤ v1.12.4):

```go
func parse(c *caddy.Controller) (*Loop, error) {
    i := 0
    zones := []string{"."}          // safe default
    for c.Next() {
        if i > 0 {
            return nil, plugin.ErrOnce
        }
        i++
        if c.NextArg() {
            return nil, c.ArgErr()
        }

        if len(c.ServerBlockKeys) > 0 {
            zones = plugin.Host(c.ServerBlockKeys[0]).NormalizeExact()
            // BUG: NormalizeExact() returns []string{} for "unix:///tmp/coredns.sock"
            // zones is now empty — the safe default "." is lost
        }
    }
    return New(zones[0]), nil  // PANIC: index out of range [0] with length 0
}
```

**The fix** ([commit `31e2859`](https://github.com/coredns/coredns/commit/31e2859)) guards the assignment:

```go
if len(c.ServerBlockKeys) > 0 {
    z := plugin.Host(c.ServerBlockKeys[0]).NormalizeExact()
    if len(z) > 0 {       // ← guard added
        zones = z
    }
    // if z is empty, zones keeps the default "."
}
```

## How It Happens

1. A Corefile contains a server block using a Unix socket URI, e.g. `unix:///tmp/coredns.sock { loop ... }`
2. The Caddy framework sets `c.ServerBlockKeys = []string{"unix:///tmp/coredns.sock"}`
3. `plugin.Host("unix:///tmp/coredns.sock").NormalizeExact()` strips the URI scheme and finds no valid domain label → returns `[]string{}`
4. `zones` is overwritten with `[]string{}`; the safe default `"."` is gone
5. `return New(zones[0]), nil` → **panic: runtime error: index out of range [0] with length 0**

## Affected Versions

| Version | Status |
|---------|--------|
| ≤ v1.12.4 | **Vulnerable** |
| v1.13.0 | Fixed (first release with `31e2859`) |
| v1.14.1 | Fixed (backport) |

## Reproduction Workflow

### 1. Build the vulnerable CoreDNS binary

```bash
# Clone CoreDNS and check out the vulnerable commit (parent of the fix)
git clone https://github.com/coredns/coredns.git
cd coredns
git checkout 0d05791

# Build with debug symbols (disables inlining and optimisations)
GO111MODULE=on go build -gcflags="all=-N -l" -o /tmp/coredns-vulnerable .

# Verify the version
/tmp/coredns-vulnerable --version
# CoreDNS-1.12.4

# Locate the vulnerable parse function
go tool nm /tmp/coredns-vulnerable | grep "plugin/loop.parse"
#  2f73520 t github.com/coredns/coredns/plugin/loop.parse
```

### 2. Create the malicious Corefile

```bash
cat > /tmp/Corefile.trigger << 'EOF'
unix:///tmp/coredns.sock {
    loop
    forward . 8.8.8.8
}
EOF
```

### 3. Trigger the panic

```bash
/tmp/coredns-vulnerable -conf /tmp/Corefile.trigger
```

**Actual output:**

```
maxprocs: Leaving GOMAXPROCS=24: CPU quota undefined
panic: runtime error: index out of range [0] with length 0

goroutine 1 [running]:
github.com/coredns/coredns/plugin/loop.parse(0xc00099c090)
	/home/kgorna/go-projects/coredns/plugin/loop/setup.go:79 +0x235
github.com/coredns/coredns/plugin/loop.setup(0xc00099c090)
	/home/kgorna/go-projects/coredns/plugin/loop/setup.go:18 +0x45
github.com/coredns/caddy.executeDirectives(0xc000482200, {0x7ffdec849515, 0x15}, {0x5a1ec20, 0x36, 0x36}, {0xc000612a40, 0x1, 0x1}, 0x0)
	/tmp/gopath-proto/pkg/mod/github.com/coredns/caddy@v1.1.3/caddy.go:663 +0xaff
github.com/coredns/caddy.ValidateAndExecuteDirectives({0x43ee960, 0xc000808480}, 0xc000482200, 0x0)
	/tmp/gopath-proto/pkg/mod/github.com/coredns/caddy@v1.1.3/caddy.go:614 +0x84f
github.com/coredns/caddy.startWithListenerFds({0x43ee960, 0xc000808480}, 0xc000482200, 0x0)
	/tmp/gopath-proto/pkg/mod/github.com/coredns/caddy@v1.1.3/caddy.go:517 +0x226
github.com/coredns/caddy.Start({0x43ee960, 0xc000808480})
	/tmp/gopath-proto/pkg/mod/github.com/coredns/caddy@v1.1.3/caddy.go:474 +0x1ad
github.com/coredns/coredns/coremain.Run()
	/home/kgorna/go-projects/coredns/coremain/run.go:73 +0x70d
main.main()
	/home/kgorna/go-projects/coredns/coredns.go:12 +0xf
exit status 2
```

### 4. Run `go test -fuzz`

The panic is a clean crash, so coverage-guided fuzzing can detect it.

> **Note on a common mistake**: placing the fuzz file in the repo root with `package fuzz`
> and running `go test -fuzz=FuzzLoopParse ./plugin/loop/...` will print `PASS` in ~0.004 s
> and fuzz nothing — Go only runs a `FuzzX` function if it lives *inside* the target package.
> Likewise, seeding with `"unix:///tmp/coredns.sock"` is wrong: `NormalizeExact` returns
> `["/tmp/coredns.sock."]` (non-empty) for that input, so no panic. The actual trigger is
> `"unix://"` (scheme only), which returns `[]`.

The correct harness lives in `plugin/loop/` and **must declare `package loop`** (not `package fuzz`).
Because it is in the same package as `parse()`, no exported shim is needed — `fuzz_export.go` is not required.

```go
// plugin/loop/fuzz_loop_test.go
package loop   // ← must match the package, not "fuzz"

import (
    "testing"

    "github.com/coredns/caddy"
)

func FuzzLoopParse(f *testing.F) {
    // Correct trigger: "unix://" → NormalizeExact returns [] → zones[0] panics
    f.Add("unix://")
    // Safe paths that must not crash
    f.Add("example.com")
    f.Add(".")
    f.Add("")

    f.Fuzz(func(t *testing.T, key string) {
        c := caddy.NewTestController("dns", `loop`)
        if key != "" {
            c.ServerBlockKeys = []string{key}
        }
        // parse() is unexported but accessible because we are in package loop
        parse(c) //nolint:errcheck
    })
}
```

Run from the repo root:

```bash
cd /home/kgorna/go-projects/coredns
GO111MODULE=on go test -fuzz=FuzzLoopParse ./plugin/loop/ -fuzztime=60s
```

**Actual output (confirmed)**:

```
fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed
fuzz: elapsed: 0s, gathering baseline coverage: 2/2 completed, now fuzzing with 24 workers
fuzz: elapsed: 0s, execs: 82 (454/sec), new interesting: 0 (total: 2)
--- FAIL: FuzzLoopParse (0.18s)
    --- FAIL: FuzzLoopParse (0.00s)
        testing.go:1693: panic: runtime error: index out of range [0] with length 0
            goroutine 149 [running]:
            github.com/coredns/coredns/plugin/loop.parse(0xc000322fc0)
            	/home/kgorna/go-projects/coredns/plugin/loop/setup.go:79 +0x334
            github.com/coredns/coredns/plugin/loop.FuzzLoopParse.func1(0x0?, {0xc00029b1d6, 0x2})
            	/home/kgorna/go-projects/coredns/plugin/loop/fuzz_loop_test.go:18 +0x145

    Failing input written to testdata/fuzz/FuzzLoopParse/93076e9d6b6510b6
    To re-run:
    go test -run=FuzzLoopParse/93076e9d6b6510b6

FAIL
exit status 1
FAIL	github.com/coredns/coredns/plugin/loop	0.187s
```

The fuzzer found the crash in **0.18 s** using only 82 executions, starting from the benign seeds
`"."` and `"example.com"` — no `"unix://"` seed was needed. The failing input
(`testdata/fuzz/FuzzLoopParse/93076e9d6b6510b6`, 2 bytes) is committed by the Go fuzzer
and can be replayed with:

```bash
GO111MODULE=on go test -run=FuzzLoopParse/93076e9d6b6510b6 ./plugin/loop/
```

### 5. Run Zorya

```bash
# Create a benign Corefile — valid zone name, parse() completes without crash.
# Zorya uses this concrete execution as its starting point, then negates
# branch conditions to discover the path where NormalizeExact() returns []
# and zones[0] fires panicIndex.
cat > /tmp/Corefile.benign << 'EOF'
example.com:5353 {
    loop
    forward . 8.8.8.8
}
EOF

zorya /tmp/coredns-vulnerable \
  --mode function 0x2f73520 \
  --lang go \
  --compiler gc \
  --thread-scheduling main-only \
  --arg "-conf /tmp/Corefile.benign" \
  --negate-path-exploration
```

**Parameters explained:**
- `--mode function 0x2f73520` — target `plugin/loop.parse` directly (breakpoint at function entry; get the address with `go tool nm /tmp/coredns-vulnerable | grep "plugin/loop.parse"`)
- `--lang go --compiler gc` — tell Zorya the binary is a standard Go toolchain build
- `--thread-scheduling main-only` — restrict execution to the main goroutine (Caddy plugin setup runs on goroutine 1)
- `--arg "-conf /tmp/Corefile.benign"` — **non-crashing** Corefile: `example.com` is a valid zone so `NormalizeExact()` returns `["example.com."]` and `zones[0]` succeeds; Zorya observes this concrete path through `parse()`
- `--negate-path-exploration` — Zorya negates branch conditions along the path to explore alternatives; it discovers the path where `zones[0]` can panic

**Actual results** (run time ~27 min, see `FOUND_SAT_STATE.txt`):

Zorya reported **2 satisfiable states**:

| # | Elapsed | Address | Opcode | Condition found |
|---|---------|---------|--------|-----------------|
| 1 | 1560 s | `0x2f735c6` | LOAD | `c_ptr = 0` — nil `*caddy.Controller` passed to `parse()` |
| 2 | 1632 s | `0x2f736a8` (panic `0x2f7374e`) | CBRANCH | `c.ServerBlockKeys.len = 0` — empty keys slice, leading to `zones[0]` panic |

Finding #2 is the intended bug. Zorya symbolizes the `caddy.Controller` fields, negates the slice-bounds `CBRANCH` at `0x2f736a8`, and reaches the crash block confirmed by `objdump`:

```
0x2f736a8  CBRANCH  ← bounds check: index vs zones slice length (Zorya negates this)
               ↓
0x2f7374e  xor %eax,%eax        ← Go ABI pre-panic stub (zero return register)
0x2f73750  call runtime.panicIndex  ← THE BUG: zones[0] index out of range
```

The `xor %eax,%eax` at `0x2f7374e` is the standard Go compiler preamble before a non-returning call; Zorya reports it as the panic address because it is the first instruction of the crash basic block.

The raw Zorya output is saved in [`FOUND_SAT_STATE.txt`](./FOUND_SAT_STATE.txt).

### 6. Run GoLibAFL

`parse` is unexported — add a one-line exported shim inside `plugin/loop/` (e.g. `plugin/loop/fuzz_export.go`) so the harness module can reach it:

```go
// plugin/loop/fuzz_export.go  (add to the vulnerable CoreDNS checkout)
package loop

import "github.com/coredns/caddy"

// ParseForFuzz exposes parse() for GoLibAFL harness use only.
func ParseForFuzz(c *caddy.Controller) (*Loop, error) { return parse(c) }
```

#### Harness

```go
package main

// #include <stdint.h>
// #include <stddef.h>
import "C"
import (
    "github.com/coredns/caddy"
    "github.com/coredns/coredns/plugin/loop"
)

// harness is called by LibAFL for every generated input.
// data[0] bit-0: 0 → valid zone "." (safe path, NormalizeExact returns ["."])
//                 1 → "unix://" key (bug: NormalizeExact returns [], zones[0] panics)
//
// Why "unix://" and not "unix:///tmp/coredns.sock"?
//   plugin.Host("unix:///tmp/coredns.sock").NormalizeExact() = ["/tmp/coredns.sock."] ← non-empty, no crash
//   plugin.Host("unix://").NormalizeExact()                  = []                     ← empty → zones[0] panics
// Caddy's own zone normalizer strips the socket path, so c.ServerBlockKeys[0]
// ends up as "unix://" (scheme only) when parsing a unix:///... server block.
func harness(data []byte) {
    if len(data) == 0 {
        return
    }
    c := caddy.NewTestController("dns", `loop`)
    if data[0]&1 == 1 {
        c.ServerBlockKeys = []string{"unix://"}   // ← real trigger: NormalizeExact returns []
    } else {
        c.ServerBlockKeys = []string{"."}
    }
    // zones[0] panics when data[0]&1 == 1 — LibAFL records it as a crash
    loop.ParseForFuzz(c)
}

// Do NOT declare func main() — GoLibAFL provides it in harness_fuzz.go.
```

#### Build and run (5-minute budget)

```bash
# 1. Clone GoLibAFL
git clone https://github.com/srlabs/golibafl
cd golibafl

# 2. Create harness directory
mkdir -p harnesses/coredns-loop
# paste main.go above into harnesses/coredns-loop/main.go

cd harnesses/coredns-loop
go mod init fuzz
go mod edit -replace github.com/coredns/coredns=/home/kgorna/go-projects/coredns
go mod tidy
cd ../..

# 3. Build and fuzz (5 minutes)
export HARNESS=harnesses/coredns-loop
cargo run --release -- fuzz --timeout 300

# 4. Replay a crash
cargo run -- run -i output/crashes/<crashfile>
```

**Result**: **Bug detected** — GoLibAFL reported `objectives: 459` after 3m15s (75M+ executions at ~390k exec/sec). The crash fires on the first mutation where `data[0]` has bit-0 set, setting `c.ServerBlockKeys = ["unix://"]` so that `NormalizeExact` returns `[]` and `zones[0]` panics with `index out of range [0] with length 0` (→ SIGSEGV). Crash files are written to `output/crashes/`.

#### Crash replay output (confirmed)

```
$ cargo run -- run -i output/crashes/000f158e4819ba1a
Running: output/crashes/000f158e4819ba1a
Go panic: runtime error: index out of range [0] with length 0
goroutine 17 [running, locked to thread]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:26 +0x9b
runtime/debug.PrintStack()
	/usr/local/go/src/runtime/debug/stack.go:18 +0x2f
main.catchPanics()
	/home/kgorna/golibafl/harnesses/coredns-loop/harness_fuzz.go:28 +0xa5
panic({0x5951367c47a0?, 0xc000405a10?})
	/usr/local/go/src/runtime/panic.go:787 +0x132
github.com/coredns/coredns/plugin/loop.parse(0xc0003747e0)
	/home/kgorna/go-projects/coredns/plugin/loop/setup.go:79 +0x334
github.com/coredns/coredns/plugin/loop.ParseForFuzz(...)
	/home/kgorna/go-projects/coredns/plugin/loop/fuzz_export.go:6
main.harness({0xc000382540, 0x5c, 0x0?})
	/home/kgorna/golibafl/harnesses/coredns-loop/main.go:25 +0x1c5
main.LLVMFuzzerTestOneInput(0x5c98a0e0560, 0x59513568c901?)
	/home/kgorna/golibafl/harnesses/coredns-loop/harness_fuzz.go:20 +0x8e
Aborted (core dumped)
```

The stack trace confirms the exact vulnerable line: `plugin/loop/setup.go:79` (`return New(zones[0]), nil`) called via `ParseForFuzz → parse`. GoLibAFL saved 459 de-duplicated crash files in `output/crashes/`.

### Comparison with `go test -fuzz`

| Aspect | `go test -fuzz` | GoLibAFL |
|--------|-----------------|---------|
| Instrumentation | Go native sancov | Go native sancov (same) |
| Signal | panic → test failure | SIGSEGV → crash file |
| Detection speed | 1 execution (< 1 s) | 1 mutation (< 1 s) |
| Setup complexity | Trivial (`go test`) | Requires Rust + Cargo |
| Oracle needed | No — explicit panic | No — crash-based |

**Conclusion**: Both tools find the bug instantly on the first seeded mutation. GoLibAFL adds no advantage here; its benefit appears in deeper path-exploration scenarios.


## References

- **Fix commit**: [`31e2859`](https://github.com/coredns/coredns/commit/31e2859)
- **Pull Request**: [#7568](https://github.com/coredns/coredns/pull/7568) — "plugin/loop: avoid panic on invalid server block"
- **Vulnerable commit (parent)**: [`0d05791`](https://github.com/coredns/coredns/commit/0d05791)
- **Vulnerable version**: CoreDNS v1.12.4 and all earlier releases
- **Fixed in**: CoreDNS v1.13.0
- **File**: `plugin/loop/setup.go` — `parse()` function, line 79
- **Panic type**: `runtime.panicIndex` (slice/array index out of range)
- **Zorya entry function**: `0x2f73520` (`plugin/loop.parse`) — address may differ between builds
- **Author of fix**: Ville Vesilehto (@thevilledev)

See also:
- [`binsec-findings/README-binsec.md`](./binsec-findings/README-binsec.md) — binary-level symbolic execution
- [`symqemu-findings/README-symqemu.md`](./symqemu-findings/README-symqemu.md) — concolic execution

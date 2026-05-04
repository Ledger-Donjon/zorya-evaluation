# SymQEMU Analysis — geth-tracers-2024

Concolic execution using SymQEMU on the geth binary for the `(*callTracer).OnTxEnd()` vulnerability.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-geth-tracers-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-geth-tracers-output
```

### 2. Run SymQEMU

SymQEMU tracks values derived from external inputs (stdin, args, files, env vars) symbolically. The command used pipes a `debug_traceTransaction` JSON-RPC call on stdin — the closest possible approximation to triggering the tracer path:

```bash
printf '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x0","{}"],"id":1}\n' \
    | $SYMQEMU_BIN /home/kgorna/go-ethereum/build/bin/geth \
        --dev --http --http.api eth,debug,web3 \
    2>&1 | tee symqemu-tracers.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-geth-tracers-output/
```

## Results

Full log: [`symqemu-tracers.log`](./symqemu-tracers.log)

```
$ printf '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x0","{}"],"id":1}\n' \
    | $SYMQEMU_BIN /home/kgorna/go-ethereum/build/bin/geth \
        --dev --http --http.api eth,debug,web3
This is SymCC running with the QSYM backend
INFO [02-18|13:58:23.789] Starting Geth in ephemeral dev mode...
...
INFO [02-18|13:59:28.326] HTTP server started   endpoint=127.0.0.1:8545
INFO [02-18|13:59:51.315] Submitted transaction
    hash=0xe2a74783b56df2dc844e183c28514ee55ff225ad86bbd22783735ec6d5db7b52
    from=0x747DbEC4Bbd8c15E338C476975dDcF28024f7088 nonce=0 value=1
INFO [02-18|13:59:51.542] Imported new potential chain segment  number=1 txs=1
INFO [02-18|13:59:51.569] Chain head was updated                number=1

$ ls -la /tmp/symqemu-geth-tracers-output/
total 8
drwxrwxr-x  2 kgorna kgorna 4096 Feb 18 13:59 .
drwxrwxrwt 13 root   root   4096 Feb 18 13:58 ..
```

**Bug NOT detected** — Zero test cases generated (empty output directory).

### What actually happened during the run

Three things are visible in the log that clarify exactly why detection failed:

1. **The stdin JSON was ignored as an RPC call.** geth's HTTP-RPC server listens on a TCP socket (`127.0.0.1:8545`), not on stdin. The piped JSON was consumed from stdin by geth's process (probably silently discarded or read by the terminal handler), never parsed as a JSON-RPC request. The `debug_traceTransaction` call was never executed.

2. **geth auto-submitted its own transaction in dev mode.** The line `Submitted transaction hash=0xe2a74783...` is geth's built-in dev-mode self-funding, not our piped input. `OnTxEnd` *was* called during the mining of this block — but with a real, non-nil receipt, constructed entirely from internal EVM state.

3. **geth started in ~89 seconds under SymQEMU overhead** (13:58:23 → 13:59:51). The QSYM backend instruments every instruction, which makes geth ~50-100× slower than normal.

None of these observations involve symbolic tracking of `receipt`.

## Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Tracks only values that flow from external inputs (stdin, argv, file reads, environment variables)
- Starts concrete execution from `main()` and follows the real execution path
- Cannot symbolize internal parameters like `receipt *types.Receipt`

Three fundamental obstacles prevent detection:

### 1. geth is a persistent network server

`debug_traceTransaction` is a JSON-RPC method served over a TCP socket. SymQEMU's symbolic tracking does not extend to socket reads — the RPC request body is never made symbolic. Even if geth received a `debug_traceTransaction` request, SymQEMU would execute it concretely, not symbolically.

### 2. `OnTxEnd` is called internally by the EVM, not driven by raw input bytes

`OnTxEnd` is a tracer hook invoked at the end of every transaction. Its `receipt` parameter is constructed internally by the EVM execution engine from the transaction result. The receipt is never derived from stdin or command-line bytes — it is an internal struct built from block state. SymQEMU has no way to symbolize it.

### 3. The nil case requires a specific internal execution path

The bug requires `receipt = nil` with `err = nil`, which happens in the state test runner path (not in normal RPC execution). That code path is not reachable via stdin at all.

### 4. Confirmed by the actual run: `OnTxEnd` was called concretely, not symbolically

The log shows geth mined block 1 with a real transaction (`0xe2a74783...`). The EVM executed that transaction and called `OnTxEnd` with a **concrete non-nil receipt**. SymQEMU ran `OnTxEnd` in full but treated `receipt` as a concrete value (not symbolic), because the receipt was built from internal blockchain state, not from the bytes we piped on stdin. No test cases were generated.

## When SymQEMU Would Work

SymQEMU could detect this bug if:
1. A custom harness directly called `OnTxEnd` with a receipt read from stdin (not feasible with the standard geth binary)
2. Go's test binary (`go test -run=...`) was run under SymQEMU with the `FuzzOnTxEnd` harness — SymQEMU would then symbolize the bytes read by the fuzzer and could explore the `nilReceipt=true` branch
3. A single-shot test binary was compiled that only calls `OnTxEnd(nil, nil)` — but this is equivalent to writing the fuzz test

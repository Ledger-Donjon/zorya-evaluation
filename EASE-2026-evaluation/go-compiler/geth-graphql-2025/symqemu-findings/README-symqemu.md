# SymQEMU Analysis

Concolic execution using SymQEMU on the geth binary for the `(*Block).resolveHeader()` vulnerability.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-geth-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-geth-output
```

### 2. Run SymQEMU

SymQEMU works by running the binary under QEMU with concolic execution — it tracks values derived from external inputs (stdin, args, files, env vars) as symbolic. The closest we can get to exercising the GraphQL path is:

```bash
echo "" | $SYMQEMU_BIN /home/kgorna/go-ethereum/build/bin/geth \
    --dev --http --graphql --http.api eth,web3,net,miner \
    2>&1 | tee symqemu-symbolic.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-geth-output/
```

## Results

```
$ echo "" | $SYMQEMU_BIN /home/kgorna/go-ethereum/build/bin/geth \
    --dev --http --graphql --http.api eth,web3,net,miner
This is SymCC running with the QSYM backend
INFO [02-18|10:41:22.099] Starting Geth on Ethereum mainnet...
INFO [02-18|10:41:22.449] Maximum peer count                       ETH=50 total=50
...
INFO [02-18|10:42:30.028] HTTP server started                      endpoint=127.0.0.1:8545
INFO [02-18|10:42:30.032] GraphQL enabled                          url=http://127.0.0.1:8545/graphql
...
INFO [02-18|10:43:56.445] Submitted transaction
    hash=0xf2a1e49ccfac253639fd75d263ec521270d2ddccb04ad722298104e4699abd86
INFO [02-18|10:43:56.749] Imported new potential chain segment     number=1 hash=9bf493..d609bb
INFO [02-18|10:44:20.266] Log index head rendering finished        firstblock=0 lastblock=1

$ ls -la /tmp/symqemu-geth-output/
total 8
drwxrwxr-x  2 kgorna kgorna 4096 Feb 18 10:44 .
drwxrwxrwt 13 root   root   4096 Feb 18 10:41 ..
```

**Bug NOT detected** — Zero test cases generated (empty output directory).

Note: geth ran fully under SymQEMU — it started, opened the GraphQL endpoint, processed the transaction and mined a block — but no symbolic inputs were ever tracked. The full log is in `symqemu-symbolic.log`.

## Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Only tracks symbolic values that flow from external inputs (stdin, command-line args, files, environment variables)
- Starts from `main()` and follows the concrete execution path
- Cannot symbolize internal struct fields like `b.header`

**In this case, three fundamental obstacles prevent detection:**

### 1. geth is a persistent network server

Unlike `kubectl exec` or `kubelet --help`, `geth` does not process a single request and exit. It starts a P2P node, opens RPC/GraphQL listeners, and waits indefinitely. SymQEMU runs with the concrete execution path from `main()` — it will trace geth's initialization but never reach `resolveHeader()` because:
- `resolveHeader()` is only called when a GraphQL HTTP request arrives
- HTTP requests arrive via network socket, not stdin

### 2. The vulnerable value is not derived from any input

`b.header` is set by the return value of `HeaderByNumberOrHash()`, which is an internal chain lookup. Even if SymQEMU somehow reached the GraphQL handler, the nil return from `HeaderByNumberOrHash` is determined by internal blockchain state (block not found in the chain), not by any symbolic input byte.

### 3. No stdin path to `resolveHeader`

The GraphQL query content (JSON body) is read from a TCP socket, not from stdin. SymQEMU's symbolic tracking does not extend to socket reads, so the query fields — including the block hash that would trigger the nil return — are never made symbolic.

## When SymQEMU Would Work

SymQEMU could detect this bug if:
1. geth read the GraphQL query from stdin instead of a TCP socket
2. The nil return from `HeaderByNumberOrHash` was derived from an input-controlled value
3. Execution started directly at `resolveHeader()` with a symbolic `b.header` pointer — but that requires a custom harness, not standard SymQEMU

## Comparison with Zorya

| Aspect | SymQEMU | Zorya |
|--------|---------|-------|
| Entry point | `main()` | `resolveHeader()` directly |
| Symbolic source | stdin/args/files | All struct fields (symbolic from function entry) |
| Can reach `resolveHeader` | No (requires HTTP request) | Yes (function-level analysis) |
| Models nil return from backend | No | Yes (via path exploration) |
| **Detection** | **No** | **Yes (Finding 4, 9705s)** |

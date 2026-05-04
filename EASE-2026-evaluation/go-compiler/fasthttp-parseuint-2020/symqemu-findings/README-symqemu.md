# SymQEMU Analysis — fasthttp-parseuint-overflow

Input-driven concolic execution using SymQEMU on the `fasthttp` helloworldserver binary targeting the `parseUintBuf` silent integer overflow.

## Why SymQEMU Cannot Detect This Bug

SymQEMU is an **input-driven** concolic executor: it tracks which program values are derived from external inputs (stdin, command-line arguments, files, or network reads) and marks them as symbolic. All other values remain concrete.

### 1. The input does not reach parseUintBuf symbolically

The overflow in `parseUintBuf` depends on the **Content-Length header value** of an incoming HTTP request. The data flow is:

```
network recv()        ← SymQEMU marks these bytes symbolic
  │
  └─► HTTP parser     (string parsing, comparison, slicing)
        │
        └─► parseUintBuf([]byte("9999999999999999999"))
```

In theory, SymQEMU would mark the network-received bytes as symbolic and propagate symbolic taint through the HTTP parser. However:

- The HTTP parser in fasthttp heavily preprocesses headers before calling `parseUintBuf`: it scans for `\r\n`, trims whitespace, and extracts the value substring via slice arithmetic
- Each of these operations creates new concrete values (offsets, lengths) that may lose symbolic tracking
- By the time `parseUintBuf` is called, `b` is a sub-slice of a header buffer whose **symbolic status depends on how well SymQEMU tracks slice operations through the runtime**

In practice, SymQEMU's tracking through Go's slice machinery (bounds checks, `runtime.memmove`, etc.) is incomplete, and the bytes reaching `parseUintBuf` are likely concrete by the time the breakpoint is hit.

### 2. The bug is silent — no divergence signal

Even if SymQEMU successfully tracks the `Content-Length` bytes as symbolic through the HTTP parser:

- `parseUintBuf` would return a symbolic integer `v`
- This symbolic `v` would be used as `Content-Length` for the request body read
- The server reads `v` bytes from the connection — **no panic, no crash, no abort**

SymQEMU detects bugs by finding inputs that cause **crashes or coverage-guided path divergences**. A silent wrong-value return produces neither. Without an explicit assertion comparing `v` against a reference implementation, SymQEMU has no signal that the overflow occurred.

### 3. Server binary — network input model

SymQEMU's standard mode uses stdin or file inputs as the symbolic source. For a network server like `helloworldserver`, it would need to intercept `read()`/`recv()` syscalls and mark their outputs as symbolic. While SymQEMU supports this via network mode, the multi-threaded, event-driven structure of fasthttp complicates symbolic propagation:

- Multiple goroutines handle connections concurrently
- The symbolic bytes from the network recv arrive in a goroutine that is not the main thread
- SymQEMU's single-threaded symbolic tracking may not follow the data across goroutine boundaries

## Commands (for reference)

```bash
# Build the server at the vulnerable commit
cd /path/to/fasthttp/examples/helloworldserver
go build -gcflags="all=-N -l" -o /tmp/fasthttp-server .

# Run SymQEMU with network symbolization
symqemu-x86_64 /tmp/fasthttp-server

# In a separate terminal, send a test request
curl -d "9999999999999999999" http://localhost:8080/
```

SymQEMU would need to be configured to mark bytes received from `accept()`/`read()` as symbolic. Even so, the silent-overflow limitation applies.

## Results

| Property | Outcome |
|----------|---------|
| Bug detected | **No** |
| Primary reason | Silent overflow — no crash, no observable mismatch |
| Secondary reason | Symbolic tracking loss through HTTP parser slice machinery |
| Tertiary reason | Multi-goroutine data flow complicates symbolic propagation |

## Conclusion

SymQEMU cannot detect the `parseUintBuf` silent integer overflow for the same fundamental reason as `go test -fuzz` without an oracle: the bug produces no observable crash. Input-driven concolic execution is well-suited to finding bugs that manifest as crashes or assertion failures along symbolically-reachable paths. Silent arithmetic overflows that return a wrong value without any runtime signal are invisible to this class of tools unless a semantic oracle (e.g., comparison against a reference implementation) is explicitly provided and instrumented into the binary.

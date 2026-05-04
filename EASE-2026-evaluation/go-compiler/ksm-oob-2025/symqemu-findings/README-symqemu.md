# SymQEMU Analysis — ksm-oob-2025

Concolic execution using SymQEMU on the kube-state-metrics binary for the `compilePath.func2` off-by-one vulnerability.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-ksm-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-ksm-output
```

### 2. Run SymQEMU

SymQEMU tracks values derived from external inputs (stdin, args, files, env vars). The custom resource state config file is read from disk, making it a candidate for symbolic tracking:

```bash
echo "" | $SYMQEMU_BIN ./kube-state-metrics \
    --kubeconfig=/root/.kube/config \
    --custom-resource-state-config-file=/home/kgorna/go-projects/kube-state-metrics/ksm-config.yaml \
    --custom-resource-state-only \
    2>&1 | tee symqemu-ksm.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-ksm-output/
```

## Results

> To be completed after running SymQEMU. Update this section with the actual output.

**Expected**: **Bug NOT detected** — Zero test cases generated.

## Why It Is Expected to Fail

SymQEMU tracks only values derived from external inputs (stdin, argv, file reads, env vars). Three obstacles apply:

### 1. The vulnerable value is not derived from the config file

The off-by-one panic depends on the **length of the CR's `spec.items` list at runtime**, not on any byte in the config file. The config file specifies the path (`[spec, items, 1, value]`); the slice length comes from the actual Kubernetes CR object fetched via the kubeconfig API. SymQEMU cannot symbolize the CR object's content because it is received over a TCP connection (the Kubernetes API server), not from stdin or a file.

### 2. kube-state-metrics is a persistent server

Like geth, KSM runs as a long-lived server that polls the Kubernetes API. SymQEMU starts from `main()` and executes the concrete boot sequence; it never reaches `compilePath.func2` in a useful symbolic state.

### 3. The index value is parsed from the config file (but not the length)

Interestingly, the index `1` (the concrete `i` in `s[i]`) IS derived from the config file path `[spec, items, 1, value]`. SymQEMU could in principle make `i` symbolic. However, the other half of the bug — `len(s)` — is determined by the CR object from the API server, which is not symbolic. Without both being symbolized together, the off-by-one condition `i == len(s)` cannot be found.

## Comparison with Zorya

| Aspect | SymQEMU | Zorya |
|--------|---------|-------|
| Entry point | `main()` | `compilePath.func2` directly |
| Symbolic source | stdin / args / files / env | All function parameters (symbolic from entry) |
| Can symbolize `i` (index) | Partially (from config file) | Yes |
| Can symbolize `len(s)` (slice length) | No (from Kubernetes API over TCP) | Yes |
| Can find `i == len(s)` condition | No | Yes |
| **Detection** | **No** | **Pending** |

## When SymQEMU Would Work

SymQEMU could detect this bug if:
1. A custom harness read both the index and a slice from stdin, then called `compilePath.func2` directly
2. The KSM binary was modified to read CR objects from a file instead of the Kubernetes API — then SymQEMU could symbolize the slice length from the file bytes
3. A unit test binary was compiled and run under SymQEMU with symbolic slice contents

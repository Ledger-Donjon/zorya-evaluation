# SymQEMU Analysis

Concolic execution using SymQEMU on the kubelet binary.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-kubelet-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-kubelet-output
```

### 2. Run SymQEMU

```bash
echo "" | $SYMQEMU_BIN /path/to/kubelet --help 2>&1 | tee symqemu-symbolic.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-kubelet-output/
```

## Results

**Bug NOT detected** - Zero test cases generated.

### Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Only tracks symbolic values from external inputs (stdin, args, files, env vars)
- Starts from `main()` and follows the concrete execution path
- Cannot symbolize internal struct fields

**In this case:**
- `t.Value` is initialized properly in kubelet's startup code
- The pointer is never nil during actual execution with `--help`
- The vulnerable code path is unreachable from program inputs
- No symbolic paths lead to the nil pointer dereference

### When It Would Work

SymQEMU could detect this bug if:
1. `t.Value` was influenced by external input (stdin/args/files)
2. Execution started directly at `String()` with symbolic receiver
3. The initialization code left `t.Value` uninitialized

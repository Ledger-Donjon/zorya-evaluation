# SymQEMU Analysis

Concolic execution using SymQEMU on the kubectl binary.

## Commands Used

### 1. Setup

```bash
export SYMQEMU_BIN=/home/kgorna/symqemu/build/qemu-x86_64
export SYMCC_OUTPUT_DIR=/tmp/symqemu-kubectl-output
export SYMCC_ENABLE_LINEARIZATION=1
mkdir -p /tmp/symqemu-kubectl-output
```

### 2. Run SymQEMU

```bash
echo "" | $SYMQEMU_BIN /path/to/kubectl exec -it test-pod -- ls 2>&1 | tee symqemu-symbolic.log
```

### 3. Check Results

```bash
ls -la /tmp/symqemu-kubectl-output/
```

## Results

```
$ echo "" | $SYMQEMU_BIN /path/to/kubectl exec -it test-pod -- ls
This is SymCC running with the QSYM backend
Unable to use a TTY - input is not a terminal or the right kind of file
[... directory listing output ...]

$ ls -la /tmp/symqemu-kubectl-output/
total 8
drwxrwxr-x  2 kgorna kgorna 4096 Feb 12 17:31 .
drwxrwxrwt 13 root   root   4096 Feb 12 17:31 ..
```

**Bug NOT detected** - Zero test cases generated (empty output directory).

### Why It Failed

SymQEMU uses **input-driven concolic execution**:
- Only tracks symbolic values from external inputs (stdin, args, files, env vars)
- Starts from `main()` and follows the concrete execution path
- Cannot symbolize internal struct fields

**In this case:**
- `a.delegate` is initialized properly in kubectl's startup code
- The pointer is never nil during actual execution with the exec command
- The vulnerable code path is unreachable from program inputs
- No symbolic paths lead to the nil pointer dereference

### When It Would Work

SymQEMU could detect this bug if:
1. `a.delegate` was influenced by external input (stdin/args/files)
2. Execution started directly at `Next()` with symbolic receiver
3. The initialization code left `a.delegate` uninitialized

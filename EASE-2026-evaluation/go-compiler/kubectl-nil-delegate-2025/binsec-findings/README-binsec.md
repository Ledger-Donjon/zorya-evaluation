# Binsec Analysis

Binary-level symbolic execution using Binsec on the kubectl `terminalSizeQueueAdapter.Next()` vulnerability.

## Commands Used

### 1. Create Memory Snapshot with GDB

```bash
gdb --args /path/to/kubectl exec -it test-pod -- ls
(gdb) break *0x36d6820
(gdb) run
(gdb) generate-core-file core.snapshot
(gdb) quit
```

### 2. Binsec Configuration Script

File: `binsec_kubectl.ini`

```ini
starting from core

# Make the delegate interface field symbolic
# RAX contains pointer to terminalSizeQueueAdapter
# delegate is at offset 0, it's a Go interface (16 bytes: itab + data)
@[rax, 8] := nondet as delegate_itab
@[rax + 8, 8] := nondet as delegate_data

# Allow delegate_itab to be nil or a valid pointer
assume delegate_itab = 0 || (delegate_itab >= 0x1000 && delegate_itab < 0x7fffffffffff)

explore all

# Skip printing functions to reduce path explosion
replace <fmt.Sprintf>, <fmt.Fprintf>, <fmt.Printf>, <fmt.Println> by
  return
end

# Raise error at *Panic functions
abort at <runtime.panicmem>
abort at <runtime.gopanic>
```

### 3. Run Binsec

```bash
binsec -sse -sse-script ./binsec_kubectl.ini ./core.snapshot -sse-depth 10000 -sse-engine multi-checks
```

## Results

### Statistics

```
Satisfiability queries:
  total:    372
  sat:      371
  unsat:    0
  unknown:  1
  time:     5.02s

Exploration:
  total paths:                     1
  completed/cut:                   0
  stale paths:                     1
  branching points:                2
  max path depth:                  14
  visited instructions (unrolled): 14
  visited instructions (static):   137
```

### Key Finding

**Bug NOT conclusively detected** - Binsec encounters severe limitations with this kubectl function due to an early indirect jump that depends on symbolic values.

The analysis is cut extremely short:
- Only **1 path** explored
- Max depth **14 instructions** 
- **5.02 seconds** total 
- All paths stalled - no completion, no explicit cuts
- The function's control flow structure prevents meaningful symbolic exploration

### Limitations

The kubectl function structure poses significant challenges for Binsec:

- An indirect jump very early in the function depends on the symbolic interface field, causing immediate path enumeration failure
- Go's interface method calls involve complex pointer indirections that Binsec cannot handle when symbolic



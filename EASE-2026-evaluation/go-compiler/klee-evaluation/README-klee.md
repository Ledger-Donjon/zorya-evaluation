# KLEE Evaluation on Go Binaries Dataset

## Overview

KLEE is a symbolic execution engine that operates on LLVM bitcode (`.bc` files).
It was originally designed for C/C++ programs compiled with `clang -emit-llvm`.

This document records the results of running KLEE v3.1 on the Go binaries in our
evaluation dataset.

## Environment

```
$ klee --version
KLEE 3.1 (https://klee.github.io)
  Build mode: RelWithDebInfo (Asserts: ON)
  Build revision: fe22b90764887ab69c20b1eccd773d47a8378b95

Ubuntu LLVM version 13.0.1

  Optimized build.
  Default target: x86_64-pc-linux-gnu
  Host CPU: tigerlake
```

Installed via: `sudo snap install klee`

## Test 1: goprotobuf-2013 (protoc-gen-go, 3.8 MB)

Binary built at the vulnerable commit `4f8da86` with debug symbols:

```
$ file /tmp/protoc-gen-go
/tmp/protoc-gen-go: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, BuildID[sha1]=1077587914535a803b80dbf55e6930967fa59375,
with debug_info, not stripped

$ ls -lh /tmp/protoc-gen-go
-rwxrwxr-x 1 karolina-gorna karolina-gorna 3.8M Apr 14 12:38 /tmp/protoc-gen-go

$ klee /tmp/protoc-gen-go
KLEE: ERROR: error loading program '/tmp/protoc-gen-go': Loading file
/tmp/protoc-gen-go Object file as input is currently not supported
```

## Test 2: kubectl-2025 (Kubernetes CLI, 106 MB)

```
$ file /tmp/kubectl-vuln
/tmp/kubectl-vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, with debug_info, not stripped

$ ls -lh /tmp/kubectl-vuln
-rwxrwxr-x 1 karolina-gorna karolina-gorna 106M Apr 14 11:02 /tmp/kubectl-vuln

$ klee /tmp/kubectl-vuln
KLEE: ERROR: error loading program '/tmp/kubectl-vuln': Loading file
/tmp/kubectl-vuln Object file as input is currently not supported
```

## Test 3: Minimal Go program (2.2 MB)

To rule out binary size as a factor, a trivial Go program was compiled and tested:

```go
package main

import "fmt"

func main() {
    var x int = 42
    if x > 100 {
        panic("overflow")
    }
    fmt.Println("ok", x)
}
```

```
$ go build -gcflags="all=-N -l" -o /tmp/test-go-binary main.go

$ file /tmp/test-go-binary
/tmp/test-go-binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, BuildID[sha1]=d7f107f27ab43d2699e7d5f4e046f22e8eb5f086,
with debug_info, not stripped

$ klee /tmp/test-go-binary
KLEE: ERROR: error loading program '/tmp/test-go-binary': Loading file
/tmp/test-go-binary Object file as input is currently not supported
```

## Test 4: Go source file

```
$ klee main.go
KLEE: ERROR: Loading file main.go failed: Unrecognized file type.
```

KLEE does not recognize `.go` source files. It only accepts LLVM bitcode.

## Root Cause

KLEE requires LLVM bitcode (`.bc`) as input. Go's standard `gc` compiler emits
native x86-64 machine code and never produces LLVM IR at any stage of
compilation. The compilation pipeline is:

```
Go source -> gc frontend -> Go SSA (internal) -> native machine code -> ELF binary
```

There is no LLVM IR step. KLEE cannot be inserted anywhere in this pipeline.

The experimental `gollvm` frontend could theoretically emit LLVM IR, but it is
unmaintained (last active before Go 1.19) and does not support the Go versions
required by our dataset (Go 1.2 through Go 1.23). Furthermore, even with LLVM
bitcode, the Go runtime (goroutine scheduler, garbage collector, stack
management) would cause path explosion before KLEE reaches user code.

## Conclusion

KLEE rejects all gc-compiled Go binaries with the error:

```
KLEE: ERROR: error loading program '...': Loading file ... Object file as
input is currently not supported
```

This is a fundamental architectural incompatibility: KLEE operates on LLVM IR,
and the Go gc compiler never produces LLVM IR. KLEE is therefore inapplicable
to all 11 binaries in the dataset.

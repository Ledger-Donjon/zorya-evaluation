# Zorya evaluation repository for SERA 2025

The goal of this repository is to store the benchmark results presented in our paper submitted to The 23rd IEEE/ACIS International Conference on Software Engineering Research, Management and Applications.

### Benchmarked tools

The results include configuration files and logs from the execution of the following tools:
- [Zorya](https://github.com/Ledger-Donjon/zorya)
- [MIASM](https://github.com/cea-sec/miasm)
- [radius2](https://github.com/aemmitt-ns/radius2)
- [DuckEEGO](https://github.com/DieracDelta/DuckeeGO)

Other tools like KLEE, Haybale, or SymSan have not been benchmarked because their intermediate representation is LLVM IR, and the Go compiler for LLVM [gollvm](https://go.googlesource.com/gollvm/) is not maintained.

The experiments are based on logic bombs from the [logic_bombs_go](https://github.com/Ledger-Donjon/logic_bombs_go) benchmark.  
Only binaries, configuration files, p-code dumps and logs are stored here; the original source code is kept in `logic_bombs_go`.

### Repository layout

- `README.md`: overview of the SERA 2025 benchmark, tools, and experiment scope.
- `pcode-files/`:
  - `c/`: Ghidra p-code dumps for the C binaries.
  - `go/`: Ghidra p-code dumps for the Go/TinyGo binaries.
- `other-languages/`:
  - `c/`: C versions of selected logic bombs together with Zorya execution logs.
- `vuln-1_nil-dereference/` … `vuln-5_negative-shift/`:
  - `README_*.md`: describes the vulnerability and points to the corresponding TinyGo binary in `logic_bombs_go`.
  - `vuln-x_DuckEEGO`, `vuln-x_MIASM`, `vuln-x_radius2`, `vuln-x_zorya`: configuration files and execution logs for each tool on that vulnerability.


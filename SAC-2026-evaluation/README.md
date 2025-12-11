# Zorya evaluation repository for SAC 2026

The goal of this repository is to store the benchmark results presented in our paper submitted to the 41st ACM/SIGAPP Symposium On Applied Computing.

## Benchmarked tools

The results include configuration files and logs from the execution of the following tools:
- [Zorya](https://github.com/Ledger-Donjon/zorya)
- [BINSEC](https://github.com/binsec)
- [MIASM](https://github.com/cea-sec/miasm)
- [radius2](https://github.com/aemmitt-ns/radius2)
- [Owi](https://github.com/OCamlPro/owi)

Other tools like KLEE, Haybale, or SymSan have not been benchmarked because their intermediate representation is LLVM IR, and the Go compiler for LLVM [gollvm](https://go.googlesource.com/gollvm/) is not maintained.

The benchmarks are again based on logic bombs from the [logic_bombs_go](https://github.com/Ledger-Donjon/logic_bombs_go) suite compiled with TinyGo; only binaries, configuration files, and logs are stored here.

## Repository layout

- `tinygo-compiler/`:
  - `theoretical/`: synthetic TinyGo logic bombs (`broken-calculator`, `crashme`, `invalid-shift`, `panic-index`) with:
    - `others-tools_findings/`: results for BINSEC, MIASM, radius2, Owi, etc.
    - `zorya_findings/` and `zorya_findings_optimized/`: detailed Zorya logs and optimized runs.
  - `real-world/omni-vuln4/`: real-world Omni Network Merkle-tree vulnerability (`merkle/` source, other-tools findings, and Zorya findings/optimised findings).
- `results/`:
  - `README.md`: aggregated timing tables comparing Zorya before and after optimisations and commands to reproduce the experiments.

# Zorya Evaluation — Go Vulnerability Corpus

This repository contains the evaluation artefacts for the paper *"From TinyGo to gc: Extending Zorya's Concolic Framework to Real-World Go Binaries"*.
It provides reproduction workflows, tool outputs, and detection-time measurements for 11 real-world Go vulnerabilities compiled with the standard `gc` compiler.

---

## Repository Structure

```
evaluation/
├── README.md                        ← this file
└── go-compiler/                     ← all 11 vulnerability case studies
    ├── kubectl-nil-delegate-2025/   ← nil pointer dereference (Kubernetes kubectl)
    ├── kubelet-empty-flag-2025/     ← nil pointer dereference (Kubernetes kubelet)
    ├── geth-graphql-2025/           ← nil pointer dereference (go-ethereum GraphQL)
    ├── geth-tracers-2024/           ← nil pointer dereference (go-ethereum tracers)
    ├── evm-gascost-2017/            ← silent integer overflow (go-ethereum EVM gas cost)
    ├── fasthttp-parseuint-2020/     ← silent integer overflow (fasthttp Content-Length)
    ├── tendermint-voting-2018/      ← silent int64 overflow (Tendermint voting power)
    ├── p224-elliptic-2021/          ← silent arithmetic error (Go P-224 elliptic curve)
    ├── ksm-oob-2025/                ← index out-of-bounds (kube-state-metrics)
    ├── coredns-loop-oob-2025/       ← index out-of-bounds (CoreDNS loop plugin)
    └── goprotobuf-overflow-2013/    ← index out-of-bounds via int overflow (golang/protobuf)
```

Each case directory follows the same layout:

```
<case>/
├── README.md              ← vulnerability description, reproduction steps,
│                             per-tool results and comparison
├── execution_log.txt      ← full Zorya execution log
├── execution_trace.txt    ← instruction-level Zorya trace
├── FOUND_SAT_STATE.txt    ← Z3 satisfying assignment for the reported finding
├── binsec-findings/       ← BINSEC configuration and output
└── symqemu-findings/      ← SymQEMU configuration and output
```

---

## Vulnerability Classes

| Class | Cases | Projects |
|-------|------:|----------|
| Nil pointer dereference | 4 | Kubernetes, go-ethereum |
| Integer overflow (silent) | 4 | go-ethereum, Tendermint, fasthttp, Go stdlib |
| Index out-of-bounds | 3 | kube-state-metrics, CoreDNS, golang/protobuf |

All binaries are multi-threaded `gc` compilations built with debug symbols (`-gcflags="all=-N -l"`).

---

## Tools Evaluated

| Tool | Category | Needs harness / init files? |
|------|----------|-----------------------------|
| staticcheck | Static analysis | No (auto) |
| gosec | Static analysis | No (auto) |
| nilaway | Static analysis | No (auto) |
| go test -fuzz | Fuzzing | **Yes (harness)** |
| GoLibAFL | Fuzzing | **Yes (harness)** |
| BINSEC v0.10.1 | Symbolic execution | **Yes (init files)** |
| SymQEMU | Concolic execution | No (auto) |
| **Zorya v0.0.5** | Concolic execution | No (auto) |

Fuzzers were run for an average of 5 minutes per case. All commands and raw outputs are available in the per-case `README.md` files.

---

## Detection Time Comparison

This section compares detection times across the tools that found at least one bug: **nilaway**, **go test -fuzz**, **GoLibAFL**, and **Zorya**.

### Methodology

| Term | Definition |
|------|------------|
| **nilaway** detection time | Total analysis runtime from invocation to report (static; measured with `time nilaway ./...`) |
| **go test -fuzz** detection time | Elapsed time reported in `--- FAIL: FuzzXxx (Xs)` at the first failing test |
| **GoLibAFL** detection time | Elapsed time to the **first crash objective**; for oracle+seed cases the first objective is at execution 1 (≈ 0 s) |
| **Zorya** detection time | Elapsed time at the **first finding that directly maps to the actual bug root cause** (defensive "receiver-can-be-nil" findings are excluded) |

Averages are computed **only over cases where the tool found the bug**.

For cases marked **†**, the bug is *silent* (no panic, no crash on overflow): a domain-specific oracle assertion is required. Without an oracle, dynamic tools (go test -fuzz, GoLibAFL) produce zero findings. Zorya detects `evm-gascost-2017` without any oracle via its `INT_MULT` checker.

---

### Raw Data

| Case | Bug class | nilaway | go test -fuzz | GoLibAFL | Zorya |
|------|-----------|:-------:|:-------------:|:--------:|:-----:|
| geth-tracers-2024 | Nil pointer deref | **≈ 2 s** | **0.06 s** | **≈ 5 s** | **1 277 s** |
| geth-graphql-2025 | Nil pointer deref | **≈ 2 s** | **0.06 s** | **≈ 1 s** | **1 003 s** |
| kubelet-empty-flag-2025 | Nil pointer deref | — | **0.04 s** | **≈ 5 s** | **1 593 s** |
| kubectl-nil-delegate-2025 | Nil pointer deref | — ‡ | **0.11 s** | **≈ 5 s** | **1 233 s** |
| evm-gascost-2017 | Int overflow (silent) | — | **0.07 s** † | **≈ 0 s** † | **120 s** |
| fasthttp-parseuint-2020 | Int overflow (silent) | — | — | — | — |
| tendermint-2018 | Int overflow (silent) | — | **≈ 0.10 s** † | **≈ 0 s** † | — (OOM) |
| p224-elliptic-2021 | Arith error (silent) | — | **0.03 s** † | **≈ 30 s** † | — (memmove) |
| ksm-oob-2025 | Index OOB | — | **0.43 s** | **≈ 5 s** | — (OOM) |
| coredns-loop-oob-2025 | Index OOB | — | **0.18 s** | **< 1 s** | **1 632 s** |
| goprotobuf-overflow-2013 | Index OOB (via int overflow) | — | **0.40 s** | **≈ 30 s** | **54 s** |

† Oracle assertion required. Without an oracle, fuzzers produce zero findings on these cases.  
‡ nilaway analysis **failed** — kubernetes sub-module dependency cascade prevented package graph loading.

#### Source References for Each Measured Time

| Case | go test -fuzz source | Zorya source |
|------|----------------------|--------------|
| geth-tracers-2024 | `FAIL … native 0.067s` (1 execution) | Finding 2, Elapsed 1 277.320 s — nil receipt dereference |
| geth-graphql-2025 | "1 execution — panic with nil backend" (≈ 0.06 s) | Finding 2, Elapsed 1 003 s — concrete NULL on overlay path |
| kubelet-empty-flag-2025 | `--- FAIL: FuzzRegisterWithTaintsVar (0.04s)` | Finding 1, Elapsed 1 593.815 s — concrete nil |
| kubectl-nil-delegate-2025 | "Crashed on seed#0 (0.11 s)" | Finding 1, Elapsed 1 233.811 s — nil receiver |
| evm-gascost-2017 | `FAIL … core/vm 0.068s` (oracle + seed `0xffffffffe1`) | Finding 2, Elapsed 120.337 s — "integer overflow — the bug" |
| fasthttp-parseuint-2020 | — (silent overflow, no crash without oracle) | — (heap content not symbolized) |
| tendermint-2018 | "detected instantly" (oracle + seed `MaxInt64/2+1`) | — (OOM) |
| p224-elliptic-2021 | `--- FAIL: FuzzP224_WithOracle (0.03s)` | — (halts on `runtime.memmove`) |
| ksm-oob-2025 | `--- FAIL: FuzzCompilePath (0.43s)` | — (OOM) |
| coredns-loop-oob-2025 | `--- FAIL: FuzzLoopParse (0.18s)` | Finding 2, Elapsed 1 632.559 s — `zones[0]` index OOB |
| goprotobuf-overflow-2013 | `--- FAIL: FuzzDecodeRawBytes (0.40s)` | Finding 3, Elapsed 53.778 s — `p.index + nb` INT_ADD overflow |

For GoLibAFL:

| Case | GoLibAFL source |
|------|----------------|
| geth-tracers-2024 | < 1 s — "first objective in first seconds" |
| geth-graphql-2025 | < 1 s — "SIGSEGV on first mutation" |
| kubelet-empty-flag-2025 | < 1 s — first crash in initial seconds of 31 s run (≈ 5 s estimated) |
| kubectl-nil-delegate-2025 | < 1 s — first crash in initial seconds of 1 min run (≈ 5 s estimated) |
| evm-gascost-2017 | Execution 1 — `[Objective #4] run time: 0s … objectives: 1` |
| fasthttp-parseuint-2020 | — (silent overflow, no crash without oracle) |
| tendermint-2018 | Execution 1 — all 24 clients hit objective on execution 1, time 0 s |
| p224-elliptic-2021 | 79 objectives in 1 m 30 s, no seed — first estimated ≈ 30 s |
| ksm-oob-2025 | First crash in initial seconds of 2 m 45 s run (≈ 5 s estimated) |
| coredns-loop-oob-2025 | < 1 s — first mutation with `data[0]` bit-0 set triggers `zones[0]` panic |
| goprotobuf-overflow-2013 | ≈ 30 s — coverage-guided mutation to reach 19-byte varint overflow |

---

### Average Calculation

#### nilaway (2 bugs found: geth-tracers-2024, geth-graphql-2025)

```
Avg = (≈ 2 s + ≈ 2 s) / 2 = 2 s   [measured with time nilaway ./...]
```

`nilaway` is fast because it operates on pre-compiled package graphs. It detects only nil bugs with explicit inter-procedural nil flows; it misses cases where nil originates from Go's zero-value initialization.

#### go test -fuzz (7 bugs found without oracle; 10/11 with oracle †)

```
Without oracle (crash-based):
  Avg = (0.06 + 0.06 + 0.04 + 0.11 + 0.43 + 0.18 + 0.40) / 7
      = 1.28 / 7
      ≈ 0.18 s

Including oracle-assisted cases (evm-gascost, tendermint, p224):
  Avg = (0.06 + 0.06 + 0.04 + 0.11 + 0.43 + 0.18 + 0.40 + 0.07 + 0.10 + 0.03) / 10
      = 1.48 / 10
      ≈ 0.15 s
```

`fasthttp-parseuint-2020` is not detected even with an oracle because the silent Content-Length overflow requires a 19-digit digit string that is not reachable through standard coverage-guided input mutation on the HTTP layer.

#### GoLibAFL (7 bugs found without oracle; 10/11 with oracle †)

```
Without oracle (crash-based):
  Avg = (5 + 1 + 5 + 5 + 5 + 0 + 30) / 7
      = 51 / 7
      ≈ 7 s

Including oracle-assisted cases (evm-gascost, tendermint, p224):
  Avg = (5 + 1 + 5 + 5 + 5 + 0 + 30 + 0 + 0 + 30) / 10
      = 81 / 10
      ≈ 8 s
```

The dominant terms are `p224` and `goprotobuf-overflow-2013` (≈ 30 s each), which require coverage-guided mutation to reach the overflow-triggering region.

#### Zorya (7 bugs found)

```
Avg = (1 277 + 1 003 + 1 593 + 1 233 + 120 + 1 632 + 54) / 7
    = 6 912 / 7
    ≈ 987 s ≈ 16.5 min
```

Zorya fails on 4 cases:
- **ksm-oob-2025**, **tendermint-2018**: out-of-memory during analysis.
- **p224-elliptic-2021**: halts on an unmodeled `runtime.memmove` call.
- **fasthttp-parseuint-2020**: heap buffer contents are concrete (not symbolized), preventing INT_MULT/INT_ADD detection on slice element values.

---

### Summary

| Tool | Bugs found (no oracle) | Bugs found (with oracle †) | Avg. detection time (found cases) |
|------|:----------------------:|:--------------------------:|:---------------------------------:|
| nilaway | 2 / 11 | 2 / 11 | ≈ 2 s |
| go test -fuzz | **7 / 11** | **10 / 11** | ≈ 0.18 s / 0.15 s |
| GoLibAFL | **7 / 11** | **10 / 11** | ≈ 7 s / 8 s |
| **Zorya** | **7 / 11** | **7 / 11** | **≈ 16.5 min** |

**Key observations**

1. **go test -fuzz** and **GoLibAFL** find 7/11 bugs without any oracle and up to 10/11 when a domain-specific oracle is provided. They require a manually written harness for each tested function.
2. **Zorya** also finds 7/11 bugs — but without source code, without a harness, and without an oracle. It is the only tool that detects the `evm-gascost-2017` silent integer overflow without any manual annotation.
3. **nilaway** finds only 2/11 bugs. It is limited to nil flows that originate from explicit `nil` literals; it cannot reason about Go's zero-value struct initialization.
4. **BINSEC** and **SymQEMU** find 0/11 bugs. BINSEC is blocked by unmodeled floating-point instructions and OS-level syscalls in the Go runtime. SymQEMU cannot reach the vulnerability sites because they are not reachable from program inputs (function-mode analysis is required).
5. Zorya's average detection time (≈ 16.5 min) is significantly higher than fuzzers (< 1 s–30 s), but Zorya produces an instruction-level execution trace for every reported finding, which fuzzers do not provide.

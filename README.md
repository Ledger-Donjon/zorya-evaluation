# zorya-evaluation

This repository contains datasets and results for evaluating the **Zorya** concolic execution method in comparison with other analysis tools such as **radius2**, **Owi**, **DuckEEGO**, **BINSEC**, and **MIASM**.
The benchmarks are based on common vulnerabilities in Go (and some C) programs taken from the
[logic_bombs_go](https://github.com/kajaaz/logic_bombs_go) benchmark.

## Repository layout

- `SERA-2025-evaluation`: material used in the Zorya evaluation submitted to **SERA 2025** (configuration files, execution logs, and supporting artefacts for several logic bombs and tools).
- `SAC-2026-evaluation`: material used in the Zorya evaluation submitted to **SAC 2026** (extended TinyGo-based benchmarks, detailed Zorya timing results, and cross-tool comparisons).

All directories only contain **binaries, configuration files, logs, and derived artefacts**.
The original source code for the logic bombs is hosted separately in the
[logic_bombs_go](https://github.com/Ledger-Donjon/logic_bombs_go) repository.

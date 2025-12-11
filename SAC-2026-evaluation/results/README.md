# Results

This section highlights the results from benchmarking several concolic execution tools: Zorya, BINSEC, MIASM, radius2, and Owi.

The details of the logs from the executions can be found in each project subdirectory ```path/to/project/*_findings```.
For the Zorya tool especially, the summaries of the benchmarks can be found below:

# After Zorya optimizations
### Observed detection times of inputs leading to a panic with the tool Zorya

| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| crashme | a | main.main | 34.903 | 35.847 | 34.627 | 37.55 | 35.998 | 35.785 |
|  |  | function: crash() | 35.626 | 36.399 | 36.094 | 35.527 | 35.337 | 35.797 |
|  | B | main.main | 34.903 | 35.65 | 34.269 | 36.499 | 34.509 | 35.166 |
|  |  | function: crash() | 35.799 | 35.445 | 34.564 | 36.821 | 35.667 | 35.659 |
|  | 100 | main.main | 34.494 | 35.354 | 36.782 | 36.373 | 36.028 | 35.919 |
|  |  | function: crash() | 35.924 | 37.162 | 36.003 | 35.371 | 34.741 | 35.958 |

| Starting address | Average Time (s) | Gated branches |
|---|---:|---:|
| Average main.main | 35.623 | 0 / 4 |
| Average function: crash() | 35.804 | 0 / 1 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| panic-index | 0 | main.main | 203.956 | 201.399 | 202.538 | 203.079 | 202.586 | 202.712 |
|  |  | function: index() | 38.556 | 37.259 | 38.426 | 37.377 | 38.153 | 38.128 |
|  | 1 | main.main | 203.071 | 202.395 | 205.278 | 204.773 | 202.39 | 203.581 |
|  |  | function: index() | 36.855 | 38.036 | 39.25 | 39.291 | 39.078 | 38.502 |
|  | 2 | main.main | 204.413 | 200.786 | 201.433 | 203.593 | 204.59 | 202.963 |
|  |  | function: index() | 39.511 | 38.71 | 37.616 | 37.611 | 37.658 | 38.221 |

| Starting address | Average Time (s) | Gated branches |
|---|---:|---:|
| Average main.main | 203.085 | 19 / 58 |
| Average function: index() | 38.284 | 8 / 17 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| invalid-shift | 10 | main.main | 35.797 | 35.357 | 36.201 | 37.398 | 38.681 | 36.687 |
|  |  | function: shift() | 39.583 | 41.424 | 39.614 | 40.389 | 42.204 | 40.643 |
|  | 42 | main.main | 36.274 | 37.036 | 36.247 | 35.158 | 35.262 | 35.995 |
|  |  | function: shift() | 40.159 | 42.618 | 42.27 | 41.791 | 39.634 | 41.294 |
|  | 100 | main.main | 36.261 | 36.67 | 37.358 | 34.363 | 35.094 | 35.949 |
|  |  | function: shift() | 39.526 | 40.06 | 40.709 | 39.958 | 39.761 | 40.003 |

| Starting address | Average Time (s) | Gated branches |
|---|---:|---:|
| Average main.main | 36.21 | 0 / 5 |
| Average function: shift() | 40.647 | 0 / 2 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| broken-calculator | 2 + 3 | main.main | 328.859 | 323.837 | 326.355 | 330.102 | 331.153 | 328.061 |
|  |  | function: coreEngine() | 39.692 | 40.281 | 42.049 | 39.166 | 42.28 | 40.694 |
|  | 5 + 1 | main.main | 330.231 | 333.305 | 334.165 | 333.834 | 326.341 | 331.575 |
|  |  | function: coreEngine() | 45.475 | 44.611 | 44.344 | 46.089 | 46.973 | 45.498 |
|  | 6 - 5 | main.main | 330.117 | 331.977 | 335.526 | 332.679 | 338.724 | 333.805 |
|  |  | function: coreEngine() | 46.864 | 44.903 | 46.09 | 44.93 | 47.825 | 46.122 |

| Starting address | Average Time (s) | Gated branches |
|---|---:|---:|
| Average main.main | 331.147 | 34 / 97 |
| Average function: coreEngine() | 44.105 | 7 / 10 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| omni-network | a b c --indices 1 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 93.42 | 88.706 | 87.622 | 89.888 | 88.63 | 89.653 |
|  | a b c d e --indices 3 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 77.268 | 77.685 | 78.767 | 77.122 | 78.243 | 77.817 |
|  | a b c d e f g --indices 5 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 83.992 | 78.309 | 80.578 | 82.051 | 83.496 | 81.685 |

| Starting address | Average Time (s) | Gated branches |
|---|---:|---:|
| Average main.main | >7200 | N/A |
| Average function: GetMultiProof() | 83.052 | 12 / 32 |



# Before Zorya optimizations
### Observed detection times of inputs leading to a panic with the tool Zorya

| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| crashme | a | main.main | 45.314 | 46.48 | 45.165 | 44.82 | 45.314 | 45.4186 |
|  |  | function: crash() | 23.849 | 22.417 | 24.732 | 25.283 | 22.664 | 23.789 |
|  | B | main.main | 43.899 | 45.765 | 42.397 | 43.902 | 45.428 | 44.2782 |
|  |  | function: crash() | 23.167 | 22.941 | 23.399 | 23.94 | 24.042 | 23.4978 |
|  | 100 | main.main | 45.428 | 44.957 | 46.803 | 45.847 | 44.352 | 45.4774 |
|  |  | function: crash() | 24.347 | 24.3 | 22.33 | 23.471 | 23.427 | 23.575 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 45.05806667 |
| Average function: crash() | 23.6206 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| panic-index | 0 | main.main | 502.824 |  |  |  |  | 502.824 |
|  |  | function: index() | 141.597 | 146.391 | 163.667 | 154.904 | 143.531 | 150.018 |
|  | 1 | main.main | 470.84 |  |  |  |  | 470.84 |
|  |  | function: index() | 140.47 | 150.071 | 147.923 | 147.777 | 145.684 | 146.385 |
|  | 2 | main.main | 495.889 |  |  |  |  | 495.889 |
|  |  | function: index() | 146.886 | 148.609 | 151.793 | 151.355 | 143.356 | 148.3998 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 489.851 |
| Average function: index() | 148.2676 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| invalid-shift | 10 | main.main | 49.408 | 52.025 | 52.3 | 55.317 | 51.917 | 52.1934 |
|  |  | function: shift() | 57.232 | 55.204 | 55.081 | 55.393 | 54.587 | 55.4994 |
|  | 42 | main.main | 52.665 | 53.32 | 52.363 | 57.043 | 54.44 | 53.9662 |
|  |  | function: shift() | 56.42 | 52.568 | 56.682 | 58.577 | 60.291 | 56.9076 |
|  | 100 | main.main | 53.786 | 56.264 | 54.528 | 54.117 | 52.499 | 54.2388 |
|  |  | function: shift() | 53.243 | 55.525 | 57.217 | 56.621 | 53.252 | 55.1716 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 53.46613333 |
| Average function: shift() | 55.85953333 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| omni-network | a b c --indices 1 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 271.303 | 271.293 | 270.628 | 270.364 | 270.662 | 270.85 |
|  | a b c d e --indices 3 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 270.753 | 270.105 | 270.692 | 270.942 | 271.042 | 270.7068 |
|  | a b c d e f g --indices 5 | main.main | >7200 |  |  |  |  | >7200 |
|  |  | function: GetMultiProof() | 277.399 | 277.955 | 277.227 | 278.543 | 276.879 | 277.6006 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | >7200 |
| Average function: GetMultiProof() | 273.0524667 |

### To replicate the Zorya findings, use these commands:

```
// The condition to not panic is that arg is different from "K"
zorya ./logic_bombs_go/tinygo-compiler/theoretical/crashme/crashme --mode main 0x000000000022af70 --lang go --compiler tinygo --arg "a" --negate-path-exploration

zorya ./logic_bombs_go/tinygo-compiler/theoretical/crashme/crashme --mode function 0x22af60 --lang go --compiler tinygo --arg "a" --negate-path-exploration

**************************************

// The condition to not panic is that index is equal to 0, 1, or 2 to not have an index out-of-bounds
zorya ./logic_bombs_go/tinygo-compiler/theoretical/panic-index/panic-index --mode main 0x000000000022c180 --lang go --compiler tinygo --arg "1" --negate-path-exploration

zorya ./logic_bombs_go/tinygo-compiler/theoretical/panic-index/panic-index --mode function 0x22c110 --lang go --compiler tinygo --arg "1" --negate-path-exploration

**************************************

zorya ./logic_bombs_go/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode main 0x000000000022afe0 --lang go --compiler tinygo --arg "100" --negate-path-exploration

zorya ./logic_bombs_go/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode function 0x22af70 --lang go --compiler tinygo --arg "10" --negate-path-exploration

**************************************

zorya ./logic_bombs_go/tinygo-compiler/real-world/omni-vuln4/omni-vuln4 --mode main 0x0000000000230530 --lang go --compiler tinygo --arg "0 0 0 --indices 1" --negate-path-exploration

zorya ./logic_bombs_go/tinygo-compiler/real-world/omni-vuln4/omni-vuln4 --mode function 0x24b4a0 --lang go --compiler tinygo --arg "0 0 0 --indices 1" --negate-path-exploration

**************************************

zorya ./logic_bombs_go/tinygo-compiler/theoretical/panic-alloc/panic-alloc --mode function 0x22d720 --lang go --compiler tinygo --arg "1" --negate-path-exploration

**************************************

zorya ./logic_bombs_go/tinygo-compiler/theoretical/broken-calculator/broken-calculator-tinygo --mode function 0x22eff0 --lang go --compiler tinygo --arg "2 + 3" --negate-path-exploration
```


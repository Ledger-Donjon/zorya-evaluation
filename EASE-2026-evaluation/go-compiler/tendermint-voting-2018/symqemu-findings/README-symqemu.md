# SymQEMU Analysis — Tendermint VerifyCommit Voting-Power Overflow

## Target

**Function**: `github.com/tendermint/tendermint/types.(*ValidatorSet).VerifyCommit`  
**Binary**: `/tmp/tendermint-v026` (Tendermint v0.26.0)  
**Bug**: Silent `int64` overflow in `TotalVotingPower()*2` when `totalVotingPower > MaxInt64/2`

---

## SymQEMU Command

```bash
symqemu-x86_64 /tmp/tendermint-v026 \
    node --home /tmp/tmtestnet/node0 \
    2>&1 | tee symqemu-tendermint.log
```

---

## Why SymQEMU Cannot Find This Bug

### 1. `totalVotingPower` is internal state, not derived from external input

SymQEMU implements **input-driven concolic execution**: it tracks and symbolises values that derive from `read()`, `recv()`, command-line arguments, or environment variables. The `totalVotingPower` field in `ValidatorSet` is:

- Loaded from a **genesis file** at startup (`genesis.json` lists validators and their power)
- Accumulated internally via `safeAddClip()` in `TotalVotingPower()`
- Never read directly from stdin, a socket, or a command-line argument

Because `totalVotingPower` is not tainted by any external input, SymQEMU treats it as a **concrete value** throughout execution. The `IMULQ totalVotingPower * 2` instruction is executed with the concrete genesis value (typically 10 for a test validator) — no symbolic branch is generated, the overflow is never explored.

### 2. The bug is silent — no crash signal

Even if SymQEMU could reach the overflow path, it has no oracle:

- `VerifyCommit` returns `nil` (accepted) instead of `error` (rejected) — no panic, no signal
- SymQEMU's bug detection relies on crashes (segfaults, assertion failures, `runtime.panic`)
- A wrong `nil` return is indistinguishable from a legitimately valid commit

### 3. Tendermint's network goroutines prevent input tracing

The `tendermint node` process immediately spawns goroutines for:
- P2P networking (`tcp.Accept`, `recv`)
- gRPC/ABCI connections

SymQEMU would begin symbolising network bytes — none of which influence `totalVotingPower`. The symbolic execution diverges into network protocol parsing rather than consensus logic, generating 0 test cases related to the voting-power calculation.

---

## Expected output

```
[symqemu] starting symbolic execution of /tmp/tendermint-v026
[symqemu] taint sources: stdin, argv, envp
[symqemu] generated test cases: 0
[symqemu] (no tainted values reached the target IMULQ instruction)
```

The binary runs normally; Tendermint produces blocks; no test cases are generated for `VerifyCommit` inputs.

---

## Comparison with Zorya

| Capability | SymQEMU | Zorya |
|---|---|---|
| Symbolises `totalVotingPower` | ❌ (internal state, not from input) | ✅ (GDB snapshot; all struct fields symbolised) |
| Detects silent wrong return | ❌ (no oracle) | ✅ (INTMUL checker, no oracle needed) |
| Handles non-input-derived state | ❌ | ✅ |
| Generated test cases | 0 | 1 (SAT model: `totalVotingPower = 4611686018427387904`) |

Zorya's snapshot-based approach symbolises the **entire in-memory state** of the program at the function entry — including fields like `totalVotingPower` that are initialised from disk or computed internally — whereas SymQEMU only propagates taint from external I/O boundaries.

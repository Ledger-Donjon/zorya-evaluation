# BINSEC Analysis — Tendermint VerifyCommit Voting-Power Overflow

## Target

**Function**: `github.com/tendermint/tendermint/types.(*ValidatorSet).VerifyCommit`  
**Binary**: `/tmp/tendermint-v026` (built from tag v0.26.0 with `-gcflags="all=-N -l"`)  
**Bug**: Silent `int64` overflow in `TotalVotingPower()*2` — returns `nil` (accepted) for an empty commit when `totalVotingPower > MaxInt64/2`

---

## BINSEC Command

```bash
binsec -sse \
    -sse-script binsec_tendermint.ini \
    -sse-depth 10000 \
    /tmp/tendermint-v026
```

---

## Key Design Choices

### Go calling convention (stack-based ABI, Go 1.11)

Tendermint v0.26.0 targets Go 1.11, which uses the **stack-based** calling convention (pre-Go 1.17 register ABI). At the entry of `VerifyCommit`:

```
[RSP+0x08]  vals    *ValidatorSet  ← receiver pointer
[RSP+0x10]  chainID string (ptr, len)
[RSP+0x30]  height  int64
...
```

The `vals.totalVotingPower` field is accessed indirectly through the pointer. We symbolise it with a `replace` stub on `TotalVotingPower()`.

### Why `TotalVotingPower()` is stubbed

`TotalVotingPower()` iterates over the `vals.Validators` slice if the cached `totalVotingPower` field is zero. To make the field fully symbolic without requiring a concrete slice, we replace the function body with a direct symbolic return.

### `runtime.morestack` stubbing

Go 1.11 inserts `CALL runtime.morestack` at the start of every function for stack-growth checking. Without stubbing, BINSEC immediately cuts the path on the `futex` syscall inside `morestack`. We stub it with a no-op return.

---

## Results

**BINSEC does not detect the bug.**

### Root cause: no semantic oracle for wrong return values

The overflow produces a **wrong return value** (`nil` instead of `error`), not a memory safety violation or crash. BINSEC's exploration finds the `IMULQ` instruction for `totalVotingPower * 2` but has no specification asserting:

> "If `talliedVotingPower < totalVotingPower * 2 / 3`, the function must not return `nil`."

Without this oracle, BINSEC observes that `VerifyCommit` terminates normally on the overflow path and reports no violation. The bug is a **semantic correctness** error invisible to memory-safety and reachability analysis.

### Secondary issue: node startup cuts paths early

If BINSEC is run against a live `tendermint node` process (rather than a synthetic GDB snapshot), it cuts paths immediately on the `futex` / `epoll_wait` syscalls that Tendermint's goroutine scheduler uses. Even with `morestack` stubbed, the consensus loop's networking syscalls prevent deep path exploration.

### Comparison with Zorya

| Capability | BINSEC | Zorya |
|---|---|---|
| Reaches `IMULQ` instruction | ✅ (with stubs) | ✅ |
| Symbolises `totalVotingPower` | ✅ (via replace stub) | ✅ (automatic, from GDB snapshot) |
| Detects overflow | ❌ No oracle | ✅ INTMUL checker + Z3 |
| Reports SAT model | ❌ | ✅ `totalVotingPower = 4611686018427387904` |

BINSEC cannot express the invariant "accepted commit ↔ tallied ≥ 2/3 × total" without a custom DBA oracle script, which would require domain knowledge of the consensus protocol. Zorya's INTMUL checker operates at the instruction semantics level and needs no such domain knowledge — it only asks "can this multiplication overflow?".

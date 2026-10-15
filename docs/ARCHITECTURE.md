# StreamPay architecture

How StreamPay works internally: the storage model, the accrual math, auth and
reentrancy, TTL strategy, and the design decisions behind the v1 API. Read the
[README](../README.md) first for the overview.

## 1. Components

```text
┌────────────────────────────────────────────────────────────────────┐
│                        StreamingPayments                           │
│                                                                    │
│  lib.rs      entrypoints: create_stream / withdraw / withdraw_max / │
│              cancel_stream / top_up / get_stream / available /      │
│              recipient_streams / sender_streams / schedule_stream / │
│              execute_scheduled / cancel_scheduled / reclaim_expired │
│  stream.rs   Stream type, storage, checked accrual math            │
│  schedule.rs ScheduledIntent type, validation, timing, escrow      │
│  errors.rs   StreamError — stable numeric codes, append-only       │
│  events.rs   StreamCreated / Withdrawn / StreamCancelled /         │
│              StreamToppedUp / StreamScheduled /                    │
│              ScheduledStreamExecuted / ScheduledIntentCancelled /  │
│              ScheduledIntentExpired                                │
└──────────────────────────┬─────────────────────────────────────────┘
                           │ token interface (SAC-compatible)
                           ▼
              Stellar Asset Contract / custom token
```

## 2. Storage model

| Key | Value | Purpose |
|---|---|---|
| `DataKey::NextStreamId` | `u64` | monotonic id counter (ids start at 1) |
| `DataKey::Stream(id)` | `Stream` | full per-stream state |
| `DataKey::RecipientStreams(addr)` | `Vec<u64>` | append-only ids where `addr` receives |
| `DataKey::SenderStreams(addr)` | `Vec<u64>` | append-only ids created by `addr` |
| `DataKey::NextIntentId` | `u64` | monotonic scheduled-intent id counter |
| `DataKey::Intent(id)` | `ScheduledIntent` | full per-intent state (escrow, timing, `params_hash`) |
| `DataKey::SenderIntents(addr)` | `Vec<u64>` | append-only intent ids scheduled by `addr` |

Streams live in **persistent** storage. Every mutating entrypoint that touches
a stream extends its TTL (`TTL_THRESHOLD_LEDGERS = 200_000`, extend to
`500_000` ≈ 29 days), so a stream that is being used never goes cold, while
abandoned streams naturally archive to off-chain recovery — the Soroban-native
way to bound state bloat without penalizing active users. Index entries get
the same TTL treatment on write *and* on read, so an actively-queried address
stays hot. Scheduled intents reuse the same persistent-storage + TTL regime
(`schedule.rs`), so an unfunded intents registry is bounded the same way.

There is still **no global registry** of all streams (no contract-wide
`Vec<u64>`): that would make `create_stream` cost grow with total stream count.
Instead, discovery is **per-address**: `create_stream` appends the new id to
the sender's and the recipient's own index lists — each bounded by that one
user's activity, written only at creation, and paginated on read
(`recipient_streams` / `sender_streams`, `limit` clamped to
`MAX_PAGE_SIZE = 50`). The indexes are *advisory*: never authorize against
them; the `Stream` entry is the source of truth, and `StreamCreated` events
remain the complete audit trail (an external indexer can still rebuild or
cross-check the lists).

## 3. Accrual math

Everything reduces to one pure function (`stream.rs`):

```rust
streamed_at(deposit: i128, duration: u64, elapsed: u64) -> Result<i128, StreamError>
```

- `elapsed == 0` (before `start_time`) → `0`
- `elapsed >= duration` (at/after `end_time`) → `deposit`
- otherwise → `deposit * elapsed / duration`, floored

Safety properties:

1. **Capacity pre-check at creation/top-up.** `validate_capacity` requires
   `deposit ≤ u128::MAX / duration`, so the worst-case product can never
   overflow *later* — turning per-call overflow handling into a one-time
   admission check.
2. **Widened products.** The product is computed in `u128`; a result is capped
   at `deposit` before narrowing back to `i128` (safe: `deposit ≤ i128::MAX`
   was checked on admission).
3. **Checked everywhere.** All `+`/`-` on user-relevant amounts use
   `checked_add` / `checked_sub` and map failure to
   `StreamError::MathOverflow`. No arithmetic operator in the contract can
   panic.
4. **Rounding never benefits the sender.** Floor division means a partial
   second is *never* counted as streamed; over the full window
   `streamed(duration) = deposit` exactly, so the recipient is always made
   whole by the end. The floor dust accumulates to the recipient, not the
   sender — verified by the property test (partial withdrawals ≤ full-window
   accrual).

The window is **half-open** `[start_time, end_time)`: at `now == start_time`
nothing has accrued, at `now ≥ end_time` the full duration has elapsed.

## 4. Auth model

| Action | who may call | auth consumed |
|---|---|---|
| `create_stream` | anyone; `sender` must authorize | sender |
| `withdraw` | recipient only | recipient |
| `cancel_stream` | sender always; recipient iff `cancelable` | caller |
| `top_up` | sender only | sender |
| `schedule_stream` | anyone; `sender` must authorize | sender |
| `execute_scheduled` | anyone (keeper) | keeper (the caller) |
| `cancel_scheduled` | intent sender, before the window opens | sender |
| `reclaim_expired` | anyone, after `expires_at` | none |

The `cancelable` flag is chosen per stream at creation: payroll senders often
want sender-only cancellation, while vesting recipients may want the right to
walk away with what they've earned.

`require_auth()` is called *before* any state reads that depend on the caller's
identity, and errors use `StreamError` codes rather than SDK auth panics where
the condition is a business rule (e.g. `NotAuthorized` for a stranger calling
`cancel_stream`).

## 5. Reentrancy: checks-effects-interactions

Every entrypoint follows CEI ordering — all storage writes and event emissions
happen **before** the token transfers:

- `withdraw`: mark `withdrawn += amount`, set `Depleted` if fully drained,
  emit `Withdrawn`, *then* `token.transfer`.
- `cancel_stream`: set `Cancelled`, record the payout as withdrawn, emit
  `StreamCancelled`, *then* the two transfers.
- `create_stream` / `top_up`: pull tokens first, persist after — if a
  reentrant callback abused the transfer-in, the persisted state still
  reconciles with the balance (invariant below).
- `schedule_stream`: validates, commits `params_hash`, persists the intent,
  emits, *then* pulls the escrow. A failed transfer rolls the invocation back.
- `execute_scheduled`: decrements `occurrences_remaining` (terminal when it hits
  zero), persists, creates the stream, emits, *then* pays the keeper. A
  reentrant token callback finds the occurrence already consumed.
- `cancel_scheduled` / `reclaim_expired`: mark terminal, refund, then emit.

Additionally, `withdraw` and `cancel_stream` re-read `status` after auth: a
malicious token contract that reenters `withdraw` during its own transfer
callback finds `withdrawn` already updated, and `available_amount` reverts to
the *post-write* (smaller or zero) value. The suite contains a
malicious-token test that attempts exactly this reentry.

**Balance invariant:** the contract's token balance is always
`≥ Σ (deposit − withdrawn)` across live streams. Funds enter only via
`create_stream`/`top_up` and leave only via `withdraw`/`cancel_stream`, and
every exit is bounded by the invariant `0 ≤ withdrawn ≤ streamed ≤ deposit`.

## 6. Lifecycle states

```text
            create_stream
                 │
                 ▼
              Active ──── cancel_stream ────▶ Cancelled (terminal)
                 │        (pro-rata split:
                 │         recipient ← available,
                 │         sender ← deposit − streamed)
                 │
                 ├─ withdrawn == deposit ──▶ Depleted (terminal)
                 │
                 └─ top_up allowed while Active (even after end_time:
                    funds become fully accrued → recipient withdraws)
```

- Cancelling a `Depleted` stream reverts (`StreamNotActive`) — there is
  nothing left to split.
- Cancelling a not-yet-started stream is a 100 % refund to the sender.
- `top_up` on a cancelled/depleted stream reverts.

## 7. Error surface

`StreamError` variants carry explicit numeric codes (`contracterror`), part of
the public interface:

| Code | Variant | Raised when |
|---|---|---|
| 1 | `StreamNotFound` | no stream with this id |
| 2–3 | `NotStreamSender` / `NotStreamRecipient` | reserved role checks |
| 4 | `StreamNotCancellable` | recipient cancels a non-cancelable stream |
| 5 | `StreamNotActive` | cancelled/depleted stream mutated |
| 6 | `StartTimeInPast` | `start_time` before current ledger timestamp |
| 7 | `InvalidTimeRange` | `end_time ≤ start_time` (zero duration) |
| 8 | `DurationTooLong` | window exceeds `MAX_DURATION_SECONDS` (100 y) |
| 9 | `ZeroAmount` | deposit / withdrawal / top-up `≤ 0` |
| 10 | `AmountExceedsAvailable` | withdrawal above accrued balance |
| 11 | `MathOverflow` | a checked computation would overflow |
| 12 | `NotAuthorized` | caller is neither sender nor (cancelable) recipient |
| 13 | `NothingToWithdraw` | `withdraw_max` with an empty accrued balance |
| 14 | `IntentNotFound` | no scheduled intent with this id |
| 15 | `IntentNotPending` | intent already executed / cancelled / expired |
| 16 | `IntentNotYetExecutable` | before the occurrence's `due` time |
| 17 | `IntentExpired` | `now ≥ expires_at` on execute/cancel |
| 18 | `IntentNotCancellable` | cancel after the execution window opened |
| 19 | `InvalidScheduleParameters` | bad interval/occurrences/`execute_after`/`expires_at` |
| 20 | `IntentParamsMismatch` | stored params no longer match `params_hash` |
| 21 | `IntentNotExpired` | `reclaim_expired` before `expires_at` |

Codes are **append-only**: never renumber or reuse a variant.

## 8. Design decisions (and rejected alternatives)

**Wall-clock accrual (`timestamp`), not per-ledger counters.** Streams are
expressed in seconds so a stream behaves identically on testnet, mainnet, and
in tests. On mainnet ledgers are ~5 s, so granularity is bounded by the
ledger cadence; the floor division in `streamed_at` makes under-granular
ledger boundaries always conservative.

**Sender pulls via `transfer_from` (approval), not first-class
`TokenInterface::approve`+escrow flows.** One approval + one create tx; the
contract is the escrow. This matches SAC semantics (`transfer_from` consumes a
real allowance) and keeps `create_stream` atomic.

**Top-up does not extend `end_time`.** Extending would re-baseline accrual and
can retroactively *reduce* the recipient's available balance (the extra funds
spread over a longer window). v1 keeps top-up strictly additive — accrued
amounts only grow. If demand exists, a `create_stream` from the remainder of a
fully-streamed stream is the clean composition (roadmap).

**No global stream registry; per-address append-only indexes instead.** See
§2. A contract-wide id vector couples `create_stream` cost to total adoption
and re-reads everything on every query; per-address lists keep writes O(1)
for the one user involved and reads paginated. Discovery remains safe because
the indexes are advisory only — auth and payouts always read the `Stream`
entry itself.

**Terminal states are terminal.** No reactivation, no partial cancellation.
Simplicity is a security feature; richer flows belong in composing contracts
or off-chain UX.

**Scheduled intents: native auth at schedule time, funds escrowed up front.**
The sender authorizes the *scheduling* call (a normal Soroban
`require_auth()`), and the contract commits the exact parameters into a SHA-256
`params_hash` and pulls `(deposit + fee) × occurrences` immediately. Execution
is then permissionless and needs no sender key: the keeper authorizes only its
own call (which is what entitles it to the fee and prevents front-running).
Escrowing up front is the load-bearing choice — it removes the "keeper executes
an unfunded intent and wastes gas" failure mode entirely, at the cost of
locking the sender's capital from scheduling until the last occurrence (or
expiry). Recurring intents are modeled as N independent one-shot executions of
a fixed-window recurrence, so catch-up and partial progress need no migration
state. The full threat model (replay, front-running, under-funded-keeper
griefing) is in [`SCHEDULED_INTENTS.md`](./SCHEDULED_INTENTS.md).

## 9. Testing strategy

- **Unit tests** (`test.rs`) cover every spec edge case: withdraw before
  start / at / after end, sequential partial withdrawals, cancel before start
  / fully-withdrawn / not-cancelable, top-up after end, zero-duration and
  zero-amount rejection, `i128::MAX`-scale checked math, event emission
  (typed, per-contract-filtered), and a malicious-token reentrancy attempt.
- **Property test**: random `(deposit, duration)` — for random sample points
  `t ≤ duration`, the sum of payouts up to `t` never exceeds
  `streamed_at(deposit, duration, t)`, and `streamed_at(..., duration) ==
  deposit` exactly.
- **Rate math is pure** (`streamed_at` takes no `Env`), so the `cargo-fuzz`
  target in [`fuzz/`](../fuzz/fuzz_targets/streamed_at.rs) hammers it without
  a Soroban host: bounds, exact floor-ratio reference comparison,
  monotonicity, and "errors are only ever genuine `MathOverflow`". CI runs a
  scheduled session (`fuzz.yml`, non-blocking); any crash becomes a regression
  unit test.
- **`withdraw_max`** shares the `withdraw` payout tail (`pay_out`) so both
  paths inherit the same CEI ordering and reentrancy proof; index pagination
  and TTL behavior have dedicated tests in `test.rs`.
- **Scheduled intents** (`schedule_test.rs`) cover the full lifecycle:
  one-shot and recurring execution, double-execution rejection, the
  cancel/execute race, expired-auth replay, permissionless reclaim, refund
  accounting, and every validation/error path.

## 10. Open problems / roadmap hooks

- `pause_stream` (sender-initiated temporary hold) — needs a fourth status and
  careful `cancel_amounts` treatment; drafted as a good-first-issue.
- Multi-token batch creation — one tx, N streams; watch the instruction
  budget, likely `try_create_batch` with per-item results.
- Gas optimization pass on storage reads — `cancel_stream` does one
  read-modify-write; a `Stream` split into hot/cold fields could shave bytes.
- Event indexer service — TypeScript worker polling `getEvents` per topic
  `stream_id`, materializing stream history for the UI.

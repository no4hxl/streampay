//! Error types for StreamPay.
//!
//! Every expected failure is expressed as a [`StreamError`] variant with a
//! stable numeric code, so clients can branch on failures without parsing
//! strings. The contract never panics on expected failure paths: all public
//! entrypoints return `Result<_, StreamError>` and all arithmetic is checked.
//!
//! Codes are part of the public interface — never renumber or reuse a variant;
//! only append new ones.

use soroban_sdk::contracterror;

/// Errors returned by the StreamPay contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StreamError {
    /// No stream exists with the provided id.
    StreamNotFound = 1,
    /// The caller is not the sender of the stream.
    NotStreamSender = 2,
    /// The caller is not the recipient of the stream.
    NotStreamRecipient = 3,
    /// The stream is not `cancelable`, so the recipient cannot cancel it.
    StreamNotCancellable = 4,
    /// The stream is cancelled or depleted; the operation is not permitted.
    StreamNotActive = 5,
    /// `start_time` is before the current ledger timestamp.
    StartTimeInPast = 6,
    /// `end_time` is not strictly after `start_time`.
    InvalidTimeRange = 7,
    /// The stream duration exceeds the maximum supported duration.
    DurationTooLong = 8,
    /// A provided amount (deposit, top-up, or withdrawal) is zero or negative.
    ZeroAmount = 9,
    /// The requested withdrawal exceeds the accrued, unwithdrawn balance.
    AmountExceedsAvailable = 10,
    /// An intermediate computation would overflow; all math is checked.
    MathOverflow = 11,
    /// The caller is not permitted to perform this action.
    NotAuthorized = 12,
    /// `withdraw_max` found nothing accrued-but-unwithdrawn to pay out.
    NothingToWithdraw = 13,
    /// No scheduled intent exists with the provided id.
    IntentNotFound = 14,
    /// The scheduled intent is not pending (already executed, cancelled, or
    /// expired), so the operation is not permitted.
    IntentNotPending = 15,
    /// Execution was attempted before the intent's `execute_after` (for the
    /// next outstanding occurrence).
    IntentNotYetExecutable = 16,
    /// Execution or cancellation was attempted at/after the intent's
    /// `expires_at`; the funds are reclaimable via `reclaim_expired`.
    IntentExpired = 17,
    /// The sender tried to cancel an intent whose execution window has already
    /// opened; cancellation is only allowed before `execute_after`.
    IntentNotCancellable = 18,
    /// The scheduling parameters are inconsistent (bad occurrence/interval
    /// combination, negative fee budget, ordering of `execute_after` /
    /// `start_time` / `expires_at`, or an overflowing recurrence window).
    InvalidScheduleParameters = 19,
    /// A defensive integrity check failed: the stored intent's parameters no
    /// longer hash to the commitment recorded when it was scheduled.
    IntentParamsMismatch = 20,
    /// `reclaim_expired` was called before the intent's `expires_at`.
    IntentNotExpired = 21,
}

//! Bounded control-plane coordinator for asynchronous `StateAxis` KV restores.
//!
//! Device copies remain owned by the host. This crate owns the hard parts that
//! are independent of an accelerator runtime: identity validation, duplicate
//! coalescing, bounded admission, one active lease per state generation, and
//! transactional completion or retry.

use std::collections::{BTreeMap, VecDeque};

pub type StateKey = (u64, u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransferIdentity {
    pub state_id: u64,
    pub generation: u64,
    pub snapshot_sha256: [u8; 32],
}

impl TransferIdentity {
    #[must_use]
    pub const fn state_key(self) -> StateKey {
        (self.state_id, self.generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferConfig {
    pub max_pending_keys: usize,
    pub max_correlations: usize,
    pub max_retries: u32,
}

impl TransferConfig {
    /// Validate nonzero queue bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidBounds`] if either bound is zero.
    pub fn validate(self) -> Result<Self, AdmissionError> {
        if self.max_pending_keys == 0 || self.max_correlations == 0 {
            return Err(AdmissionError::InvalidBounds);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferStats {
    pub submitted: u64,
    pub admitted: u64,
    pub coalesced: u64,
    pub identity_conflicts: u64,
    pub capacity_rejections: u64,
    pub begun: u64,
    pub committed: u64,
    pub aborted: u64,
    pub retried: u64,
    pub failed: u64,
    pub completed_correlations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Admitted,
    Coalesced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    InvalidBounds,
    InvalidIdentity,
    DuplicateCorrelation,
    IdentityConflict,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionError {
    UnknownLease,
    LeaseMismatch,
    RetryBudgetExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferLease {
    pub lease_id: u64,
    pub identity: TransferIdentity,
    pub correlations: Vec<u64>,
    pub attempt: u32,
}

#[derive(Clone, Debug)]
struct Pending {
    identity: TransferIdentity,
    correlations: Vec<u64>,
    attempt: u32,
    lease_id: Option<u64>,
}

/// Deterministic, bounded coordinator. All mutating methods require `&mut self`;
/// hosts choose their own mutex/executor and cannot accidentally race it.
pub struct TransferCoordinator {
    config: TransferConfig,
    pending: BTreeMap<StateKey, Pending>,
    queue: VecDeque<StateKey>,
    correlations: BTreeMap<u64, StateKey>,
    next_lease_id: u64,
    stats: TransferStats,
}

impl TransferCoordinator {
    /// Construct an empty coordinator with validated bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidBounds`] for a zero queue bound.
    pub fn new(config: TransferConfig) -> Result<Self, AdmissionError> {
        Ok(Self {
            config: config.validate()?,
            pending: BTreeMap::new(),
            queue: VecDeque::new(),
            correlations: BTreeMap::new(),
            next_lease_id: 1,
            stats: TransferStats::default(),
        })
    }

    /// Admit or coalesce a correlation under an exact transfer identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, reused correlation IDs, identity conflicts,
    /// or work that would exceed either configured bound.
    pub fn submit(
        &mut self,
        identity: TransferIdentity,
        correlation_id: u64,
    ) -> Result<Admission, AdmissionError> {
        self.stats.submitted += 1;
        if identity.state_id == 0 || identity.generation == 0 || identity.snapshot_sha256 == [0; 32]
        {
            return Err(AdmissionError::InvalidIdentity);
        }
        if self.correlations.contains_key(&correlation_id) {
            return Err(AdmissionError::DuplicateCorrelation);
        }
        let key = identity.state_key();
        if let Some(work) = self.pending.get_mut(&key) {
            if work.identity != identity {
                self.stats.identity_conflicts += 1;
                return Err(AdmissionError::IdentityConflict);
            }
            if self.correlations.len() >= self.config.max_correlations {
                self.stats.capacity_rejections += 1;
                return Err(AdmissionError::CapacityExceeded);
            }
            work.correlations.push(correlation_id);
            self.correlations.insert(correlation_id, key);
            self.stats.coalesced += 1;
            return Ok(Admission::Coalesced);
        }
        if self.pending.len() >= self.config.max_pending_keys
            || self.correlations.len() >= self.config.max_correlations
        {
            self.stats.capacity_rejections += 1;
            return Err(AdmissionError::CapacityExceeded);
        }
        self.pending.insert(
            key,
            Pending {
                identity,
                correlations: vec![correlation_id],
                attempt: 0,
                lease_id: None,
            },
        );
        self.correlations.insert(correlation_id, key);
        self.queue.push_back(key);
        self.stats.admitted += 1;
        Ok(Admission::Admitted)
    }

    #[must_use]
    pub fn begin_next(&mut self) -> Option<TransferLease> {
        let key = self.queue.pop_front()?;
        let work = self.pending.get_mut(&key)?;
        debug_assert!(work.lease_id.is_none());
        let lease_id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.checked_add(1).unwrap_or(1);
        work.lease_id = Some(lease_id);
        work.attempt += 1;
        self.stats.begun += 1;
        Some(TransferLease {
            lease_id,
            identity: work.identity,
            correlations: work.correlations.clone(),
            attempt: work.attempt,
        })
    }

    /// Publish successful completion and release every coalesced correlation.
    ///
    /// # Errors
    ///
    /// Rejects unknown, stale, or forged leases without changing admitted work.
    pub fn commit(&mut self, lease: &TransferLease) -> Result<Vec<u64>, CompletionError> {
        let key = self.validate_lease(lease)?;
        let work = self
            .pending
            .remove(&key)
            .ok_or(CompletionError::UnknownLease)?;
        for correlation in &work.correlations {
            self.correlations.remove(correlation);
        }
        self.stats.committed += 1;
        self.stats.completed_correlations += work.correlations.len() as u64;
        Ok(work.correlations)
    }

    /// Abort an active lease, optionally requeueing it within the retry budget.
    ///
    /// # Errors
    ///
    /// Rejects invalid leases. A request to retry beyond the configured budget
    /// fails the work closed and returns [`CompletionError::RetryBudgetExhausted`].
    pub fn abort(
        &mut self,
        lease: &TransferLease,
        retry: bool,
    ) -> Result<Vec<u64>, CompletionError> {
        let key = self.validate_lease(lease)?;
        self.stats.aborted += 1;
        if retry {
            let work = self
                .pending
                .get_mut(&key)
                .ok_or(CompletionError::UnknownLease)?;
            if work.attempt > self.config.max_retries {
                let correlations = self.fail_key(key);
                return Err(if correlations.is_empty() {
                    CompletionError::UnknownLease
                } else {
                    CompletionError::RetryBudgetExhausted
                });
            }
            work.lease_id = None;
            self.queue.push_back(key);
            self.stats.retried += 1;
            return Ok(Vec::new());
        }
        Ok(self.fail_key(key))
    }

    fn validate_lease(&self, lease: &TransferLease) -> Result<StateKey, CompletionError> {
        let key = lease.identity.state_key();
        let work = self
            .pending
            .get(&key)
            .ok_or(CompletionError::UnknownLease)?;
        if work.identity != lease.identity
            || work.lease_id != Some(lease.lease_id)
            || work.attempt != lease.attempt
        {
            return Err(CompletionError::LeaseMismatch);
        }
        Ok(key)
    }

    fn fail_key(&mut self, key: StateKey) -> Vec<u64> {
        let Some(work) = self.pending.remove(&key) else {
            return Vec::new();
        };
        self.queue.retain(|candidate| *candidate != key);
        for correlation in &work.correlations {
            self.correlations.remove(correlation);
        }
        self.stats.failed += 1;
        work.correlations
    }

    #[must_use]
    pub fn stats(&self) -> TransferStats {
        self.stats
    }

    #[must_use]
    pub fn pending_keys(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn pending_correlations(&self) -> usize {
        self.correlations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(state_id: u64, generation: u64, byte: u8) -> TransferIdentity {
        TransferIdentity {
            state_id,
            generation,
            snapshot_sha256: [byte; 32],
        }
    }

    fn coordinator() -> TransferCoordinator {
        TransferCoordinator::new(TransferConfig {
            max_pending_keys: 2,
            max_correlations: 3,
            max_retries: 1,
        })
        .unwrap()
    }

    #[test]
    fn coalesces_only_exact_identity_and_commits_all_correlations() {
        let mut lane = coordinator();
        assert_eq!(lane.submit(identity(7, 2, 3), 11), Ok(Admission::Admitted));
        assert_eq!(lane.submit(identity(7, 2, 3), 12), Ok(Admission::Coalesced));
        assert_eq!(
            lane.submit(identity(7, 2, 4), 13),
            Err(AdmissionError::IdentityConflict)
        );
        let lease = lane.begin_next().unwrap();
        assert_eq!(lane.commit(&lease), Ok(vec![11, 12]));
        assert_eq!(lane.pending_keys(), 0);
        assert_eq!(lane.stats().completed_correlations, 2);
    }

    #[test]
    fn enforces_bounds_without_mutating_admitted_work() {
        let mut lane = coordinator();
        lane.submit(identity(1, 1, 1), 1).unwrap();
        lane.submit(identity(2, 1, 2), 2).unwrap();
        assert_eq!(
            lane.submit(identity(3, 1, 3), 3),
            Err(AdmissionError::CapacityExceeded)
        );
        assert_eq!(lane.pending_keys(), 2);
        assert_eq!(lane.pending_correlations(), 2);
    }

    #[test]
    fn abort_requeues_once_then_fails_closed() {
        let mut lane = coordinator();
        lane.submit(identity(1, 1, 1), 41).unwrap();
        let first = lane.begin_next().unwrap();
        assert_eq!(lane.abort(&first, true), Ok(Vec::new()));
        let second = lane.begin_next().unwrap();
        assert_eq!(second.attempt, 2);
        assert_eq!(
            lane.abort(&second, true),
            Err(CompletionError::RetryBudgetExhausted)
        );
        assert_eq!(lane.pending_keys(), 0);
        assert_eq!(lane.stats().failed, 1);
    }

    #[test]
    fn stale_or_forged_lease_cannot_complete_work() {
        let mut lane = coordinator();
        lane.submit(identity(9, 4, 5), 1).unwrap();
        let mut forged = lane.begin_next().unwrap();
        forged.lease_id += 1;
        assert_eq!(lane.commit(&forged), Err(CompletionError::LeaseMismatch));
        assert_eq!(lane.pending_keys(), 1);
    }
}

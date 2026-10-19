//! Lease-safe, collision-verified, bounded prefix-cache index.
//!
//! The index owns only lookup metadata and opaque state handles. The host keeps
//! lifecycle authority: it decides whether a state is resident or leased and
//! performs any device eviction returned by [`PrefixCacheIndex::insert`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

const PREFIX_CACHE_SCHEMA: &str = "native-prefix-cache-block-root-v1";
const TOKEN_BLOCK_SCHEMA: &[u8] = b"native-prefix-cache-token-block-v1\0";

pub type StateKey = (u64, u64);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheDomain {
    namespace_sha256: [u8; 32],
    salt_sha256: [u8; 32],
}

impl CacheDomain {
    pub fn new(namespace_bytes: &[u8], salt: Option<&str>) -> Self {
        Self {
            namespace_sha256: *blake3::hash(namespace_bytes).as_bytes(),
            salt_sha256: *blake3::hash(salt.unwrap_or("").as_bytes()).as_bytes(),
        }
    }
}

#[derive(Clone, Debug)]
struct Entry<V> {
    tokens: Arc<[u32]>,
    block_hashes: Arc<[[u8; 32]]>,
    key: StateKey,
    value: V,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixCacheHit<V> {
    pub value: V,
    pub reused_tokens: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupOutcome<V> {
    pub hit: Option<PrefixCacheHit<V>>,
    pub hash_collisions: u64,
    pub stale_entries: u64,
}

impl<V> Default for LookupOutcome<V> {
    fn default() -> Self {
        Self {
            hit: None,
            hash_collisions: 0,
            stale_entries: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertOutcome<V> {
    pub inserted: bool,
    pub evicted: Option<V>,
    pub lease_blocked: bool,
}

impl<V> Default for InsertOutcome<V> {
    fn default() -> Self {
        Self {
            inserted: false,
            evicted: None,
            lease_blocked: false,
        }
    }
}

/// Metadata index for cache-owned prefix states.
pub struct PrefixCacheIndex<V> {
    enabled: bool,
    block_tokens: usize,
    max_entries: usize,
    entries: HashMap<CacheDomain, BTreeMap<usize, HashMap<[u8; 32], Vec<Entry<V>>>>>,
    state_keys: HashMap<StateKey, (CacheDomain, usize, [u8; 32])>,
    lru: VecDeque<StateKey>,
}

impl<V> Default for PrefixCacheIndex<V> {
    fn default() -> Self {
        Self {
            enabled: false,
            block_tokens: 1,
            max_entries: 0,
            entries: HashMap::new(),
            state_keys: HashMap::new(),
            lru: VecDeque::new(),
        }
    }
}

impl<V: Clone> PrefixCacheIndex<V> {
    pub fn new(enabled: bool, block_tokens: u32, max_entries: usize) -> Self {
        Self {
            enabled,
            block_tokens: usize::try_from(block_tokens)
                .ok()
                .filter(|tokens| *tokens > 0)
                .unwrap_or(1),
            max_entries,
            ..Self::default()
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn len(&self) -> usize {
        self.state_keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state_keys.is_empty()
    }

    fn block_hashes(&self, tokens: &[u32]) -> Vec<[u8; 32]> {
        tokens
            .chunks(self.block_tokens)
            .map(|block| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(TOKEN_BLOCK_SCHEMA);
                hasher.update(&(block.len() as u64).to_le_bytes());
                for token in block {
                    hasher.update(&token.to_le_bytes());
                }
                *hasher.finalize().as_bytes()
            })
            .collect()
    }

    fn root(domain: &CacheDomain, token_len: usize, blocks: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREFIX_CACHE_SCHEMA.as_bytes());
        hasher.update(&domain.namespace_sha256);
        hasher.update(&domain.salt_sha256);
        hasher.update(&(token_len as u64).to_le_bytes());
        for block in blocks {
            hasher.update(block);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn insert<F>(
        &mut self,
        namespace_bytes: &[u8],
        salt: Option<&str>,
        tokens: &[u32],
        key: StateKey,
        context_len: usize,
        value: V,
        mut is_leased: F,
    ) -> InsertOutcome<V>
    where
        F: FnMut(StateKey) -> bool,
    {
        if !self.enabled
            || tokens.is_empty()
            || context_len != tokens.len()
            || self.max_entries == 0
        {
            return InsertOutcome::default();
        }
        self.remove(key);
        let evicted = if self.state_keys.len() >= self.max_entries {
            let victim = self.lru.iter().copied().find(|key| !is_leased(*key));
            let Some(victim) = victim else {
                return InsertOutcome {
                    lease_blocked: true,
                    ..InsertOutcome::default()
                };
            };
            self.remove(victim)
        } else {
            None
        };
        let domain = CacheDomain::new(namespace_bytes, salt);
        let block_hashes = self.block_hashes(tokens);
        let root = Self::root(&domain, tokens.len(), &block_hashes);
        self.entries
            .entry(domain.clone())
            .or_default()
            .entry(tokens.len())
            .or_default()
            .entry(root)
            .or_default()
            .push(Entry {
                tokens: Arc::from(tokens),
                block_hashes: Arc::from(block_hashes),
                key,
                value,
            });
        self.state_keys.insert(key, (domain, tokens.len(), root));
        self.lru.push_back(key);
        InsertOutcome {
            inserted: true,
            evicted,
            lease_blocked: false,
        }
    }

    pub fn lookup<F>(
        &mut self,
        namespace_bytes: &[u8],
        salt: Option<&str>,
        tokens: &[u32],
        mut is_resident: F,
    ) -> LookupOutcome<V>
    where
        F: FnMut(StateKey, &V) -> bool,
    {
        let mut outcome = LookupOutcome::default();
        if !self.enabled {
            return outcome;
        }
        let domain = CacheDomain::new(namespace_bytes, salt);
        let Some(lengths) = self.entries.get(&domain) else {
            return outcome;
        };
        for (&length, roots) in lengths.range(..=tokens.len()).rev() {
            let prefix = &tokens[..length];
            let blocks = self.block_hashes(prefix);
            let root = Self::root(&domain, length, &blocks);
            let Some(bucket) = roots.get(&root) else {
                continue;
            };
            for entry in bucket {
                if entry.block_hashes.as_ref() != blocks.as_slice()
                    || entry.tokens.as_ref() != prefix
                {
                    outcome.hash_collisions += 1;
                    continue;
                }
                if is_resident(entry.key, &entry.value) {
                    self.lru.retain(|candidate| *candidate != entry.key);
                    self.lru.push_back(entry.key);
                    outcome.hit = Some(PrefixCacheHit {
                        value: entry.value.clone(),
                        reused_tokens: length,
                    });
                    return outcome;
                }
                outcome.stale_entries += 1;
            }
        }
        outcome
    }

    pub fn contains(&self, key: StateKey) -> bool {
        self.state_keys.contains_key(&key)
    }

    pub fn remove(&mut self, key: StateKey) -> Option<V> {
        let (domain, length, root) = self.state_keys.remove(&key)?;
        self.lru.retain(|candidate| *candidate != key);
        let mut removed = None;
        let mut remove_domain = false;
        if let Some(lengths) = self.entries.get_mut(&domain) {
            let mut remove_length = false;
            if let Some(roots) = lengths.get_mut(&length) {
                let mut remove_root = false;
                if let Some(bucket) = roots.get_mut(&root) {
                    if let Some(index) = bucket.iter().position(|entry| entry.key == key) {
                        removed = Some(bucket.remove(index).value);
                    }
                    remove_root = bucket.is_empty();
                }
                if remove_root {
                    roots.remove(&root);
                }
                remove_length = roots.is_empty();
            }
            if remove_length {
                lengths.remove(&length);
            }
            remove_domain = lengths.is_empty();
        }
        if remove_domain {
            self.entries.remove(&domain);
        }
        removed
    }

    #[doc(hidden)]
    pub fn inject_collision_for_test(
        &mut self,
        namespace_bytes: &[u8],
        salt: Option<&str>,
        indexed_tokens: &[u32],
        conflicting_tokens: &[u32],
        key: StateKey,
        value: V,
    ) {
        let domain = CacheDomain::new(namespace_bytes, salt);
        let block_hashes = self.block_hashes(indexed_tokens);
        let root = Self::root(&domain, indexed_tokens.len(), &block_hashes);
        self.entries
            .entry(domain)
            .or_default()
            .entry(indexed_tokens.len())
            .or_default()
            .entry(root)
            .or_default()
            .insert(
                0,
                Entry {
                    tokens: Arc::from(conflicting_tokens),
                    block_hashes: Arc::from(block_hashes),
                    key,
                    value,
                },
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_is_domain_salted_and_collision_verified() {
        let mut index = PrefixCacheIndex::new(true, 2, 4);
        assert!(
            index
                .insert(
                    b"namespace-a",
                    Some("tenant-a"),
                    &[10, 20, 30, 40],
                    (1, 1),
                    4,
                    "state-a",
                    |_| false
                )
                .inserted
        );
        let hit = index.lookup(
            b"namespace-a",
            Some("tenant-a"),
            &[10, 20, 30, 40, 50],
            |key, value| key == (1, 1) && *value == "state-a",
        );
        assert_eq!(hit.hit.unwrap().reused_tokens, 4);
        assert!(index
            .lookup(
                b"namespace-a",
                Some("tenant-b"),
                &[10, 20, 30, 40],
                |_, _| true
            )
            .hit
            .is_none());
        index.inject_collision_for_test(
            b"namespace-a",
            Some("tenant-a"),
            &[10, 20, 30, 40],
            &[10, 20, 30, 99],
            (9, 9),
            "collision",
        );
        let verified = index.lookup(
            b"namespace-a",
            Some("tenant-a"),
            &[10, 20, 30, 40],
            |key, _| key == (1, 1),
        );
        assert_eq!(verified.hash_collisions, 1);
        assert_eq!(verified.hit.unwrap().value, "state-a");
    }

    #[test]
    fn lru_eviction_skips_leases_and_fails_closed_when_all_are_leased() {
        let mut index = PrefixCacheIndex::new(true, 2, 2);
        for id in 1..=2 {
            assert!(
                index
                    .insert(
                        b"ns",
                        Some(&id.to_string()),
                        &[1, 2],
                        (id, 1),
                        2,
                        id,
                        |_| false
                    )
                    .inserted
            );
        }
        assert!(index
            .lookup(b"ns", Some("1"), &[1, 2], |_, _| true)
            .hit
            .is_some());
        let replacement = index.insert(b"ns", Some("3"), &[1, 2], (3, 1), 2, 3, |_| false);
        assert_eq!(replacement.evicted, Some(2));
        assert!(index.contains((1, 1)));
        assert!(index.contains((3, 1)));

        let blocked = index.insert(b"ns", Some("4"), &[1, 2], (4, 1), 2, 4, |_| true);
        assert!(blocked.lease_blocked);
        assert!(!blocked.inserted);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn stale_generation_never_authorizes_reuse() {
        let mut index = PrefixCacheIndex::new(true, 2, 1);
        index.insert(b"ns", None, &[1, 2], (7, 3), 2, "generation-3", |_| false);
        let outcome = index.lookup(b"ns", None, &[1, 2], |key, _| key == (7, 4));
        assert!(outcome.hit.is_none());
        assert_eq!(outcome.stale_entries, 1);
    }
}

use super::batch::PUBLIC_KEY_LEN;
use super::cache::{CachedPublicKey, KeyCache};
use std::cell::Cell;
use std::collections::HashMap;

/// Eligible eviction candidates sampled per eviction.
const EVICTION_SAMPLE: usize = 8;

#[derive(Clone, Debug)]
struct CacheEntry {
    key: CachedPublicKey,
    last_used: Cell<u64>,
}

/// A [`KeyCache`] that retains hot decoded keys across batches.
#[derive(Debug)]
pub struct HotKeyCache {
    keys: HashMap<[u8; PUBLIC_KEY_LEN], CacheEntry>,
    capacity: usize,
    clock: Cell<u64>,
    /// Rotating start offset for the eviction sampling window.
    evict_cursor: usize,
}

impl HotKeyCache {
    /// Create a cache bounded to `capacity` retained keys, at least one.
    ///
    /// This is the only constructor on purpose. Each retained key costs a
    /// precomputed multiple table (roughly 2.7 KiB) and the verifier retains
    /// every distinct public key it successfully decodes, so an unbounded
    /// variant would let a peer sending attacker-chosen keys grow this map
    /// without limit: 1M distinct keys is on the order of 2.7 GiB. Callers that
    /// really do have a known-bounded key set can pass that bound.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: HashMap::new(),
            capacity: capacity.max(1),
            clock: Cell::new(0),
            evict_cursor: 0,
        }
    }

    /// Set the maximum retained key count, evicting down to it immediately.
    /// Clamped to at least one key.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        self.evict_to_capacity(None);
    }

    fn tick(&self) -> u64 {
        let next = self.clock.get().wrapping_add(1);
        self.clock.set(next);
        next
    }

    fn touch(&self, entry: &CacheEntry) {
        entry.last_used.set(self.tick());
    }

    fn insert_cached(&mut self, key: CachedPublicKey) {
        let last_used = self.tick();
        let encoded = key.encoded;
        self.keys.insert(
            encoded,
            CacheEntry {
                key,
                last_used: Cell::new(last_used),
            },
        );
        self.evict_to_capacity(Some(encoded));
    }

    fn evict_to_capacity(&mut self, protected: Option<[u8; PUBLIC_KEY_LEN]>) {
        while self.keys.len() > self.capacity {
            // `HashMap::iter` yields a fixed order for a given map, so sampling
            // the first `EVICTION_SAMPLE` entries every time would keep
            // reconsidering the same head and never look at most of the cache
            // — evicting hot keys while cold ones further in are untouchable.
            // Rotate the sampling window instead.
            let len = self.keys.len();
            let offset = self.evict_cursor % len;
            self.evict_cursor = offset.wrapping_add(EVICTION_SAMPLE);

            let victim = self
                .keys
                .iter()
                .cycle()
                // Bound the scan to one full rotation so an all-protected
                // cache cannot spin forever on the infinite `cycle`.
                .skip(offset)
                .take(len)
                .filter(|(encoded, _)| Some(**encoded) != protected)
                .take(EVICTION_SAMPLE)
                .min_by_key(|(_, entry)| entry.last_used.get())
                .map(|(encoded, _)| *encoded);

            let Some(victim) = victim else {
                break;
            };
            self.keys.remove(&victim);
        }
    }
}

impl super::cache::private::Sealed for HotKeyCache {}

impl KeyCache for HotKeyCache {
    #[inline]
    fn get(&self, encoded: &[u8; PUBLIC_KEY_LEN]) -> Option<&CachedPublicKey> {
        let entry = self.keys.get(encoded)?;
        self.touch(entry);
        Some(&entry.key)
    }

    fn insert(&mut self, key: CachedPublicKey) {
        if let Some(entry) = self.keys.get(&key.encoded) {
            self.touch(entry);
        } else {
            self.insert_cached(key);
        }
    }
}

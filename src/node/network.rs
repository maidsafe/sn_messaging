// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::{consensus::Proven, section::EldersInfo};

use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::{btree_set, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    iter::FromIterator,
};
use threshold_crypto::PublicKey;
use xor_name::{Prefix, XorName};

/// Container for storing information about other sections in the network.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Network {
    // Neighbour sections: maps section prefixes to their latest signed elders infos.
    neighbours: PrefixMap<Proven<EldersInfo>>,
    // BLS public keys of known sections excluding ours.
    keys: PrefixMap<Proven<(Prefix, PublicKey)>>,
    // Indices of our section keys that are trusted by other sections.
    knowledge: PrefixMap<Proven<(Prefix, u64)>>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            neighbours: Default::default(),
            keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    pub fn closest(&self, name: &XorName) -> Option<&EldersInfo> {
        self.all()
            .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, name))
    }

    /// Returns iterator over all known sections.
    pub fn all(&self) -> impl Iterator<Item = &EldersInfo> + Clone {
        self.neighbours.iter().map(|info| &info.value)
    }
    /*
        /// Get `EldersInfo` of a known section with the given prefix.
        pub fn get(&self, prefix: &Prefix) -> Option<&EldersInfo> {
            self.neighbours.get(prefix).map(|info| &info.value)
        }

        /// Returns prefixes of all known sections.
        pub fn prefixes(&self) -> impl Iterator<Item = &Prefix> + Clone {
            self.all().map(|elders_info| &elders_info.prefix)
        }

        /// Returns all elders from all known sections.
        pub fn elders(&self) -> impl Iterator<Item = &Peer> {
            self.all().flat_map(|info| info.elders.values())
        }

        /// Returns a `Peer` of an elder from a known section.
        pub fn get_elder(&self, name: &XorName) -> Option<&Peer> {
            self.neighbours.get_matching(name)?.value.elders.get(name)
        }

        /// Merge two `Network`s into one.
        /// TODO: make this operation commutative, associative and idempotent (CRDT)
        /// TODO: return bool indicating whether anything changed.
        pub fn merge(&mut self, other: Self, section_chain: &SectionProofChain) {
            // FIXME: these operations are not commutative:

            for entry in other.neighbours {
                if entry.verify(section_chain) {
                    let _ = self.neighbours.insert(entry);
                }
            }

            for entry in other.keys {
                if entry.verify(section_chain) {
                    let _ = self.keys.insert(entry);
                }
            }

            for entry in other.knowledge {
                if entry.verify(section_chain) {
                    let _ = self.knowledge.insert(entry);
                }
            }
        }

        pub fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
            // TODO: verify
            // if !elders_info.verify(section_chain) {
            //     return false;
            // }

            if let Some(old) = self.neighbours.insert(elders_info.clone()) {
                if old == elders_info {
                    return false;
                }
            }

            true
        }

        /// Updates the entry in `keys` for `prefix` to the latest known key.
        pub fn update_their_key(&mut self, new_key: Proven<(Prefix, bls::PublicKey)>) -> bool {
            // TODO: verify against section chain

            trace!(
                "update key for {:?}: {:?}",
                new_key.value.0,
                new_key.value.1
            );

            if let Some(old) = self.keys.insert(new_key.clone()) {
                if old == new_key {
                    return false;
                }
            }

            true
        }

        /// Remove sections that are no longer our neighbours.
        pub fn prune_neighbours(&mut self, our_prefix: &Prefix) {
            let to_remove: Vec<_> = self
                .neighbours
                .prefixes()
                .filter(|prefix| {
                    can_prune_neighbour(
                        our_prefix,
                        prefix,
                        self.neighbours
                            .descendants(prefix)
                            .map(|info| &info.value.prefix),
                    )
                })
                .copied()
                .collect();

            for prefix in to_remove {
                let _ = self.neighbours.remove(&prefix);
            }
        }

        /// Returns the known section keys.
        pub fn keys(&self) -> impl Iterator<Item = (&Prefix, &bls::PublicKey)> {
            self.keys
                .iter()
                .map(|entry| (&entry.value.0, &entry.value.1))
        }

        pub fn has_key(&self, key: &bls::PublicKey) -> bool {
            self.keys.iter().any(|entry| entry.value.1 == *key)
        }
    */
    /// Returns the latest known key for the prefix that matches `name`.
    pub fn key_by_name(&self, name: &XorName) -> Option<&PublicKey> {
        self.keys.get_matching(name).map(|entry| &entry.value.1)
    }

    /// Returns the elders_info and the latest known key for the prefix that matches `name`,
    /// excluding self section.
    pub fn section_by_name(&self, name: &XorName) -> (Option<PublicKey>, Option<EldersInfo>) {
        (
            self.keys.get_matching(name).map(|entry| entry.value.1),
            self.neighbours
                .get_matching(name)
                .map(|entry| entry.value.clone()),
        )
    }
    /*
    /// Returns the index of the public key in our_history that will be trusted by the given
    /// section.
    pub fn knowledge_by_section(&self, prefix: &Prefix) -> u64 {
        self.knowledge
            .get_equal_or_ancestor(prefix)
            .map(|entry| entry.value.1)
            .unwrap_or(0)
    }

    /// Returns the index of the public key in our chain that will be trusted by the given
    /// location
    pub fn knowledge_by_location(&self, dst: &DstLocation) -> u64 {
        let name = if let Some(name) = dst.name() {
            name
        } else {
            return 0;
        };

        let (prefix, index) = if let Some(entry) = self.knowledge.get_matching(name) {
            (&entry.value.0, entry.value.1)
        } else {
            return 0;
        };

        // TODO: we might not need to do this anymore because we have the bounce untrusted messages
        // mechanism now.
        if let Some(sibling_entry) = self.knowledge.get_equal_or_ancestor(&prefix.sibling()) {
            // The sibling section might not have processed the split yet, so it might still be in
            // `dst`'s location. Because of that, we need to return index that would be trusted
            // by them too.
            index.min(sibling_entry.value.1)
        } else {
            index
        }
    }

    /// Updates the entry in `knowledge` for `prefix` to `new_index`; if a split
    /// occurred in the meantime, the index for sections covering the rest of the address space
    /// are initialised to the old index that was stored for their common ancestor
    pub fn update_knowledge(&mut self, new_index: Proven<(Prefix, u64)>) {
        trace!(
            "update knowledge of section ({:b}) about our section to {}",
            new_index.value.0,
            new_index.value.1,
        );

        let _ = self.knowledge.insert(new_index);
    }

    /// Returns network statistics.
    pub fn network_stats(&self, our: &EldersInfo) -> NetworkStats {
        let (known_elders, total_elders, total_elders_exact) = self.network_elder_counts(our);

        NetworkStats {
            known_elders,
            total_elders,
            total_elders_exact,
        }
    }

    // Compute an estimate of the total number of elders in the network from the size of our
    // routing table.
    //
    // Return (known, total, exact), where `exact` indicates whether `total` is an exact number of
    // an estimate.
    fn network_elder_counts(&self, our: &EldersInfo) -> (u64, u64, bool) {
        let known_prefixes = iter::once(&our.prefix).chain(self.prefixes());
        let is_exact = Prefix::default().is_covered_by(known_prefixes.clone());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        let known = our.elders.len() + self.elders().count();
        let total = known as f64 / network_fraction;

        (known as u64, total.ceil() as u64, is_exact)
    }*/
}

/// Container that acts as a map whose keys are prefixes.
///
/// It differs from a normal map of `Prefix` -> `T` in a couple of ways:
/// 1. It allows to keep the prefix and the value in the same type which makes it internally more
///    similar to a set of `(Prefix, T)` rather than map of `Prefix` -> `T` while still providing
///    convenient map-like API
/// 2. It automatically prunes redundant entries. That is, when the prefix of an entry is fully
///    covered by other prefixes, that entry is removed. For example, when there is entry with
///    prefix (00) and we insert entries with (000) and (001), the (00) prefix becomes fully
///    covered and is automatically removed.
/// 3. It provides some additional lookup API for convenience (`get_equal_or_ancestor`,
///    `get_matching`, ...)
///
#[derive(Clone, Serialize, Deserialize)]
pub struct PrefixMap<T>(BTreeSet<Entry<T>>)
where
    T: Borrow<Prefix>;

impl<T> Default for PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    /// Create empty `PrefixMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts new entry into the map. Replaces previous entry at the same prefix.
    /// Removes those ancestors of the inserted prefix that are now fully covered by their
    /// descendants.
    /// Does not insert anything if any descendant of the prefix of `entry` is already present in
    /// the map.
    /// Returns the previous entry with the same prefix, if any.
    // TODO: change to return `bool` indicating whether anything changed. It's more useful for our
    // purposes.
    pub fn insert(&mut self, entry: T) -> Option<T> {
        // Don't insert if any descendant is already present in the map.
        if self.descendants(entry.borrow()).next().is_some() {
            return Some(entry);
        }

        let parent_prefix = entry.borrow().popped();
        let old = self.0.replace(Entry(entry));
        self.prune(parent_prefix);
        old.map(|entry| entry.0)
    }

    /// Removes the entry at `prefix` and returns it, if any.
    pub fn remove(&mut self, prefix: &Prefix) -> Option<T> {
        self.0.take(prefix).map(|entry| entry.0)
    }

    /// Get the entry at `prefix`, if any.
    pub fn get(&self, prefix: &Prefix) -> Option<&T> {
        self.0.get(prefix).map(|entry| &entry.0)
    }

    /// Get the entry at `prefix` or any of its ancestors. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub fn get_equal_or_ancestor(&self, prefix: &Prefix) -> Option<&T> {
        let mut prefix = *prefix;
        loop {
            if let Some(entry) = self.get(&prefix) {
                return Some(entry);
            }

            if prefix.is_empty() {
                return None;
            }

            prefix = prefix.popped();
        }
    }

    /// Get the entry at the prefix that matches `name`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub fn get_matching(&self, name: &XorName) -> Option<&T> {
        self.0
            .iter()
            .filter(|entry| entry.prefix().matches(name))
            .max_by_key(|entry| entry.prefix().bit_count())
            .map(|entry| &entry.0)
    }

    /// Returns an iterator over the entries, in order by prefixes.
    pub fn iter(&self) -> impl Iterator<Item = &T> + Clone {
        self.0.iter().map(|entry| &entry.0)
    }

    /// Returns an iterator over the prefixes
    pub fn prefixes(&self) -> impl Iterator<Item = &Prefix> + Clone {
        self.0.iter().map(|entry| entry.prefix())
    }

    /// Returns an iterator over all entries whose prefixes are descendants (extensions) of
    /// `prefix`.
    pub fn descendants<'a>(
        &'a self,
        prefix: &'a Prefix,
    ) -> impl Iterator<Item = &'a T> + Clone + 'a {
        // TODO: there might be a way to do this in O(logn) using BTreeSet::range
        self.0
            .iter()
            .filter(move |entry| entry.0.borrow().is_extension_of(prefix))
            .map(|entry| &entry.0)
    }

    // Remove `prefix` and any of its ancestors if they are covered by their descendants.
    // For example, if `(00)` and `(01)` are both in the map, we can remove `(0)` and `()`.
    fn prune(&mut self, mut prefix: Prefix) {
        // TODO: can this be optimized?

        loop {
            if prefix.is_covered_by(self.descendants(&prefix).map(|entry| entry.borrow())) {
                let _ = self.0.remove(&prefix);
            }

            if prefix.is_empty() {
                break;
            } else {
                prefix = prefix.popped();
            }
        }
    }
}

impl<T> Debug for PrefixMap<T>
where
    T: Borrow<Prefix> + Debug,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> FromIterator<T> for PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        iter.into_iter().fold(Self::new(), |mut map, entry| {
            let _ = map.insert(entry);
            map
        })
    }
}

pub struct IntoIter<T>(btree_set::IntoIter<Entry<T>>);

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|entry| entry.0)
    }
}

impl<T> IntoIterator for PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

// Need to impl this manually, because the derived one would use `PartialEq` of `Entry` which
// compares only the prefixes.
impl<T> PartialEq for PrefixMap<T>
where
    T: Borrow<Prefix> + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(lhs, rhs)| lhs.0 == rhs.0)
    }
}

impl<T> Hash for PrefixMap<T>
where
    T: Borrow<Prefix> + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        for entry in &self.0 {
            entry.0.hash(state)
        }
    }
}

impl<T> Eq for PrefixMap<T> where T: Borrow<Prefix> + Eq {}

impl<T> From<PrefixMap<T>> for BTreeSet<T>
where
    T: Borrow<Prefix> + Ord,
{
    fn from(map: PrefixMap<T>) -> Self {
        map.0.into_iter().map(|entry| entry.0).collect()
    }
}

// Wrapper for entries of `PrefixMap` which implements Eq, Ord by delegating them to the prefix.
#[derive(Clone, Serialize, Deserialize)]
struct Entry<T>(T);

impl<T> Entry<T>
where
    T: Borrow<Prefix>,
{
    fn prefix(&self) -> &Prefix {
        self.0.borrow()
    }
}

impl<T> Borrow<Prefix> for Entry<T>
where
    T: Borrow<Prefix>,
{
    fn borrow(&self) -> &Prefix {
        self.0.borrow()
    }
}

impl<T> PartialEq for Entry<T>
where
    T: Borrow<Prefix>,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.borrow().eq(other.0.borrow())
    }
}

impl<T> Eq for Entry<T> where T: Borrow<Prefix> {}

impl<T> Ord for Entry<T>
where
    T: Borrow<Prefix>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.borrow().cmp(other.0.borrow())
    }
}

impl<T> PartialOrd for Entry<T>
where
    T: Borrow<Prefix>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Debug> Debug for Entry<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

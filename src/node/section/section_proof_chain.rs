// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    iter, mem,
    ops::{Bound, RangeBounds},
};
use thiserror::Error;
use threshold_crypto::{PublicKey, Signature};

/// Chain of section BLS keys where every key is proven (signed) by the previous key, except the
/// first one.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofChain {
    head: PublicKey,
    tail: Vec<Block>,
}

#[allow(clippy::len_without_is_empty)]
impl SectionProofChain {
    /// Creates new chain consisting of only one block.
    pub fn new(first: PublicKey) -> Self {
        Self {
            head: first,
            tail: Vec::new(),
        }
    }

    /// Pushes a new key into the chain but only if the signature is valid.
    /// Returns whether the chain changed.
    pub(crate) fn push(&mut self, key: PublicKey, signature: Signature) -> bool {
        if self.has_key(&key) {
            //trace!("already has key {:?}", key);
            return false;
        }
        let valid = bincode::serialize(&key)
            .map(|bytes| self.last_key().verify(&signature, &bytes))
            .unwrap_or(false);

        if valid {
            self.tail.push(Block { key, signature });
            true
        } else {
            /*error!(
                "invalid SectionProofChain block signature (new key: {:?}, last key: {:?})",
                key,
                self.last_key()
            );*/
            false
        }
    }

    /// Pushed a new key into the chain without validating the signature. For testing only.
    #[cfg(test)]
    pub fn push_without_validation(&mut self, key: PublicKey, signature: Signature) {
        self.tail.push(Block { key, signature })
    }

    /// Returns the first key of the chain.
    pub fn first_key(&self) -> &PublicKey {
        &self.head
    }

    /// Returns the last key of the chain.
    pub fn last_key(&self) -> &PublicKey {
        self.tail
            .last()
            .map(|block| &block.key)
            .unwrap_or(&self.head)
    }

    /// Returns all the keys of the chain as a DoubleEndedIterator.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &PublicKey> {
        iter::once(&self.head).chain(self.tail.iter().map(|block| &block.key))
    }

    /// Returns whether this chain contains the given key.
    pub fn has_key(&self, key: &PublicKey) -> bool {
        self.keys().any(|existing_key| existing_key == key)
    }

    /// Returns the index of the key in the chain or `None` if not present in the chain.
    pub fn index_of(&self, key: &PublicKey) -> Option<u64> {
        self.keys()
            .position(|existing_key| existing_key == key)
            .map(|index| index as u64)
    }

    /// Returns a subset of this chain specified by the given index range.
    ///
    /// Note: unlike `std::slice`, if the range is invalid or out of bounds, it is silently adjusted
    /// to the nearest valid range and so this function never panics.
    pub fn slice<B: RangeBounds<u64>>(&self, range: B) -> Self {
        let start = match range.start_bound() {
            Bound::Included(index) => *index as usize,
            Bound::Excluded(index) => *index as usize + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(index) => *index as usize + 1,
            Bound::Excluded(index) => *index as usize,
            Bound::Unbounded => self.tail.len() + 1,
        };

        let start = start.min(self.tail.len());
        let end = end.min(self.tail.len() + 1).max(start + 1);

        if start == 0 {
            Self {
                head: self.head,
                tail: self.tail[0..end - 1].to_vec(),
            }
        } else {
            Self {
                head: self.tail[start - 1].key,
                tail: self.tail[start..end - 1].to_vec(),
            }
        }
    }

    /// Number of blocks in the chain (including the first block)
    pub fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// Index of the last key in the chain.
    pub fn last_key_index(&self) -> u64 {
        self.tail.len() as u64
    }

    /// Check that all the blocks in the chain except the first one have valid signatures.
    /// The first one cannot be verified and requires matching against already trusted keys. Thus
    /// this function alone cannot be used to determine whether this chain is trusted. Use
    /// `check_trust` for that.
    pub fn self_verify(&self) -> bool {
        let mut current_key = &self.head;
        for block in &self.tail {
            if !block.verify(current_key) {
                return false;
            }

            current_key = &block.key;
        }
        true
    }

    /// Verify this proof chain against the given trusted keys.
    pub fn check_trust<'a, I>(&self, trusted_keys: I) -> TrustStatus
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if let Some((index, mut trusted_key)) = self.latest_trusted_key(trusted_keys) {
            for block in &self.tail[index..] {
                if !block.verify(trusted_key) {
                    return TrustStatus::Invalid;
                }

                trusted_key = &block.key;
            }

            TrustStatus::Trusted
        } else if self.self_verify() {
            TrustStatus::Unknown
        } else {
            TrustStatus::Invalid
        }
    }

    // Extend `self` so it starts at `new_first_key` while keeping the last key intact.
    pub fn extend(
        &mut self,
        new_first_key: &PublicKey,
        full_chain: &Self,
    ) -> Result<(), ExtendError> {
        if self.has_key(new_first_key) {
            return Err(ExtendError::AlreadySufficient);
        }

        let index_from = full_chain
            .index_of(new_first_key)
            .ok_or(ExtendError::InvalidFirstKey)?;

        let index_to = full_chain
            .index_of(self.last_key())
            .ok_or(ExtendError::InvalidLastKey)?;

        if index_from > index_to {
            return Err(ExtendError::InvalidFirstKey);
        }

        *self = full_chain.slice(index_from..=index_to);

        Ok(())
    }

    pub fn merge(&mut self, other: Self) -> Result<(), MergeError> {
        fn check_same_keys<'a>(
            a: impl IntoIterator<Item = &'a PublicKey>,
            b: impl IntoIterator<Item = &'a PublicKey>,
        ) -> Result<(), MergeError> {
            if a.into_iter().zip(b).all(|(a, b)| a == b) {
                Ok(())
            } else {
                Err(MergeError)
            }
        }

        if let Some(first) = self.index_of(other.first_key()) {
            check_same_keys(self.keys().skip(first as usize + 1), other.keys().skip(1))?;

            if self.has_key(other.last_key()) {
                // self:   [a b c]
                // other:    [b]
                // result: [a b c]
                Ok(())
            } else {
                // self:   [a b c]
                // other:    [b c d]
                // result: [a b c d]
                self.tail = mem::take(&mut self.tail)
                    .into_iter()
                    .take(first as usize)
                    .chain(other.tail)
                    .collect();
                Ok(())
            }
        } else if let Some(first) = other.index_of(self.first_key()) {
            check_same_keys(self.keys().skip(1), other.keys().skip(first as usize + 1))?;

            if other.has_key(self.last_key()) {
                // self:     [b]
                // other:  [a b c]
                // result: [a b c]
                self.head = other.head;
                self.tail = other.tail;
                Ok(())
            } else {
                // self:     [b c d]
                // other:  [a b c]
                // result: [a b c d]
                self.head = other.head;
                self.tail = other
                    .tail
                    .into_iter()
                    .take(first as usize)
                    .chain(mem::take(&mut self.tail))
                    .collect();
                Ok(())
            }
        } else {
            Err(MergeError)
        }
    }

    // Returns the latest key in this chain that is among the trusted keys, together with its index.
    fn latest_trusted_key<'a, 'b, I>(&'a self, trusted_keys: I) -> Option<(usize, &'a PublicKey)>
    where
        I: IntoIterator<Item = &'b PublicKey>,
    {
        let trusted_keys: HashSet<_> = trusted_keys.into_iter().collect();
        let last_index = self.len() - 1;

        self.keys()
            .rev()
            .enumerate()
            .map(|(rev_index, key)| (last_index - rev_index, key))
            .find(|(_, key)| trusted_keys.contains(key))
    }
}

// Result of a message trust check.
#[derive(Debug, Eq, PartialEq)]
pub enum TrustStatus {
    // Proof chain is trusted.
    Trusted,
    // Proof chain is untrusted because one or more blocks in the chain have invalid signatures.
    Invalid,
    // Proof chain is self-validated but its trust cannot be determined because none of the keys
    // in the chain is among the trusted keys.
    Unknown,
}

/// Error returned from `SectionProofChain::extend`
#[derive(Debug, Error)]
pub enum ExtendError {
    #[error("invalid first key")]
    InvalidFirstKey,
    #[error("invalid last key")]
    InvalidLastKey,
    #[error("proof chain already sufficient")]
    AlreadySufficient,
}

/// Error returned from `SectionProofChain::merge`
#[derive(Debug, Error, Eq, PartialEq)]
#[error("incompatible chains cannot be merged")]
pub struct MergeError;

// Block of the section proof chain. Contains the section BLS public key and is signed by the
// previous block. Note that the first key in the chain is not signed and so is not stored in
// `Block`.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
struct Block {
    key: PublicKey,
    signature: Signature,
}

impl Block {
    fn verify(&self, public_key: &PublicKey) -> bool {
        bincode::serialize(&self.key)
            .map(|bytes| public_key.verify(&self.signature, &bytes))
            .unwrap_or(false)
    }
}

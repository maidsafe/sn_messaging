// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elders_info;
mod member_info;
mod section_keys;
mod section_peers;
mod section_proof_chain;

pub use self::{
    elders_info::EldersInfo,
    member_info::{MemberInfo, PeerState, MIN_AGE},
    section_keys::{SectionKeyShare, SectionKeysProvider},
    section_peers::SectionPeers,
    section_proof_chain::{ExtendError, SectionProofChain, TrustStatus},
};
use crate::node::{consensus::Proven, peer::Peer, Error};
use bls_signature_aggregator::Proof;
use serde::{Deserialize, Serialize};
use threshold_crypto::PublicKey;
use xor_name::{Prefix, XorName};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Section {
    pub members: SectionPeers,
    pub elders_info: Proven<EldersInfo>,
    pub chain: SectionProofChain,
}

impl Section {
    /// Creates a minimal `Section` initially containing only info about our elders
    /// (`elders_info`).
    pub fn new(chain: SectionProofChain, elders_info: Proven<EldersInfo>) -> Result<Self, Error> {
        if !chain.has_key(&elders_info.proof.public_key) {
            // TODO: consider more specific error here.
            return Err(Error::InvalidMessage);
        }

        Ok(Self {
            elders_info,
            chain,
            members: SectionPeers::default(),
        })
    }

    /// Update the `EldersInfo` of our section.
    pub fn update_elders(
        &mut self,
        new_elders_info: Proven<EldersInfo>,
        new_key_proof: Proof,
    ) -> bool {
        if !new_elders_info.self_verify() {
            return false;
        }

        if !self
            .chain
            .push(new_elders_info.proof.public_key, new_key_proof.signature)
        {
            return false;
        }

        self.elders_info = new_elders_info;
        self.members
            .prune_not_matching(&self.elders_info.value.prefix);

        true
    }

    /// Update the member. Returns whether it actually changed anything.
    pub fn update_member(&mut self, member_info: Proven<MemberInfo>) -> bool {
        if !member_info.verify(&self.chain) {
            return false;
        }

        self.members.update(member_info)
    }

    // Returns a trimmed version of this `Section` which contains only the elders info and the
    // section chain truncated to the given length (the chain is truncated from the end, so it
    // always contains the latest key). If `chain_len` is zero, it is silently replaced with one.
    pub fn trimmed(&self, chain_len: usize) -> Self {
        let first_key_index = self
            .chain
            .last_key_index()
            .saturating_sub(chain_len.saturating_sub(1) as u64);

        Self {
            elders_info: self.elders_info.clone(),
            chain: self.chain.slice(first_key_index..),
            members: SectionPeers::default(),
        }
    }

    pub fn elders_info(&self) -> &EldersInfo {
        &self.elders_info.value
    }

    pub fn chain(&self) -> &SectionProofChain {
        &self.chain
    }

    // Extend the section chain so it starts at `new_first_key` while keeping the last key intact.
    pub fn extend_chain(
        &mut self,
        new_first_key: &PublicKey,
        full_chain: &SectionProofChain,
    ) -> Result<(), ExtendError> {
        self.chain.extend(new_first_key, full_chain)
    }

    pub fn is_elder(&self, name: &XorName) -> bool {
        self.elders_info().elders.contains_key(name)
    }

    // Prefix of our section.
    pub fn prefix(&self) -> &Prefix {
        &self.elders_info().prefix
    }

    /// Returns adults from our section.
    pub fn adults(&self) -> impl Iterator<Item = &Peer> {
        self.members
            .mature()
            .filter(move |peer| !self.is_elder(peer.name()))
    }
}

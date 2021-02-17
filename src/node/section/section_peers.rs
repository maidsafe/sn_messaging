// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::member_info::{MemberInfo, PeerState};
use crate::node::{consensus::Proven, peer::Peer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    hash::{Hash, Hasher},
    mem,
};
use xor_name::{Prefix, XorName};

/// Container for storing information about members of our section.
#[derive(Clone, Default, Debug, Eq, Serialize, Deserialize)]
pub struct SectionPeers {
    members: BTreeMap<XorName, Proven<MemberInfo>>,
}

impl SectionPeers {
    /*
                /// Returns an iterator over all current (joined) and past (left) members.
                pub fn all(&self) -> impl Iterator<Item = &MemberInfo> {
                    self.members.values().map(|info| &info.value)
                }
    */
    /// Returns an iterator over the members that have state == `Joined`.
    pub fn joined(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members
            .values()
            .map(|info| &info.value)
            .filter(|member| member.state == PeerState::Joined)
    }

    /// Returns joined nodes from our section with age greater than `MIN_AGE`
    pub fn mature(&self) -> impl Iterator<Item = &Peer> {
        self.joined()
            .filter(|info| info.is_mature())
            .map(|info| &info.peer)
    }
    /*
            /// Get info for the member with the given name.
            pub fn get(&self, name: &XorName) -> Option<&MemberInfo> {
                self.members.get(name).map(|info| &info.value)
            }

            /// Get proven info for the member with the given name.
            pub fn get_proven(&self, name: &XorName) -> Option<&Proven<MemberInfo>> {
                self.members.get(name)
            }

            /// Returns the candidates for elders out of all the nodes in this section.
            pub fn elder_candidates(&self, elder_size: usize, current_elders: &EldersInfo) -> Vec<Peer> {
                elder_candidates(
                    elder_size,
                    current_elders,
                    self.members
                        .values()
                        .filter(|info| is_active(&info.value, current_elders)),
                )
            }

            /// Returns the candidates for elders out of all nodes matching the prefix.
            pub fn elder_candidates_matching_prefix(
                &self,
                prefix: &Prefix,
                elder_size: usize,
                current_elders: &EldersInfo,
            ) -> Vec<Peer> {
                elder_candidates(
                    elder_size,
                    current_elders,
                    self.members.values().filter(|info| {
                        info.value.state == PeerState::Joined && prefix.matches(info.value.peer.name())
                    }),
                )
            }

            /// Returns whether the given peer is a joined member of our section.
            pub fn is_joined(&self, name: &XorName) -> bool {
                self.members
                    .get(name)
                    .map(|info| info.value.state == PeerState::Joined)
                    .unwrap_or(false)
            }
    */
    /// Update a member of our section.
    /// Returns whether anything actually changed.
    pub fn update(&mut self, new_info: Proven<MemberInfo>) -> bool {
        match self.members.entry(*new_info.value.peer.name()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(new_info);
                true
            }
            Entry::Occupied(mut entry) => {
                // To maintain commutativity, the only allowed transitions are:
                // - Joined -> Joined if the new age is greater than the old age
                // - Joined -> Left
                // - Joined -> Relocated
                // - Relocated -> Left (should not happen, but needed for consistency)
                match (entry.get().value.state, new_info.value.state) {
                    (PeerState::Joined, PeerState::Joined)
                        if new_info.value.peer.age() > entry.get().value.peer.age() => {}
                    (PeerState::Joined, PeerState::Left)
                    | (PeerState::Joined, PeerState::Relocated(_))
                    | (PeerState::Relocated(_), PeerState::Left) => {}
                    _ => return false,
                };

                let _ = entry.insert(new_info);
                true
            }
        }
    }

    /// Remove all members whose name does not match `prefix`.
    pub fn prune_not_matching(&mut self, prefix: &Prefix) {
        self.members = mem::take(&mut self.members)
            .into_iter()
            .filter(|(name, _)| prefix.matches(name))
            .collect();
    }
}

impl PartialEq for SectionPeers {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl Hash for SectionPeers {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.members.hash(state)
    }
}

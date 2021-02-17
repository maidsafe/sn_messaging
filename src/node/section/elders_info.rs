// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::{peer::Peer, Prefix};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
};
use xor_name::XorName;

/// The information about all elders of a section at one point in time. Each elder is always a
/// member of exactly one current section, but a new `EldersInfo` is created whenever the elders
/// change, due to an elder being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct EldersInfo {
    /// The section's complete set of elders as a map from their name to a `Peer`.
    pub elders: BTreeMap<XorName, Peer>,
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix,
}

impl EldersInfo {
    pub fn peers(
        &self,
    ) -> impl Iterator<Item = &Peer> + DoubleEndedIterator + ExactSizeIterator + Clone {
        self.elders.values()
    }

    /// Returns the index of the elder with `name` in this set of elders.
    /// This is useful for BLS signatures where the signature share needs to be mapped to a
    /// "field element" which is typically a numeric index.
    pub fn position(&self, name: &XorName) -> Option<usize> {
        self.elders.keys().position(|other_name| other_name == name)
    }
}

impl Borrow<Prefix> for EldersInfo {
    fn borrow(&self) -> &Prefix {
        &self.prefix
    }
}

impl Debug for EldersInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EldersInfo {{ prefix: ({:b}), elders: {{{:?}}} }}",
            self.prefix,
            self.elders.values().format(", "),
        )
    }
}

impl Display for EldersInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{{{}}}/({:b})",
            self.elders.keys().format(", "),
            self.prefix,
        )
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use super::RoutingMsg;
pub use ed25519_dalek::{Keypair, Signature, Verifier};
use serde::{Deserialize, Serialize};
use threshold_crypto::PublicKey as BlsPublicKey;
use xor_name::XorName;

/// Details of a relocation: which node to relocate, where to relocate it to and what age it should
/// get once relocated.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct RelocateDetails {
    /// Public id of the node to relocate.
    pub pub_id: XorName,
    /// Relocation destination - the node will be relocated to a section whose prefix matches this
    /// name.
    pub destination: XorName,
    /// The BLS key of the destination section used by the relocated node to verify messages.
    pub destination_key: BlsPublicKey,
    /// The age the node will have post-relocation.
    pub age: u8,
}

/// RoutingMsg with Variant::Relocate in a convenient wrapper.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignedRelocateDetails {
    /// Signed message whose content is Variant::Relocate
    pub signed_msg: RoutingMsg,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelocatePayload {
    /// The Relocate Signed message.
    pub details: SignedRelocateDetails,
    /// The new name of the node signed using its old public_key, to prove the node identity.
    pub signature_of_new_name_with_old_key: Signature,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct RelocatePromise {
    pub name: XorName,
    pub destination: XorName,
}

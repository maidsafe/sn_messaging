// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod consensus;
mod crypto;
mod errors;
pub mod hash;
pub mod location;
pub mod network;
pub mod peer;
pub mod plain_message;
pub mod relocation;
pub mod section;
pub mod src_authority;
pub mod variant;

pub use self::errors::{Error, Result};
use self::{
    hash::MessageHash,
    location::DstLocation,
    plain_message::PlainMessage,
    section::{SectionProofChain, TrustStatus},
    src_authority::SrcAuthority,
    variant::Variant,
};
use crate::{MessageType, WireMsg};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use thiserror::Error;
use threshold_crypto::PublicKey;
use xor_name::Prefix;

/// Node message sent over the network.
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct NodeMessage {
    /// Source authority.
    /// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
    /// agains the public key and we know the pub key then we are good. If the proof is not recognised we
    /// ask for a longer chain that can be recognised). Therefor we don't need to sign this field.
    pub src: SrcAuthority,
    /// Destination location.
    pub dst: DstLocation,
    /// The body of the message.
    pub variant: Variant,
    /// Proof chain to verify the message trust. Does not need to be signed.
    pub proof_chain: Option<SectionProofChain>,
    /// Source's knowledge of the destination section key. If present, the destination can use it
    /// to determine the length of the proof of messages sent to the source so the source would
    /// trust it (the proof needs to start at this key).
    pub dst_key: Option<PublicKey>,
}

impl NodeMessage {
    /// Convinience function to deserialize a 'NodeMessage' from bytes received over the wire.
    /// It returns an error if the bytes don't correspond to a node message.
    pub fn new(bytes: Bytes) -> crate::Result<Self> {
        let deserialized = WireMsg::deserialize(bytes)?;
        if let MessageType::NodeMessage(msg) = deserialized {
            Ok(msg)
        } else {
            Err(crate::Error::FailedToParse(
                "bytes as a node message".to_string(),
            ))
        }
    }

    /// Serialize this NodeMessage into bytes ready to be sent over the wire.
    pub fn serialize(&self) -> crate::Result<Bytes> {
        WireMsg::serialize_node_msg(self)
    }
}

impl PartialEq for NodeMessage {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.dst == other.dst
            && self.variant == other.variant
            && self.proof_chain == other.proof_chain
            && self.dst_key == other.dst_key
    }
}

impl Debug for NodeMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("NodeMessage")
            .field("src", &self.src.src_location())
            .field("dst", &self.dst)
            .field("variant", &self.variant)
            .finish()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum VerifyStatus {
    // The message has been fully verified.
    Full,
    // The message trust and integrity cannot be verified because it's proof is not trusted by us,
    // even though it is valid. The message should be relayed to other nodes who might be able to
    // verify it.
    Unknown,
}

impl Into<Result<VerifyStatus>> for TrustStatus {
    fn into(self) -> Result<VerifyStatus> {
        match self {
            Self::Trusted => Ok(VerifyStatus::Full),
            Self::Unknown => Ok(VerifyStatus::Unknown),
            Self::Invalid => Err(Error::InvalidMessage),
        }
    }
}

/// Status of an incomming message.
#[derive(Eq, PartialEq)]
pub enum MessageStatus {
    /// Message is useful and should be handled.
    Useful,
    /// Message is useless and should be discarded.
    Useless,
    /// Message trust can't be established.
    Untrusted,
    /// We don't know how to handle the message because we are not in the right state (e.g. it
    /// needs elder but we are not)
    Unknown,
}

// View of a message that can be serialized for the purpose of signing.
#[derive(Serialize)]
pub struct SignableView<'a> {
    // TODO: why don't we include also `src`?
    pub dst: &'a DstLocation,
    pub dst_key: Option<&'a PublicKey>,
    pub variant: &'a Variant,
}

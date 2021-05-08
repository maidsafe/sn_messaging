// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::section_info::Error as TargetSectionError;
use serde::{Deserialize, Serialize};
use sn_data_types::DataAddress;
use sn_data_types::PublicKey;
use std::result;
use thiserror::Error;

/// A specialised `Result` type.
pub type Result<T, E = Error> = result::Result<T, E>;

/// Main error type for the crate.
#[derive(Error, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Message read was built with an unsupported version.
    #[error("Unsupported messaging protocol version: {0}")]
    UnsupportedVersion(u16),
    /// Message read contains a payload with an unsupported serialization type.
    #[error("Unsupported payload serialization: {0}")]
    UnsupportedSerialization(u16),
    /// Access denied for supplied PublicKey
    #[error("Access denied for PublicKey: {0}")]
    AccessDenied(PublicKey),
    /// Error occurred when atempting to verify signature
    #[error("Signature verification error: {0}")]
    SignatureVerification(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Requested data not found
    #[error("Requested data not found: {0:?}")]
    DataNotFound(DataAddress),
    /// No history found for PublicKey
    #[error("No history found for PublicKey: {0}")]
    NoHistoryForPublicKey(sn_data_types::PublicKey),
    /// Failed to write file, likely due to a system Io error
    #[error("Failed to write file")]
    FailedToWriteFile,
    /// Provided data already exists on the network
    #[error("Data provided already exists")]
    DataExists,
    /// Entry could not be found on the data
    #[error("Requested entry not found")]
    NoSuchEntry,
    /// Exceeds limit on entrites for the given data type
    #[error("Exceeded a limit on a number of entries")]
    TooManyEntries,
    /// Key does not exist
    #[error("Key does not exist")]
    NoSuchKey,
    /// Node NotEnoughSpace error
    #[error("Node does not have sufficient space to store chunk")]
    NotEnoughSpace,
    /// Duplicate Entries in this push
    #[error("Duplicate entries provided")]
    DuplicateEntryKeys,
    /// The list of owner keys is invalid
    #[error("Invalid owner key: {0}")]
    InvalidOwners(sn_data_types::PublicKey),
    /// No Policy has been set to the data
    #[error("No policy has been set for this data")]
    PolicyNotSet,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current data version.
    #[error("Invalid version provided: {0}")]
    InvalidSuccessor(u64),
    /// Invalid version for performing a given mutating operation. Contains the
    /// current owners version.
    #[error("Invalid owners version provided: {0}")]
    InvalidOwnersSuccessor(u64),
    /// Invalid mutating operation as it causality dependency is currently not satisfied
    #[error("Operation is not causally ready. Ensure you have the full history of operations.")]
    OpNotCausallyReady,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current permissions version.
    #[error("Invalid permission version provided: {0}")]
    InvalidPermissionsSuccessor(u64),
    /// Invalid Operation such as a POST on ImmutableData
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// Mismatch between key type and signature type.
    #[error("Sign key and signature type do not match")]
    SigningKeyTypeMismatch,
    /// Failed signature validation.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Received a request with a duplicate MessageId
    #[error("Duplicate message id received")]
    DuplicateMessageId,
    // /// Network error occurring at Node level which has no bearing on clients, e.g. serialisation
    // /// failure or database failure
    // #[error("Network error: {0}")]
    // NetworkOther(String),
    /// While parsing, precision would be lost.
    #[error("Lost precision on the number of coins during parsing")]
    LossOfPrecision,
    /// The amount would exceed the maximum value for `Token` (u64::MAX).
    #[error("The token amount would exceed the maximum value (u64::MAX)")]
    ExcessiveValue,
    /// Transaction ID already exists.
    #[error("Transaction Id already exists")]
    TransactionIdExists,
    /// Insufficient coins.
    #[error("Insufficient balance to complete this operation")]
    InsufficientBalance,
    /// Inexistent balance.
    // TODO: key/wallet/balance, what's our vocab here?
    #[error("No such key exists")]
    NoSuchBalance,
    /// Inexistent sender balance.
    #[error("No such sender key balance")]
    NoSuchSender,
    /// Inexistent recipient balance.
    // TODO: this should not be possible
    #[error("No such recipient key balance")]
    NoSuchRecipient,
    /// Coin balance already exists.
    #[error("Key already exists")]
    BalanceExists,
    /// Expected data size exceeded.
    #[error("Size of the structure exceeds the limit")]
    ExceededSize,
    /// The operation has not been signed by an actor PK and so cannot be validated.
    #[error("CRDT operation missing actor signature")]
    CrdtMissingOpSignature,
    /// The data for a given policy could not be located, so CRDT operations cannot be applied.
    #[error("CRDT data is in an unexpected and/or inconsistent state. No data found for current policy.")]
    CrdtUnexpectedState,
    /// Entry already exists. Contains the current entry Key.
    #[error("Entry already exists {0}")]
    EntryExists(u8),
    /// Problem registering the payment at a node
    #[error("Payment registration failed")]
    PaymentFailed,
    /// Node failed to delete the requested data for some reason.
    #[error("Failed to delete requested data")]
    FailedToDelete,
    /// Node does not manage any section funds.
    #[error("Node does not currently manage any section funds")]
    NoSectionFunds,
    /// Node does not manage any metadata, so is likely not a fully prepared elder yet.
    #[error("Node does not currently manage any section metadata")]
    NoSectionMetaData,
    /// Node does not manage any immutable chunks.
    #[error("Node does not currently manage any immutable chunks")]
    NoImmutableChunks,
    /// Node is currently churning so cannot perform the request.
    #[error("Cannot complete request due to churning of funds")]
    NodeChurningFunds,
    /// The node hasn't left the section, and was not marked for relocation during reward operations
    #[error("Node is not being relocated")]
    NodeWasNotRelocated,

    /// There was an error in the target section of a message. Probably related to section keys.
    #[error("Target section error")]
    TargetSection(#[from] TargetSectionError),
}

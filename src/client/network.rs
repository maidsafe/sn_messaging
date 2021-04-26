// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    client::{DataCmd as NodeDataCmd, DataQuery as NodeDataQuery, Error, Result},
    EndUser,
};
use serde::{Deserialize, Serialize};
use sn_data_types::{
    ActorHistory, Chunk, ChunkAddress, CreditAgreementProof, NodeAge, PublicKey, ReplicaEvent,
    SectionElders, Signature,
};
use std::collections::BTreeMap;
use xor_name::XorName;

use super::{ChunkRead, ChunkWrite, DataExchange};

// -------------- Node Cmds --------------

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeCmd {
    /// Metadata is handled by Elders
    Metadata { cmd: NodeDataCmd, origin: EndUser },
    /// Chunks are handled by Adults
    Chunks { cmd: ChunkWrite, origin: EndUser },
    /// Transfers are handled by Elders
    Transfers(NodeTransferCmd),
    /// Cmds related to the running of a node.
    System(NodeSystemCmd),
}

/// Cmds related to the running of a node.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeSystemCmd {
    /// Register a wallet for reward payouts.
    RegisterWallet(PublicKey),
    /// Notify Elders on nearing max capacity
    StorageFull {
        /// Node Id
        node_id: PublicKey,
        /// Section to which the message needs to be sent to. (NB: this is the section of the node id).
        section: XorName,
    },
    /// Replicate a given chunk at an Adult
    ReplicateChunk(Chunk),
    /// When new section key, all propose a reward payout.
    ProposeRewardPayout(sn_data_types::RewardProposal),
    /// When proposal has been agreed, they all accumulate the reward payout.
    AccumulateRewardPayout(sn_data_types::RewardAccumulation),
    /// Sent to all promoted nodes (also sibling if any) after
    /// a completed transition to a new constellation.
    ReceiveExistingData {
        /// Age and reward wallets of registered nodes, keyed by node name.
        node_rewards: BTreeMap<XorName, (NodeAge, PublicKey)>,
        /// Transfer histories
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
        /// Metadata
        metadata: DataExchange,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferCmd {
    ///
    PropagateTransfer(CreditAgreementProof),
}

// -------------- Node Events --------------

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeEvent {
    /// Replication completed event, emitted by a node, received by elders.
    ReplicationCompleted {
        ///
        chunk: ChunkAddress,
        /// The Elder's accumulated signature
        /// over the chunk address. This is sent back
        /// to them so that any uninformed Elder knows
        /// that this is all good.
        proof: Signature,
    },
    /// Adults ack read/write of chunks as to convey responsivity.
    ChunkWriteHandled(Result<(), super::CmdError>),
}

///
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeQuery {
    /// Metadata is handled by Elders
    Metadata {
        query: NodeDataQuery,
        origin: EndUser,
    },
    /// Chunks are handled by Adults
    Chunks { query: ChunkRead, origin: EndUser },
    /// Rewards handled by Elders
    Rewards(NodeRewardQuery),
    /// Transfers handled by Elders
    Transfers(NodeTransferQuery),
    /// Related to the running of a node
    System(NodeSystemQuery),
}

/// Reward query that is sent between sections.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeRewardQuery {
    GetNodeWalletKey(XorName),
    /// A new Section Actor share (i.e. a new Elder) needs to query
    /// its peer Elders for the replicas' public key set
    /// and the history of events of the section wallet.
    GetSectionWalletHistory,
}

///
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferQuery {
    /// Replicas starting up
    /// need to query for events of
    /// the existing Replicas. (Sent to the other Elders).
    GetReplicaEvents,
}

///
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeSystemQuery {
    /// On Elder change, all Elders need to query
    /// network for the new wallet's replicas' public key set
    GetSectionElders,
    /// Acquire the chunk from current holders for replication.
    /// providing the address of the chunk to be replicated.
    GetChunk(ChunkAddress),
}

///
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeSystemQueryResponse {
    /// On Elder change, all Elders need to query
    /// network for the new wallet's replicas' public key set
    GetSectionElders(SectionElders),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeQueryResponse {
    ///
    Data(NodeDataQueryResponse),
    ///
    Transfers(NodeTransferQueryResponse),
    ///
    System(NodeSystemQueryResponse),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferQueryResponse {
    /// Replicas starting up
    /// need to query for events of
    /// the existing Replicas.
    GetReplicaEvents(Result<Vec<ReplicaEvent>>),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataQueryResponse {
    /// Elder to Adult Get.
    GetChunk(Result<Chunk>),
    /// Adult to Adult Get
    GetChunks(Result<Vec<Chunk>>),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeCmdError {
    ///
    Data(NodeDataError),
    ///
    Transfers(NodeTransferError),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataError {
    ///
    ChunkReplication {
        ///
        address: ChunkAddress,
        ///
        error: Error,
    },
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferError {
    /// The error of propagation of TransferRegistered event.
    TransferPropagation(Error),
}

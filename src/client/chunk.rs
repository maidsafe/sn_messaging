// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{CmdError, Error, QueryResponse};
use serde::{Deserialize, Serialize};
use sn_data_types::{Chunk, ChunkAddress, PublicKey};
use std::fmt;
use xor_name::XorName;

/// TODO: docs
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum ChunkRead {
    /// TODO: docs
    Get(ChunkAddress),
}

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum ChunkWrite {
    /// TODO: docs
    New(Chunk),
    /// TODO: docs
    DeletePrivate(ChunkAddress),
}

impl ChunkRead {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        QueryResponse::GetChunk(Err(error))
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use ChunkRead::*;
        match self {
            Get(ref address) => *address.name(),
        }
    }
}

impl ChunkWrite {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        CmdError::Data(error)
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use ChunkWrite::*;
        match self {
            New(ref data) => *data.name(),
            DeletePrivate(ref address) => *address.name(),
        }
    }

    /// Returns the owner of the data on a New Chunk write.
    pub fn owner(&self) -> Option<PublicKey> {
        match self {
            Self::New(data) => data.owner().cloned(),
            Self::DeletePrivate(_) => None,
        }
    }
}

impl fmt::Debug for ChunkRead {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use ChunkRead::*;
        match self {
            Get(req) => write!(formatter, "{:?}", req),
        }
    }
}

impl fmt::Debug for ChunkWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use ChunkWrite::*;
        match self {
            New(chunk) => write!(formatter, "ChunkWrite::New({:?})", chunk),
            DeletePrivate(address) => write!(formatter, "ChunkWrite::DeletePrivate({:?})", address),
        }
    }
}

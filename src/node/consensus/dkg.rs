// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::{
    crypto::{Digest256, PublicKey, Signature},
    section::EldersInfo,
};
use hex_fmt::HexFmt;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use tiny_keccak::{Hasher, Sha3};

/// Unique identified of a DKG session.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DkgKey(pub Digest256);

impl DkgKey {
    pub fn new(elders_info: &EldersInfo) -> Self {
        // Calculate the hash without involving serialization to avoid having to return `Result`.
        let mut hasher = Sha3::v256();
        let mut output = Digest256::default();

        for peer in elders_info.elders.values() {
            hasher.update(&peer.name().0);
            hasher.update(&[peer.age()]);
        }

        hasher.update(&elders_info.prefix.name().0);
        hasher.update(&elders_info.prefix.bit_count().to_le_bytes());
        hasher.finalize(&mut output);

        Self(output)
    }
}

impl Debug for DkgKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DkgKey({:10})", HexFmt(&self.0))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct DkgFailureProof {
    pub public_key: PublicKey,
    pub signature: Signature,
}

pub type DkgFailureProofSet = Vec<DkgFailureProof>;

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        node::test_utils::arbitrary_unique_nodes, section::test_utils::gen_addr, ELDER_SIZE,
        MIN_AGE,
    };
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rand::{rngs::SmallRng, SeedableRng};
    use std::{collections::HashMap, iter};
    use xor_name::Prefix;

    #[test]
    fn dkg_key_is_affected_by_ages() {
        let name = rand::random();
        let addr = gen_addr();

        let peer0 = Peer::new(name, addr, MIN_AGE);
        let peer1 = Peer::new(name, addr, MIN_AGE + 1);

        let elders_info0 = EldersInfo::new(iter::once(peer0), Prefix::default());
        let elders_info1 = EldersInfo::new(iter::once(peer1), Prefix::default());

        let key0 = DkgKey::new(&elders_info0);
        let key1 = DkgKey::new(&elders_info1);

        assert_ne!(key0, key1);
    }

    #[test]
    fn single_participant() {
        // If there is only one participant, the DKG should complete immediately.

        let mut voter = DkgVoter::default();

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let elders_info = EldersInfo::new(iter::once(node.peer()), Prefix::default());
        let dkg_key = DkgKey::new(&elders_info);

        let commands = voter.start(&node.keypair, dkg_key, elders_info);
        assert_matches!(&commands[..], &[DkgCommand::HandleOutcome { .. }]);
    }

    proptest! {
        // Run a DKG session where every participant handles every message sent to them.
        // Expect the session to successfully complete without timed transitions.
        // NOTE: `seed` is for seeding the rng that randomizes the message order.
        #[test]
        fn proptest_full_participation(nodes in arbitrary_elder_nodes(), seed in any::<u64>()) {
            proptest_full_participation_impl(nodes, seed)
        }
    }

    fn proptest_full_participation_impl(nodes: Vec<Node>, seed: u64) {
        // Rng used to randomize the message order.
        let mut rng = SmallRng::seed_from_u64(seed);
        let mut messages = Vec::new();

        let elders_info = EldersInfo::new(nodes.iter().map(Node::peer), Prefix::default());
        let dkg_key = DkgKey::new(&elders_info);

        let mut actors: HashMap<_, _> = nodes
            .into_iter()
            .map(|node| (node.addr, Actor::new(node)))
            .collect();

        for actor in actors.values_mut() {
            let commands = actor
                .voter
                .start(&actor.node.keypair, dkg_key, elders_info.clone());

            for command in commands {
                messages.extend(actor.handle(command, &dkg_key))
            }
        }

        loop {
            match actors
                .values()
                .filter_map(|actor| actor.outcome.as_ref())
                .unique()
                .count()
            {
                0 => {}
                1 => return,
                _ => panic!("inconsistent DKG outcomes"),
            }

            // NOTE: this panics if `messages` is empty, but that's OK because it would mean
            // failure anyway.
            let index = rng.gen_range(0, messages.len());
            let (addr, message) = messages.swap_remove(index);

            let actor = actors.get_mut(&addr).expect("unknown message recipient");
            let commands = actor
                .voter
                .process_message(&actor.node.keypair, dkg_key, message);

            for command in commands {
                messages.extend(actor.handle(command, &dkg_key))
            }
        }
    }

    struct Actor {
        node: Node,
        voter: DkgVoter,
        outcome: Option<bls::PublicKey>,
    }

    impl Actor {
        fn new(node: Node) -> Self {
            Self {
                node,
                voter: DkgVoter::default(),
                outcome: None,
            }
        }

        fn handle(
            &mut self,
            command: DkgCommand,
            expected_dkg_key: &DkgKey,
        ) -> Vec<(SocketAddr, DkgMessage)> {
            match command {
                DkgCommand::SendMessage {
                    recipients,
                    dkg_key,
                    message,
                    ..
                } => {
                    assert_eq!(dkg_key, *expected_dkg_key);
                    recipients
                        .into_iter()
                        .map(|addr| (addr, message.clone()))
                        .collect()
                }
                DkgCommand::HandleOutcome { outcome, .. } => {
                    self.outcome = Some(outcome.public_key_set.public_key());
                    vec![]
                }
                DkgCommand::ScheduleTimeout { .. } => vec![],
                DkgCommand::SendFailureObservation { .. }
                | DkgCommand::HandleFailureAgreement { .. } => {
                    panic!("unexpected command: {:?}", command)
                }
            }
        }
    }

    fn arbitrary_elder_nodes() -> impl Strategy<Value = Vec<Node>> {
        arbitrary_unique_nodes(2..=ELDER_SIZE, MIN_AGE..)
    }
}
*/

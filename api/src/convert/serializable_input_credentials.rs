//! Convert to/from external::TxOut

use crate::{external};
use mc_transaction_core::{tx};
use protobuf::RepeatedField;

/// Convert tx::SerializableInputCredentials --> external::SerializableInputCredentials.
impl From<&tx::SerializableInputCredentials> for external::SerializableInputCredentials {
    fn from(src: &tx::SerializableInputCredentials) -> Self {
        let mut dst = Self::new();

        dst.set_ring(RepeatedField::from_vec(src.ring.iter().map(|utxo| utxo.into()).collect()));
        dst.set_membership_proofs(RepeatedField::from_vec(src.membership_proofs.iter().map(|utxo| utxo.into()).collect()));
        dst.set_real_index(src.real_index);
        dst.set_onetime_private_key((&src.onetime_private_key).into());
        dst.set_real_output_public_key((&src.real_output_public_key).into());
        dst.set_view_private_key((&src.view_private_key).into());

        dst
    }
}

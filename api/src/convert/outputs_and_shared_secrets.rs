//! Convert to/from external::TxOut

use crate::{external};
use mc_transaction_core::{tx};

/// Convert tx::OutputsAndSharedSecrets --> external::OutputsAndSharedSecrets.
impl From<&tx::OutputsAndSharedSecrets> for external::OutputsAndSharedSecrets {
    fn from(src: &tx::OutputsAndSharedSecrets) -> Self {
        let mut dst = Self::new();

        dst.set_tx_out((&src.tx_out).into());
        dst.set_ristretto_public((&src.ristretto_public).into());

        dst
    }
}


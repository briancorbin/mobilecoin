// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Client SDK for Rust
#![deny(missing_docs)]
#![allow(clippy::result_large_err)]

mod autogenerated_code {
    /// Expose proto data types from included third-party/external proto files.
    pub use protobuf::well_known_types::Empty;

    /// Needed due to how to the auto-generated code references the Empty
    /// message.
    pub mod empty {
        pub use protobuf::well_known_types::Empty;
    }

    // Include the auto-generated code.
    include!(concat!(env!("OUT_DIR"), "/protos-auto-gen/mod.rs"));
}
pub use autogenerated_code::*;

mod cached_tx_data;
mod client;
mod client_builder;
mod error;

pub use crate::{
    client::Client,
    client_builder::ClientBuilder,
    error::{Error, Result, TxOutMatchingError},
};
pub use cached_tx_data::MemoHandlerError;
pub use mc_account_keys::{AccountKey, PublicAddress};
pub use mc_blockchain_types::BlockIndex;
pub use mc_connection::BlockInfo;
pub use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
pub use mc_transaction_core::{
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{Tx, TxOutMembershipProof},
    TokenId,
};

/// A status that a submitted transaction can have
pub enum TransactionStatus {
    /// The transaction has appeared at a particular block index
    Appeared(BlockIndex),
    /// The transaction has expired (tombstone block passed)
    Expired,
    /// It isn't known if the transaction appeared or expired yet
    Unknown,
}

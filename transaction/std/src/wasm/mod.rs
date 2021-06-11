use std::{convert::TryFrom};
use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use data_types::{JsonSigningData, JsonTx, JsonTxPrefix, JsonUnsignedTx, JsonVerifySignature};
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::CompressedCommitment;
use mc_transaction_core::ring_signature::{CurveScalar, KeyImage, RingMLSAG};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_util_from_random::FromRandom;

use crate::{InputCredentials, TransactionBuilder};

mod data_types;

#[wasm_bindgen]
pub struct Transaction {
    input_credentials: Vec<InputCredentials>,
    outputs_and_shared_secrets: Vec<(TxOut, RistrettoPublic)>,
    tombstone_block: u64,
    fee: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SingleKey {
    pub view_private: String,
    pub spend_private: String,
    pub spend_public: String,

    pub sub_view_public: String,
    pub sub_spend_public: String,
}

#[wasm_bindgen]
pub fn get_address(view_public_key: &str, spend_public_key: &str) -> Result<String, JsValue> {
    let hex_view = hex::decode(view_public_key)
        .map_err(|err| format!("Failed to parse view_private_key: {}", err))?;

    let v: &[u8] = &hex_view;

    let view_public = RistrettoPublic::try_from(v)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let hex_spend = hex::decode(spend_public_key)
        .map_err(|err| format!("Failed to parse spend_public_key: {}", err))?;

    let s: &[u8] = &hex_spend;

    let spend_public = RistrettoPublic::try_from(s)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let public_address = PublicAddress::new(&spend_public, &view_public);

    let mut wrapper = mc_api::printable::PrintableWrapper::new();
    wrapper.set_public_address((&public_address).into());

    let address = wrapper
        .b58_encode()
        .map_err(|err| format!("Failed to encode address: {}", err))?;

    Ok(address)
}

#[wasm_bindgen]
pub fn verify_signature(verify_js: JsValue) -> Result<bool, JsValue> {
    let verify: JsonVerifySignature = verify_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let message: &[u8] = &*hex::decode(verify.message)
        .map_err(|err| format!("Failed to parse message: {}", err))?;

    let ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)> = verify.ring.iter()
        .map(|ring| {
            let c: Box<[u8; 32]> = hex::decode(ring.compressed_commitment.clone()).unwrap().into_boxed_slice().try_into().unwrap();

            (CompressedRistrettoPublic::try_from(&*hex::decode(ring.compressed_ristretto_public.clone()).unwrap()).unwrap(),
             CompressedCommitment::from(&*c))
        }).collect();

    let o: Box<[u8; 32]> = hex::decode(verify.output_commitment)
        .map_err(|err| format!("Failed to parse output_commitment: {}", err))?.into_boxed_slice().try_into().unwrap();
    let output_commitment = CompressedCommitment::from(&*o);

    let c: Box<[u8; 32]> = hex::decode(verify.c_zero)
        .map_err(|err| format!("Failed to parse c_zero: {}", err))?.into_boxed_slice().try_into().unwrap();
    let c_zero = CurveScalar::from(&*c);

    let responses = verify.responses.iter()
        .map(|r| {
            let res: Box<[u8; 32]> = hex::decode(r.clone()).unwrap().into_boxed_slice().try_into().unwrap();
            CurveScalar::from(&*res)
        })
        .collect();

    let k: Box<[u8; 32]> = hex::decode(verify.key_image)
        .map_err(|err| format!("Failed to parse key_image: {}", err))?.into_boxed_slice().try_into().unwrap();

    let key_image = KeyImage::from(*k);

    let signature = RingMLSAG {
        c_zero,
        responses,
        key_image
    };

    Ok(signature.verify(message, &ring, &output_commitment).is_ok())
}

#[wasm_bindgen]
pub fn generate_address() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let root_id = RootIdentity::from_random(&mut rng);

    let account_key = AccountKey::from(&root_id);

    let subaddress = account_key.subaddress(0);
    let sub_view_public = subaddress.view_public_key();
    let sub_spend_public = subaddress.spend_public_key();

    let spend_public = RistrettoPublic::from(account_key.spend_private_key());

    let params = SingleKey {
        view_private: hex::encode(account_key.view_private_key().to_bytes()),
        spend_private: hex::encode(account_key.spend_private_key().to_bytes()),
        spend_public: hex::encode(spend_public.to_bytes()),
        sub_view_public: hex::encode(sub_view_public.to_bytes()),
        sub_spend_public: hex::encode(sub_spend_public.to_bytes()),
    };

    let params_value = JsValue::from_serde(&params).map_err(|e| {
        JsValue::from(format!(
            "Error converting constructor parameters to json object: {}",
            e
        ))
    })?;

    Ok(params_value)
}

#[wasm_bindgen]
pub fn get_public_address(private_key: &str) -> Result<String, JsValue> {
    let hex_view = hex::decode(private_key)
        .map_err(|err| format!("Failed to parse private key: {}", err))?;

    let v: &[u8] = &hex_view;

    let private = RistrettoPrivate::try_from(v)
        .map_err(|err| format!("Failed to parse private key: {:?}", err))?;

    let public = RistrettoPublic::from(&private);

    Ok(hex::encode(public.to_bytes()))
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(constructor)]
    pub fn new(unsigned_tx_js: JsValue) -> Result<Transaction, JsValue> {
        let unsigned_tx: JsonUnsignedTx = unsigned_tx_js
            .into_serde()
            .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

        // convert to proto
        let proto_unsigned_tx = mc_api::external::UnsignedTx::try_from(&unsigned_tx)
            .map_err(|err| format!("Failed to convert unsigned_tx: {}", err))?;

        // Get the list of potential inputs passed to.
        let outputs_and_shared_secrets: Vec<(TxOut, RistrettoPublic)> = proto_unsigned_tx
            .get_outputs_and_shared_secrets()
            .iter()
            .map(|proto_output| {
                let out = TxOut::try_from(proto_output.get_tx_out())
                    .map_err(|err| format!("tx_out.try_from: {}", err))
                    .and_then(|tx_out| RistrettoPublic::try_from(proto_output.get_ristretto_public())
                        .map_err(|err| format!("ristretto_public.try_from: {}", err))
                        .map(|ristretto_public| (tx_out, ristretto_public)));

                out
            })
            .collect::<Result<Vec<(TxOut, RistrettoPublic)>, String>>()?;


        let input_credentials: Vec<InputCredentials> = proto_unsigned_tx
            .get_input_credentials()
            .iter()
            .map(|input| {
                let ring = input.get_ring()
                    .iter()
                    .map(|tx_out| TxOut::try_from(tx_out)
                        .map_err(|err| format!("tx_out.try_from: {}", err)))
                    .collect::<Result<Vec<TxOut>, String>>();

                let membership_proofs = input.get_membership_proofs()
                    .iter()
                    .map(|membership_proof| TxOutMembershipProof::try_from(membership_proof)
                        .map_err(|err| format!("tx_out.try_from: {}", err)))
                    .collect::<Result<Vec<TxOutMembershipProof>, String>>();

                let real_index: usize = input.get_real_index() as usize;

                let onetime_private_key = input.onetime_private_key.as_ref()
                    .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
                    .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))
                    .map_err(|err| format!("onetime_private_key.try_from: {}", err));

                let real_output_public_key = RistrettoPublic::try_from(input.get_real_output_public_key())
                    .map_err(|err| format!("ristretto_public.try_from: {}", err));


                let view_private_key = input.view_private_key.as_ref()
                    .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
                    .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))
                    .map_err(|err| format!("view_private_key.try_from: {}", err));

                let res = ring
                    .and_then(|r| membership_proofs
                        .and_then(|m| onetime_private_key
                            .and_then(|o| real_output_public_key
                                .and_then(|rk|
                                    view_private_key
                                        .map(|v| InputCredentials {
                                            ring: r,
                                            membership_proofs: m,
                                            real_index,
                                            onetime_private_key: o,
                                            real_output_public_key: rk,
                                            view_private_key: v
                                        }
                                        ))))
                    );

                res
            })
            .collect::<Result<Vec<InputCredentials>, String>>()?;

        Ok(Self {
            input_credentials,
            outputs_and_shared_secrets,
            tombstone_block: unsigned_tx.tombstone_block,
            fee: unsigned_tx.fee
        })
    }

    #[wasm_bindgen(js_name = "get_signing_data")]
    pub fn get_signing_data(&self) -> Result<JsValue, JsValue> {
        let mut builder = TransactionBuilder::new();

        builder.set_fee(self.fee);
        builder.set_tombstone_block(self.tombstone_block);
        builder.outputs_and_shared_secrets = self.outputs_and_shared_secrets.clone();
        builder.input_credentials = self.input_credentials.clone();

        let mut rng = rand::thread_rng();

        let sign_data = builder.get_signing_data(&mut rng)
            .map_err(|err| format!("Error on get signing data: {:?}", err))
            .map(|data| JsonSigningData::from(data))?;

        let result = JsValue::from_serde(&sign_data).map_err(|e| {
            JsValue::from(format!(
                "Error converting constructor parameters to json object: {}",
                e
            ))
        })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = get_tx_prefix)]
    pub fn get_tx_prefix(&self) -> Result<JsValue, JsValue> {
        let mut builder = TransactionBuilder::new();

        builder.set_fee(self.fee);
        builder.set_tombstone_block(self.tombstone_block);
        builder.outputs_and_shared_secrets = self.outputs_and_shared_secrets.clone();
        builder.input_credentials = self.input_credentials.clone();

        let tx_prefix = builder.get_tx_prefix()
            .map_err(|err| format!("Failed to construct tx: {:?}", err))?;

        let proto = mc_api::external::TxPrefix::from(&tx_prefix);

        let json = JsonTxPrefix::from(&proto);

        let result = JsValue::from_serde(&json).map_err(|e| {
            JsValue::from(format!(
                "Error converting constructor parameters to json object: {}",
                e
            ))
        })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = sign)]
    pub fn sign(&self, view_private_key: &str, spend_private_key: &str) -> Result<JsValue, JsValue> {
        let p = hex::decode(spend_private_key)
            .map_err(|err| format!("Failed to decode private key: {}", err))?;

        let private: &[u8] = &p;

        let spend_private_key = RistrettoPrivate::try_from(private)
            .map_err(|err| format!("Invalid Private key: {:?}", err))?;

        let v = hex::decode(view_private_key)
            .map_err(|err| format!("Failed to decode private key: {}", err))?;

        let view: &[u8] = &v;

        let view_private_key = RistrettoPrivate::try_from(view)
            .map_err(|err| format!("Invalid Private key: {:?}", err))?;

        let account = AccountKey::new(&spend_private_key, &view_private_key);

        let spend_key = account.subaddress_spend_private(0);

        let mut builder = TransactionBuilder::new();

        builder.set_fee(self.fee);
        builder.set_tombstone_block(self.tombstone_block);
        builder.outputs_and_shared_secrets = self.outputs_and_shared_secrets.clone();
        builder.input_credentials = self.input_credentials.clone();

        let mut rng = rand::thread_rng();

        let signed = builder.sign(spend_key, &mut rng)
            .map_err(|err| format!("Error on sign transaction: {:?}", err))?;

        let proto = mc_api::external::Tx::from(&signed);

        let json = JsonTx::from(&proto);

        let result = JsValue::from_serde(&json).map_err(|e| {
            JsValue::from(format!(
                "Error converting constructor parameters to json object: {}",
                e
            ))
        })?;

        Ok(result)
    }
}

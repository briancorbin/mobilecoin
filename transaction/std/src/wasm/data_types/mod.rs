use std::{convert::TryFrom};

use protobuf::RepeatedField;
use serde_derive::{Deserialize, Serialize};

use mc_api::external::TxOutMembershipHash;
use mc_transaction_core::tx::{SigningData};

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonAmount {
    pub commitment: String,
    pub masked_value: String,
}

impl From<&mc_api::external::Amount> for JsonAmount {
    fn from(src: &mc_api::external::Amount) -> Self {
        Self {
            commitment: hex::encode(src.get_commitment().get_data()),
            masked_value: src.get_masked_value().to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxOut {
    pub amount: JsonAmount,
    pub target_key: String,
    pub public_key: String,
    pub e_fog_hint: String,
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonTxOut> for mc_api::external::TxOut {
    type Error = String;

    fn try_from(src: &JsonTxOut) -> Result<mc_api::external::TxOut, String> {
        let mut commitment = mc_api::external::CompressedRistretto::new();
        commitment.set_data(
            hex::decode(&src.amount.commitment)
                .map_err(|err| format!("Failed to decode commitment hex: {}", err))?,
        );
        let mut amount = mc_api::external::Amount::new();
        amount.set_commitment(commitment);
        amount.set_masked_value(
            src.amount
                .masked_value
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from value: {}", err))?,
        );
        let mut target_key = mc_api::external::CompressedRistretto::new();
        target_key.set_data(
            hex::decode(&src.target_key)
                .map_err(|err| format!("Failed to decode target key hex: {}", err))?,
        );
        let mut public_key = mc_api::external::CompressedRistretto::new();
        public_key.set_data(
            hex::decode(&src.public_key)
                .map_err(|err| format!("Failed to decode public key hex: {}", err))?,
        );
        let mut e_fog_hint = mc_api::external::EncryptedFogHint::new();
        e_fog_hint.set_data(
            hex::decode(&src.e_fog_hint)
                .map_err(|err| format!("Failed to decode e_fog_hint hex: {}", err))?,
        );

        let mut txo = mc_api::external::TxOut::new();
        txo.set_amount(amount);
        txo.set_target_key(target_key);
        txo.set_public_key(public_key);
        txo.set_e_fog_hint(e_fog_hint);

        Ok(txo)
    }
}

impl From<&mc_api::external::TxOut> for JsonTxOut {
    fn from(src: &mc_api::external::TxOut) -> Self {
        Self {
            amount: src.get_amount().into(),
            target_key: hex::encode(src.get_target_key().get_data()),
            public_key: hex::encode(src.get_public_key().get_data()),
            e_fog_hint: hex::encode(src.get_e_fog_hint().get_data()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonRange {
    pub from: String,
    pub to: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxOutMembershipElement {
    pub range: JsonRange,
    pub hash: String,
}

impl From<&mc_api::external::TxOutMembershipElement> for JsonTxOutMembershipElement {
    fn from(src: &mc_api::external::TxOutMembershipElement) -> Self {
        Self {
            range: JsonRange {
                from: src.get_range().get_from().to_string(),
                to: src.get_range().get_to().to_string(),
            },
            hash: hex::encode(src.get_hash().get_data()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxOutMembershipProof {
    pub index: String,
    pub highest_index: String,
    pub elements: Vec<JsonTxOutMembershipElement>,
}

impl From<&mc_api::external::TxOutMembershipProof> for JsonTxOutMembershipProof {
    fn from(src: &mc_api::external::TxOutMembershipProof) -> Self {
        Self {
            index: src.get_index().to_string(),
            highest_index: src.get_highest_index().to_string(),
            elements: src
                .get_elements()
                .iter()
                .map(JsonTxOutMembershipElement::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonTxOutMembershipProof> for mc_api::external::TxOutMembershipProof {
    type Error = String;

    fn try_from(src: &JsonTxOutMembershipProof) -> Result<mc_api::external::TxOutMembershipProof, String> {
        let mut elements: Vec<mc_api::external::TxOutMembershipElement> = Vec::new();
        for element in &src.elements {
            let mut range = mc_api::external::Range::new();
            range.set_from(
                element
                    .range
                    .from
                    .parse::<u64>()
                    .map_err(|err| format!("Failed to parse u64 from range.from: {}", err))?,
            );
            range.set_to(
                element
                    .range
                    .to
                    .parse::<u64>()
                    .map_err(|err| format!("Failed to parse u64 from range.to: {}", err))?,
            );

            let mut hash = TxOutMembershipHash::new();
            hash.set_data(
                hex::decode(&element.hash)
                    .map_err(|err| format!("Could not decode elem hash: {}", err))?,
            );

            let mut elem = mc_api::external::TxOutMembershipElement::new();
            elem.set_range(range);
            elem.set_hash(hash);
            elements.push(elem);
        }

        let mut proof = mc_api::external::TxOutMembershipProof::new();
        proof.set_index(
            src.index
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from index: {}", err))?,
        );
        proof.set_highest_index(
            src.highest_index
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse u64 from highest_index: {}", err))?,
        );
        proof.set_elements(RepeatedField::from_vec(elements));

        Ok(proof)
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct JsonInputCredentials {
    pub ring: Vec<JsonTxOut>,
    pub membership_proofs: Vec<JsonTxOutMembershipProof>,
    pub real_index: u64,
    pub onetime_private_key: String,
    pub real_output_public_key: String,
    pub view_private_key: String,
}

impl TryFrom<&JsonInputCredentials> for mc_api::external::SerializableInputCredentials {
    type Error = String;

    fn try_from(src: &JsonInputCredentials) -> Result<mc_api::external::SerializableInputCredentials, String> {
        let mut ring: Vec<mc_api::external::TxOut> = Vec::new();
        for input in src.ring.iter() {
            let utxo = mc_api::external::TxOut::try_from(input)
                .map_err(|err| format!("Failed to convert ring input: {}", err))?;
            ring.push(utxo);
        }

        let mut membership_proofs: Vec<mc_api::external::TxOutMembershipProof> = Vec::new();
        for proof in src.membership_proofs.iter() {
            let out = mc_api::external::TxOutMembershipProof::try_from(proof)
                .map_err(|err| format!("Failed to convert membership_proof: {}", err))?;
            membership_proofs.push(out);
        }

        let mut onetime_private_key = mc_api::external::RistrettoPrivate::new();
        onetime_private_key.set_data(
            hex::decode(&src.onetime_private_key)
                .map_err(|err| format!("Failed to decode onetime private key hex: {}", err))?,
        );

        let mut real_output_public_key = mc_api::external::CompressedRistretto::new();
        real_output_public_key.set_data(
            hex::decode(&src.real_output_public_key)
                .map_err(|err| format!("Failed to decode hex for real_output_public_key: {}", err))?,
        );

        let mut view_private_key = mc_api::external::RistrettoPrivate::new();
        view_private_key.set_data(
            hex::decode(&src.view_private_key)
                .map_err(|err| format!("Failed to decode view private key hex: {}", err))?,
        );

        // Reconstruct the public address as a protobuf
        let mut input_credentials = mc_api::external::SerializableInputCredentials::new();
        input_credentials.set_ring(RepeatedField::from_vec(ring));
        input_credentials.set_membership_proofs(RepeatedField::from_vec(membership_proofs));
        input_credentials.set_real_index(src.real_index);
        input_credentials.set_onetime_private_key(onetime_private_key);
        input_credentials.set_real_output_public_key(real_output_public_key);
        input_credentials.set_view_private_key(view_private_key);

        Ok(input_credentials)
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct JsonOutputsAndSharedSecrets {
    pub tx_out: JsonTxOut,
    pub ristretto_public: String,
}

impl TryFrom<&JsonOutputsAndSharedSecrets> for mc_api::external::OutputsAndSharedSecrets {
    type Error = String;

    fn try_from(src: &JsonOutputsAndSharedSecrets) -> Result<mc_api::external::OutputsAndSharedSecrets, String> {
        let mut ristretto_public = mc_api::external::CompressedRistretto::new();
        ristretto_public.set_data(
            hex::decode(&src.ristretto_public)
                .map_err(|err| format!("Failed to decode hex for real_output_public_key: {}", err))?,
        );

        // Reconstruct the public address as a protobuf
        let mut outputs_and_shared_secrets = mc_api::external::OutputsAndSharedSecrets::new();
        outputs_and_shared_secrets.set_tx_out(mc_api::external::TxOut::try_from(&src.tx_out)
            .map_err(|err| format!("Failed to parse tx_out: {}", err))?);
        outputs_and_shared_secrets.set_ristretto_public(ristretto_public);

        Ok(outputs_and_shared_secrets)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonUnsignedTx {
    pub input_credentials: Vec<JsonInputCredentials>,
    pub outputs_and_shared_secrets: Vec<JsonOutputsAndSharedSecrets>,
    pub fee: u64,
    pub tombstone_block: u64,
}

impl TryFrom<&JsonUnsignedTx> for mc_api::external::UnsignedTx {
    type Error = String;

    fn try_from(src: &JsonUnsignedTx) -> Result<mc_api::external::UnsignedTx, String> {
        let mut input_credentials: Vec<mc_api::external::SerializableInputCredentials> = Vec::new();
        for input in src.input_credentials.iter() {
            input_credentials.push(mc_api::external::SerializableInputCredentials::try_from(input)
                .map_err(|err| format!("Failed to convert input_credentials: {}", err))?);
        }

        let mut outputs_and_shared_secrets: Vec<mc_api::external::OutputsAndSharedSecrets> = Vec::new();
        for output in src.outputs_and_shared_secrets.iter() {
            outputs_and_shared_secrets.push(mc_api::external::OutputsAndSharedSecrets::try_from(output)
                .map_err(|err| format!("Failed to convert outputs and shared secrets {}", err))?);
        }

        // Reconstruct the public address as a protobuf
        let mut unsigned_tx = mc_api::external::UnsignedTx::new();
        unsigned_tx.set_input_credentials(RepeatedField::from_vec(input_credentials));
        unsigned_tx.set_outputs_and_shared_secrets(RepeatedField::from_vec(outputs_and_shared_secrets));
        unsigned_tx.set_fee(src.fee);
        unsigned_tx.set_tombstone_block(src.tombstone_block);

        Ok(unsigned_tx)
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSigningData {
    pub message: String,
    pub rings: Vec<Vec<JsonRing>>,
    pub real_input_indices: Vec<u64>,
    pub pseudo_output_blindings: Vec<String>,
    pub input_values_and_blindings: Vec<JsonInputValuesAndBlindings>,
    pub pseudo_output_commitments: Vec<String>,
    pub range_proof_bytes: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonVerifySignature {
    pub message: String,
    pub ring: Vec<JsonRing>,
    pub output_commitment: String,
    pub c_zero: String,
    pub responses: Vec<String>,
    pub key_image: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonRing {
    pub compressed_ristretto_public: String,
    pub compressed_commitment: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonInputValuesAndBlindings {
    value: u64,
    blinding: String,
}

impl From<SigningData> for JsonSigningData {
    fn from(src: SigningData) -> Self {
        let rings = src.rings
            .iter()
            .map(|ring| ring
                .iter()
                .map(|(compressed_ristretto_public, compressed_commitment)| JsonRing {
                    compressed_ristretto_public: hex::encode(compressed_ristretto_public.as_bytes()),
                    compressed_commitment: hex::encode(compressed_commitment.point.to_bytes()),
                })
                .collect()
            )
            .collect();

        let real_input_indices = src.real_input_indices
            .iter()
            .map(|indic| indic.clone() as u64)
            .collect();

        let pseudo_output_blindings = src.pseudo_output_blindings
            .iter()
            .map(|output| hex::encode(output.to_bytes()))
            .collect();

        let input_values_and_blindings = src.input_values_and_blindings
            .iter()
            .map(|(value, blinding)| JsonInputValuesAndBlindings {
                value: value.clone(),
                blinding: hex::encode(blinding.to_bytes())
            })
            .collect();

        let pseudo_output_commitments = src.pseudo_output_commitments
            .iter()
            .map(|x| hex::encode(x.point.to_bytes()))
            .collect();

        let range_proof_bytes = hex::encode(src.range_proof_bytes);

        Self {
            message: hex::encode(src.message),
            rings,
            real_input_indices,
            pseudo_output_blindings,
            input_values_and_blindings,
            pseudo_output_commitments,
            range_proof_bytes
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxPrefix {
    pub inputs: Vec<JsonTxIn>,
    pub outputs: Vec<JsonTxOut>,
    pub fee: String,
    tombstone_block: String,
}

impl From<&mc_api::external::TxPrefix> for JsonTxPrefix {
    fn from(src: &mc_api::external::TxPrefix) -> Self {
        Self {
            inputs: src.get_inputs().iter().map(JsonTxIn::from).collect(),
            outputs: src.get_outputs().iter().map(JsonTxOut::from).collect(),
            fee: src.get_fee().to_string(),
            tombstone_block: src.get_tombstone_block().to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTx {
    pub prefix: JsonTxPrefix,
    pub signature: JsonSignatureRctBulletproofs,
}

impl From<&mc_api::external::Tx> for JsonTx {
    fn from(src: &mc_api::external::Tx) -> Self {
        Self {
            prefix: src.get_prefix().into(),
            signature: src.get_signature().into(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxIn {
    pub ring: Vec<JsonTxOut>,
    pub proofs: Vec<JsonTxOutMembershipProof>,
}

impl From<&mc_api::external::TxIn> for JsonTxIn {
    fn from(src: &mc_api::external::TxIn) -> Self {
        Self {
            ring: src.get_ring().iter().map(JsonTxOut::from).collect(),
            proofs: src
                .get_proofs()
                .iter()
                .map(JsonTxOutMembershipProof::from)
                .collect(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSignatureRctBulletproofs {
    pub ring_signatures: Vec<JsonRingMLSAG>,
    pub pseudo_output_commitments: Vec<String>,
    range_proofs: String,
}

impl From<&mc_api::external::SignatureRctBulletproofs> for JsonSignatureRctBulletproofs {
    fn from(src: &mc_api::external::SignatureRctBulletproofs) -> Self {
        Self {
            ring_signatures: src
                .get_ring_signatures()
                .iter()
                .map(JsonRingMLSAG::from)
                .collect(),
            pseudo_output_commitments: src
                .get_pseudo_output_commitments()
                .iter()
                .map(|x| hex::encode(x.get_data()))
                .collect(),
            range_proofs: hex::encode(src.get_range_proofs().to_vec()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonRingMLSAG {
    pub c_zero: String,
    pub responses: Vec<String>,
    pub key_image: String,
}

impl From<&mc_api::external::RingMLSAG> for JsonRingMLSAG {
    fn from(src: &mc_api::external::RingMLSAG) -> Self {
        Self {
            c_zero: hex::encode(src.get_c_zero().get_data()),
            responses: src
                .get_responses()
                .iter()
                .map(|x| hex::encode(x.get_data()))
                .collect(),
            key_image: hex::encode(src.get_key_image().get_data()),
        }
    }
}

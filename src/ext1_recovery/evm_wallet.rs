use alloy_primitives::{Address, FixedBytes, Signature};
#[cfg(feature = "abi")]
use borsh::{
    BorshSchema,
    schema::{Declaration, Definition},
};
use chrono::{DateTime, Utc};
use near_sdk::{
    PublicKey,
    borsh::{self, BorshDeserialize, BorshSerialize},
    near,
    serde::{Deserialize, Serialize},
};
use regex::Regex;
#[cfg(feature = "abi")]
use std::collections::BTreeMap;

use super::SIGNATURE_DURATION;

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct EvmSignature {
    pub signature: Signature,
    /// Example message: 'I want to sign in to alice.near with key ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP. The current date is 2025-01-01T00:00:00Z UTC'
    /// The date should be within [`SIGNATURE_DURATION`] of the current date, but not in the future.
    pub message: String,
}

#[near(serializers=[json, borsh])]
#[derive(Clone)]
pub struct EvmRecoveryMethod {
    #[cfg_attr(
        not(feature = "abi"),
        borsh(
            serialize_with = "borsh_serialize_evm_address",
            deserialize_with = "borsh_deserialize_evm_address",
        )
    )]
    #[cfg_attr(
        feature = "abi",
        borsh(
            serialize_with = "borsh_serialize_evm_address",
            deserialize_with = "borsh_deserialize_evm_address",
            schema(with_funcs(
                declaration = "borsh_schema_evm_address_declaration",
                definitions = "borsh_schema_evm_address_definitions",
            ))
        )
    )]
    #[cfg_attr(feature = "abi", schemars(with = "String"))]
    pub recovery_wallet_address: Address,
}

pub fn borsh_serialize_evm_address(
    address: &Address,
    writer: &mut impl borsh::io::Write,
) -> Result<(), borsh::io::Error> {
    BorshSerialize::serialize(&address.0.0, writer)
}

pub fn borsh_deserialize_evm_address(
    reader: &mut impl borsh::io::Read,
) -> Result<Address, borsh::io::Error> {
    let address: [u8; 20] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(Address(FixedBytes(address)))
}

#[cfg(feature = "abi")]
pub fn borsh_schema_evm_address_declaration() -> Declaration {
    <[u8; 20]>::declaration()
}

#[cfg(feature = "abi")]
pub fn borsh_schema_evm_address_definitions(definitions: &mut BTreeMap<Declaration, Definition>) {
    <[u8; 20]>::add_definitions_recursively(definitions);
}

impl EvmRecoveryMethod {
    pub fn check(&self, message: &str) -> Option<PublicKey> {
        let current_account_id = near_sdk::env::current_account_id();

        let Ok(signature) = serde_json::from_str::<EvmSignature>(message) else {
            return None;
        };

        let pattern = r"^I want to sign in to (.+) with key (.+)\. The current date is (.+) UTC$";
        let Ok(re) = Regex::new(pattern) else {
            return None;
        };

        let captures = re.captures(&signature.message)?;
        let account_id = &captures[1];
        let public_key_str = &captures[2];
        let date_str = &captures[3];

        if account_id != current_account_id.as_str() {
            return None;
        }
        let Ok(public_key) = public_key_str.parse::<PublicKey>() else {
            return None;
        };
        let Ok(nonce) = DateTime::parse_from_rfc3339(date_str) else {
            return None;
        };
        let nonce = nonce.with_timezone(&Utc);

        if nonce.timestamp_millis() > near_sdk::env::block_timestamp_ms() as i64
            || (nonce.timestamp_millis() as u128)
                < near_sdk::env::block_timestamp_ms() as u128 - SIGNATURE_DURATION.as_millis()
        {
            return None;
        }

        let Ok(signer_address) = signature
            .signature
            .recover_address_from_msg(&signature.message)
        else {
            return None;
        };
        if signer_address != self.recovery_wallet_address {
            return None;
        }

        Some(public_key)
    }
}

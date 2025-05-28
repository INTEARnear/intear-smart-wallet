use chrono::{DateTime, Utc};
use near_sdk::{
    PublicKey, bs58, near,
    serde::{self, Deserialize, Serialize},
};
use regex::Regex;
use solana_signature::Signature;

use super::SIGNATURE_DURATION;

// `solana-pubkey` crate doesn't compile to wasm
#[near(serializers=[borsh])]
#[derive(Clone, Copy)]
pub struct Pubkey(pub [u8; 32]);

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        bs58::encode(self.0).into_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let pubkey = bs58::decode(s)
            .into_vec()
            .map_err(serde::de::Error::custom)?;
        Ok(Pubkey(<[u8; 32]>::try_from(pubkey).map_err(|_| {
            serde::de::Error::custom("Invalid pubkey length")
        })?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SolanaSignature {
    pub signature: Signature,
    /// Example message: 'I want to sign in to alice.near with key ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP. The current date is 2025-01-01T00:00:00Z UTC'
    /// The date should be within [`SIGNATURE_DURATION`] of the current date, but not in the future.
    pub message: String,
}

#[near(serializers=[json, borsh])]
#[derive(Clone)]
pub struct SolanaRecoveryMethod {
    #[cfg_attr(feature = "abi", schemars(with = "String"))]
    pub recovery_wallet_address: Pubkey,
}

impl SolanaRecoveryMethod {
    pub fn check(&self, message: &str) -> Option<PublicKey> {
        let current_account_id = near_sdk::env::current_account_id();

        let Ok(signature) = serde_json::from_str::<SolanaSignature>(message) else {
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

        if !signature.signature.verify(
            &self.recovery_wallet_address.0,
            signature.message.as_bytes(),
        ) {
            return None;
        }

        Some(public_key)
    }
}

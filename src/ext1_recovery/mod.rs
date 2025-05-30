use evm_wallet::EvmRecoveryMethod;
use near_sdk::{CryptoHash, Promise, PublicKey, ext_contract, near, require, store::LookupSet};
use solana_wallet::SolanaRecoveryMethod;
use std::time::Duration;

use crate::{Contract, ContractExt, utils::StorageCell};

pub mod evm_wallet;
pub mod solana_wallet;

pub const MAX_RECOVERY_METHODS: usize = 100;
const EXTENSION_ID: u8 = 1;

// This trait uses `&self` event for mutating methods because
// it doesn't really do anything besides storing global contract
// state, but since state is stored in `StorageCell`s, it's not
// needed, and will save at least 46 bytes of storage, which at
// the stage of account creation is sponsored by the wallet.
#[ext_contract(ext1_recovery)]
pub trait Ext1Recovery {
    /// Get all recovery methods
    fn ext1_get_recovery_methods(&self) -> Vec<RecoveryMethod>;
    /// Replace the array of recovery methods
    fn ext1_set_recovery_methods(&self, recovery_methods: Vec<RecoveryMethod>);
    /// Add a recovery method. `message` is used to check if the recovery method is valid
    /// and the user has access to it, the format is the same as in [`Ext1Recovery::ext1_recover`].
    fn ext1_add_recovery_method(&self, recovery_method: RecoveryMethod, message: String);
    /// Recover the account using a recovery method. `message` is a JSON string with format
    /// depending on the recovery method, see [`RecoveryMethod`] for more details.
    fn ext1_recover(&self, message: String);
}

/// A signature is valid for 5 minutes
pub const SIGNATURE_DURATION: Duration = Duration::from_millis(5 * 60 * 1000);

#[near(serializers=[json, borsh])]
#[derive(Clone)]
pub enum RecoveryMethod {
    /// Recover with an EIP-712 signature. The `message` format is JSON string of [`evm_wallet::EvmSignature`]
    Evm(EvmRecoveryMethod),
    /// Recover with a Solana signature. The `message` format is JSON string of [`solana_wallet::SolanaSignature`]
    Solana(SolanaRecoveryMethod),
}

impl RecoveryMethod {
    pub fn check(&self, message: &str) -> Option<PublicKey> {
        match self {
            RecoveryMethod::Evm(evm_method) => evm_method.check(message),
            RecoveryMethod::Solana(solana_method) => solana_method.check(message),
        }
    }
}

const STORAGE_KEY_RECOVERY_METHODS: &[u8] = &[EXTENSION_ID];
const STORAGE_KEY_USED_SIGNATURES: &[u8] = &[EXTENSION_ID, b'u'];

pub fn storage_recovery_methods() -> StorageCell<Vec<RecoveryMethod>> {
    StorageCell::load(STORAGE_KEY_RECOVERY_METHODS)
}

pub fn storage_used_signatures() -> LookupSet<CryptoHash> {
    LookupSet::new(STORAGE_KEY_USED_SIGNATURES)
}

#[near(event_json(standard = "intear-smart-wallet"))]
pub enum Ext1RecoveryEvent {
    #[event_version("1.0.0")]
    RecoveryMethodsUpdated(Vec<RecoveryMethod>),
    #[event_version("1.0.0")]
    AccountRecovered {
        recovery_method: RecoveryMethod,
        new_public_key: PublicKey,
    },
}

#[near]
impl Ext1Recovery for Contract {
    fn ext1_get_recovery_methods(&self) -> Vec<RecoveryMethod> {
        storage_recovery_methods().clone()
    }

    #[private]
    fn ext1_set_recovery_methods(&self, recovery_methods: Vec<RecoveryMethod>) {
        require!(
            recovery_methods.len() <= MAX_RECOVERY_METHODS,
            "Extension 1: Too many recovery methods"
        );
        let mut stored_recovery_methods = storage_recovery_methods();
        *stored_recovery_methods = recovery_methods;
        Ext1RecoveryEvent::RecoveryMethodsUpdated(stored_recovery_methods.clone()).emit();
    }

    #[private]
    fn ext1_add_recovery_method(&self, recovery_method: RecoveryMethod, message: String) {
        // It's ok to not guard against replay attacks as this method is private
        let mut recovery_methods = storage_recovery_methods();
        require!(
            recovery_methods.len() < MAX_RECOVERY_METHODS,
            "Extension 1: Too many recovery methods"
        );
        if let Some(public_key) = recovery_method.check(&message) {
            require!(
                near_sdk::env::signer_account_pk() == public_key,
                "Extension 1: Should sign with the same public key as the recovery method"
            );
            recovery_methods.push(recovery_method);
            Ext1RecoveryEvent::RecoveryMethodsUpdated(recovery_methods.clone()).emit();
        } else {
            near_sdk::env::panic_str("Extension 1: Recovery method check failed");
        }
    }

    fn ext1_recover(&self, message: String) {
        require!(
            storage_used_signatures().insert(near_sdk::env::sha256_array(message.as_bytes())),
            "Extension 1: Already used this message"
        );
        for recovery_method in storage_recovery_methods().iter() {
            if let Some(public_key) = recovery_method.check(&message) {
                Promise::new(near_sdk::env::current_account_id())
                    .add_full_access_key(public_key.clone());
                Ext1RecoveryEvent::AccountRecovered {
                    recovery_method: recovery_method.clone(),
                    new_public_key: public_key,
                }
                .emit();
                return;
            }
        }
        near_sdk::env::panic_str("No recovery method matched the provided signature");
    }
}

use evm_wallet::EvmRecoveryMethod;
use near_sdk::{Promise, PublicKey, ext_contract, near, require};
use solana_wallet::SolanaRecoveryMethod;
use std::time::Duration;

use crate::{Contract, ContractExt};

pub mod evm_wallet;
pub mod solana_wallet;

pub const MAX_RECOVERY_METHODS: usize = 100;

#[ext_contract(ext1_recovery)]
pub trait Ext1Recovery {
    /// Get all recovery methods
    fn ext1_get_recovery_methods(&self) -> Vec<RecoveryMethod>;
    /// Replace the array of recovery methods
    fn ext1_set_recovery_methods(&mut self, recovery_methods: Vec<RecoveryMethod>);
    /// Add a recovery method. `message` is used to check if the recovery method is valid
    /// and the user has access to it, the format is the same as in [`Ext1Recovery::ext1_recover`].
    fn ext1_add_recovery_method(&mut self, recovery_method: RecoveryMethod, message: String);
    /// Recover the account using a recovery method. `message` is a JSON string with format
    /// depending on the recovery method, see [`RecoveryMethod`] for more details.
    fn ext1_recover(&mut self, message: String);
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

#[near]
impl Ext1Recovery for Contract {
    fn ext1_get_recovery_methods(&self) -> Vec<RecoveryMethod> {
        self.ext1_recovery_methods.into_iter().cloned().collect()
    }

    #[private]
    fn ext1_set_recovery_methods(&mut self, recovery_methods: Vec<RecoveryMethod>) {
        require!(
            recovery_methods.len() <= MAX_RECOVERY_METHODS,
            "Extension 1: Too many recovery methods"
        );
        self.ext1_recovery_methods.clear();
        self.ext1_recovery_methods.extend(recovery_methods);
    }

    #[private]
    fn ext1_add_recovery_method(&mut self, recovery_method: RecoveryMethod, message: String) {
        // It's ok to not guard against replay attacks as this method is private
        require!(
            self.ext1_recovery_methods.len() < MAX_RECOVERY_METHODS as u32,
            "Extension 1: Too many recovery methods"
        );
        if let Some(public_key) = recovery_method.check(&message) {
            require!(
                near_sdk::env::signer_account_pk() == public_key,
                "Extension 1: Should sign with the same public key as the recovery method"
            );
            self.ext1_recovery_methods.push(recovery_method);
        } else {
            near_sdk::env::panic_str("Extension 1: Recovery method check failed");
        }
    }

    fn ext1_recover(&mut self, message: String) {
        require!(
            self.ext1_used_signatures
                .insert(near_sdk::env::sha256_array(message.as_bytes())),
            "Extension 1: Already used this message"
        );
        for recovery_method in &self.ext1_recovery_methods {
            if let Some(public_key) = recovery_method.check(&message) {
                Promise::new(near_sdk::env::current_account_id()).add_full_access_key(public_key);
                return;
            }
        }
        near_sdk::env::panic_str("No recovery method matched the provided signature");
    }
}

// Assumption: Iterating over the recovery methods should be fine because
// the number of recovery methods is expected to be small.

use near_sdk::{PanicOnDefault, Promise, PublicKey, near, store::Vector};
use std::time::Duration;

pub mod evm;
pub mod solana;

pub use evm::EvmRecoveryMethod;
pub use solana::SolanaRecoveryMethod;

pub const SIGNATURE_DURATION: Duration = Duration::from_millis(5 * 60 * 1000);

#[near(serializers=[json,borsh])]
pub enum RecoveryMethod {
    Test,
    Evm(EvmRecoveryMethod),
    Solana(SolanaRecoveryMethod),
}

impl RecoveryMethod {
    pub fn check(&self, message: &str) -> Option<PublicKey> {
        match self {
            RecoveryMethod::Evm(evm_method) => evm_method.check(message),
            RecoveryMethod::Solana(solana_method) => solana_method.check(message),
            RecoveryMethod::Test => todo!(),
        }
    }
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    recovery_methods: Vector<RecoveryMethod>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(initial_recovery_method: Option<RecoveryMethod>) -> Self {
        let mut recovery_methods = Vector::new(b"recovery_methods".to_vec());
        if let Some(method) = initial_recovery_method {
            recovery_methods.push(method);
        }
        Self { recovery_methods }
    }

    pub fn get_recovery_methods(&self) -> Vec<&RecoveryMethod> {
        self.recovery_methods.into_iter().collect()
    }

    #[private]
    pub fn set_recovery_methods(&mut self, recovery_methods: Vec<RecoveryMethod>) {
        self.recovery_methods.clear();
        self.recovery_methods.extend(recovery_methods);
    }

    #[private]
    pub fn add_recovery_method(&mut self, recovery_method: RecoveryMethod) {
        self.recovery_methods.push(recovery_method);
    }

    pub fn recover(&mut self, message: String) {
        for recovery_method in &self.recovery_methods {
            if let Some(public_key) = recovery_method.check(&message) {
                Promise::new(near_sdk::env::current_account_id()).add_full_access_key(public_key);
                return;
            }
        }
        near_sdk::env::panic_str("No recovery method matched the provided signature");
    }
}

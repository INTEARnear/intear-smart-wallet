// Assumption: Iterating over the recovery methods should be fine because
// the number of recovery methods is expected to be small.

use ext1_recovery::RecoveryMethod;
use near_sdk::{near, store::Vector};

pub mod ext1_recovery;

#[near(contract_state)]
pub struct Contract {
    ext1_recovery_methods: Vector<RecoveryMethod>,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            ext1_recovery_methods: Vector::new(b"ext1_recovery_methods".to_vec()),
        }
    }
}

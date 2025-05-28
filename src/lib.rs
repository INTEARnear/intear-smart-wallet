use ext1_recovery::RecoveryMethod;
use near_sdk::{
    CryptoHash, near,
    store::{LookupSet, Vector},
};

pub mod ext1_recovery;

#[near(contract_state)]
pub struct Contract {
    ext1_recovery_methods: Vector<RecoveryMethod>,
    ext1_used_signatures: LookupSet<CryptoHash>,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            ext1_recovery_methods: Vector::new(b"ext1_recovery_methods".to_vec()),
            ext1_used_signatures: LookupSet::new(b"ext1_used_signatures".to_vec()),
        }
    }
}

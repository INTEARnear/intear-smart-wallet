use crate::{Contract, ContractExt, utils::StorageCell};

use near_sdk::near;

type Version = u64;
const MIGRATION_STORAGE_KEY: &[u8] = &[0]; // extensions prefixes start with 1
const LATEST_STATE_VERSION: Version = 2;

const STATE_STORAGE_KEY: &[u8] = b"STATE";

#[near(event_json(standard = "intear-smart-wallet"))]
pub enum MigrationEvent {
    #[event_version("1.0.0")]
    Migrated { from: Version, to: Version },
}

#[near]
impl Contract {
    pub fn before_upgrade(&self) {
        let mut version = StorageCell::<Version>::load(MIGRATION_STORAGE_KEY);
        if *version == 0 {
            *version = LATEST_STATE_VERSION;
        }
    }

    #[init(ignore_state)]
    pub fn after_upgrade() -> Self {
        let mut version = StorageCell::<Version>::load(MIGRATION_STORAGE_KEY); // 0 if not set
        let initial_version = *version;

        if *version == 0 {
            // Removed the global contract `STATE` and replaced all extension
            // data with `StorageCell`s

            #[near(serializers=[borsh])]
            struct OldContractState {
                ext1_recovery_methods:
                    near_sdk::store::Vector<crate::ext1_recovery::RecoveryMethod>,
                ext1_used_signatures: near_sdk::store::LookupSet<near_sdk::CryptoHash>,
            }

            let state_data =
                near_sdk::env::storage_read(STATE_STORAGE_KEY).expect("Failed to read old state");
            let old_state: OldContractState =
                near_sdk::borsh::BorshDeserialize::try_from_slice(&state_data)
                    .expect("Failed to deserialize old state");

            crate::ext1_recovery::storage_recovery_methods()
                .extend(old_state.ext1_recovery_methods.into_iter().cloned());

            near_sdk::env::storage_remove(STATE_STORAGE_KEY);
            *version += 1;
        }

        if *version == 1 {
            // Added NEP-297 events for indexing
            let recovery_methods = crate::ext1_recovery::storage_recovery_methods();
            crate::ext1_recovery::Ext1RecoveryEvent::Ext1RecoveryMethodsUpdated(
                recovery_methods.clone(),
            )
            .emit();

            *version += 1;
        }

        MigrationEvent::Migrated {
            from: initial_version,
            to: *version,
        }
        .emit();

        Contract
    }
}

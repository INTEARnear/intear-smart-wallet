use near_sdk::near;

pub mod ext1_recovery;
pub mod migrations;
pub mod utils;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract;

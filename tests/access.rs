use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::ext1_recovery::{RecoveryMethod, evm_wallet::EvmRecoveryMethod};
use near_workspaces::types::{KeyType, SecretKey};

#[tokio::test]
async fn test_cannot_call_private_methods_from_different_account() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy contract (uses Default initialization automatically)
    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Create a different user account
    let user_account = worker.dev_create_account().await?;

    // Try to call ext1_set_recovery_methods from different account - should fail
    let new_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: LocalSigner::random().address(),
    });

    let set_result = user_account
        .call(contract.id(), "ext1_set_recovery_methods")
        .args_json(serde_json::json!({"recovery_methods": vec![new_recovery_method]}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        set_result.is_err(),
        "Should not be able to call ext1_set_recovery_methods from different account"
    );

    // Try to call ext1_add_recovery_method from different account - should fail
    let add_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: LocalSigner::random().address(),
    });

    let add_result = user_account
        .call(contract.id(), "ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": add_recovery_method,
            "message": "dummy_message"
        }))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        add_result.is_err(),
        "Should not be able to call ext1_add_recovery_method from different account"
    );

    Ok(())
}

#[tokio::test]
async fn test_can_call_recover_from_different_account() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy contract (uses Default initialization automatically)
    let contract = worker.dev_deploy(&contract_wasm).await?;

    let evm_signer = LocalSigner::random();
    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    // Use existing public key for add_recovery_method
    let existing_public_key = contract
        .view_access_keys()
        .await?
        .into_iter()
        .next()
        .unwrap()
        .public_key;
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        existing_public_key,
        current_time
    );

    let signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature,
            message: message.clone(),
        },
    )?;

    // Add recovery method from contract account
    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method,
            "message": signature_json.clone()
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Create a different user account
    let user_account = worker.dev_create_account().await?;

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    let recovery_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let recovery_signature = evm_signer
        .sign_message_sync(recovery_message.as_bytes())
        .expect("Failed to sign message");

    let recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Call ext1_recover from different account - should succeed
    user_account
        .call(contract.id(), "ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result()
        .expect("Failed to call ext1_recover");

    // Verify that the new public key was actually added
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key)
        .await;

    assert!(
        access_key_result.is_ok(),
        "Public key should have been added to the contract account"
    );

    Ok(())
}

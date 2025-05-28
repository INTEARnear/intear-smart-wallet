use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::EvmRecoveryMethod;
use intear_smart_wallet::RecoveryMethod;
use near_workspaces::types::PublicKey as WorkspacesPublicKey;

#[tokio::test]
async fn test_cannot_call_new_twice() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    // Deploy and initialize contract
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Try to call new again - this should fail
    let recovery_method2 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    let second_init_result = contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method2}))
        .transact()
        .await?
        .into_result();

    assert!(
        second_init_result.is_err(),
        "Should not be able to call new() twice on the same contract"
    );

    Ok(())
}

#[tokio::test]
async fn test_cannot_call_private_methods_from_different_account() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    // Deploy and initialize contract
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Create a different user account
    let user_account = worker.dev_create_account().await?;

    // Try to call set_recovery_methods from different account - should fail
    let new_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: LocalSigner::random().address(),
    });

    let set_result = user_account
        .call(contract.id(), "set_recovery_methods")
        .args_json(serde_json::json!({"recovery_methods": vec![new_recovery_method]}))
        .transact()
        .await?
        .into_result();

    assert!(
        set_result.is_err(),
        "Should not be able to call set_recovery_methods from different account"
    );

    // Try to call add_recovery_method from different account - should fail
    let add_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: LocalSigner::random().address(),
    });

    let add_result = user_account
        .call(contract.id(), "add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": add_recovery_method}))
        .transact()
        .await?
        .into_result();

    assert!(
        add_result.is_err(),
        "Should not be able to call add_recovery_method from different account"
    );

    Ok(())
}

#[tokio::test]
async fn test_can_call_recover_from_different_account() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    // Deploy and initialize contract
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Create a different user account
    let user_account = worker.dev_create_account().await?;

    // Prepare recovery message
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: message.clone(),
    })?;

    // Call recover from different account - should succeed
    let recover_result = user_account
        .call(contract.id(), "recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(
        recover_result.is_ok(),
        "Should be able to call recover from different account"
    );

    // Verify that the public key was actually added
    let target_public_key_parsed: WorkspacesPublicKey = target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_ok(),
        "Public key should have been added to the contract account"
    );

    Ok(())
}

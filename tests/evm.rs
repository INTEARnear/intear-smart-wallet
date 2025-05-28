use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::EvmRecoveryMethod;
use intear_smart_wallet::RecoveryMethod;
use near_workspaces::types::PublicKey as WorkspacesPublicKey;

#[tokio::test]
async fn test_evm_recovery_success() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    // Deploy contract with initial recovery method
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;

    assert_eq!(recovery_methods.len(), 1, "Should have one recovery method");

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

    contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;

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

#[tokio::test]
async fn test_evm_recovery_with_wrong_signer() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up recovery method with one signer
    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Try to recover with a different signer
    let wrong_signer = LocalSigner::random();
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let signature = wrong_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: message.clone(),
    })?;

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    // The transaction should fail because the wrong signer was used
    assert!(
        result.is_err(),
        "Recovery call should fail with wrong signer"
    );

    // Verify that the public key was NOT added
    let target_public_key_parsed: WorkspacesPublicKey = target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_err(),
        "Public key should NOT have been added when recovery fails"
    );

    Ok(())
}

#[tokio::test]
async fn test_evm_recovery_with_expired_timestamp() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    // Use a timestamp from 10 minutes ago (should be expired)
    let expired_time = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        expired_time
    );

    let signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: message.clone(),
    })?;

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with expired timestamp"
    );

    // Verify that the public key was NOT added
    let target_public_key_parsed: WorkspacesPublicKey = target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_err(),
        "Public key should NOT have been added when recovery fails"
    );

    Ok(())
}

#[tokio::test]
async fn test_evm_recovery_with_wrong_account_id() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    // Use wrong account ID
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        "wrong-account.testnet", target_public_key, current_time
    );

    let signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: message.clone(),
    })?;

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with wrong account ID"
    );

    // Verify that the public key was NOT added
    let target_public_key_parsed: WorkspacesPublicKey = target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_err(),
        "Public key should NOT have been added when recovery fails"
    );

    Ok(())
}

#[tokio::test]
async fn test_evm_recovery_with_invalid_message_format() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Invalid message format
    let invalid_message = "This is not the correct format";

    let signature = evm_signer
        .sign_message_sync(invalid_message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: invalid_message.to_string(),
    })?;

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with invalid message format"
    );

    // Verify that the public key was NOT added (we need a valid public key format for this check)
    let valid_target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let target_public_key_parsed: WorkspacesPublicKey = valid_target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_err(),
        "Public key should NOT have been added when recovery fails"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_evm_recovery_methods() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up multiple EVM recovery methods
    let evm_signer1 = LocalSigner::random();
    let evm_signer2 = LocalSigner::random();

    let initial_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer1.address(),
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": initial_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Add second recovery method using the contract's own account
    let second_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer2.address(),
    });

    contract
        .call("add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": second_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let stored_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;

    assert_eq!(stored_methods.len(), 2, "Should have two recovery methods");

    // Test recovery with the second signer
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let signature = evm_signer2
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: signature,
        message: message.clone(),
    })?;

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(result.is_ok(), "Recovery should succeed with second signer");

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

use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::ext1_recovery::{RecoveryMethod, evm_wallet::EvmRecoveryMethod};
use near_workspaces::types::{KeyType, SecretKey};

#[tokio::test]
async fn test_evm_recovery_success() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract_wasm = near_workspaces::compile_project("./").await?;

    let evm_signer = LocalSigner::random();
    let evm_address = evm_signer.address();

    let recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_address,
    });

    // Deploy contract (uses Default initialization automatically)
    let contract = worker.dev_deploy(&contract_wasm).await?;

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

    // Add recovery method first
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

    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;

    assert_eq!(recovery_methods.len(), 1, "Should have one recovery method");

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

    contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

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

    // Add recovery method first
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

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    let recovery_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    // Try to recover with a different signer
    let wrong_signer = LocalSigner::random();
    let wrong_signature = wrong_signer
        .sign_message_sync(recovery_message.as_bytes())
        .expect("Failed to sign message");

    let wrong_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: wrong_signature,
            message: recovery_message.clone(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": wrong_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    // The transaction should fail because the wrong signer was used
    assert!(
        result.is_err(),
        "Recovery call should fail with wrong signer"
    );

    // Verify that the public key was NOT added
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key)
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

    // Use existing public key for add_recovery_method
    let existing_public_key = contract
        .view_access_keys()
        .await?
        .into_iter()
        .next()
        .unwrap()
        .public_key;
    let current_time = chrono::Utc::now().to_rfc3339();
    let current_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        existing_public_key,
        current_time
    );

    let current_signature = evm_signer
        .sign_message_sync(current_message.as_bytes())
        .expect("Failed to sign message");

    let current_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: current_signature,
            message: current_message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method,
            "message": current_signature_json
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    // Use a timestamp from 10 minutes ago (should be expired)
    let expired_time = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let expired_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        expired_time
    );

    let expired_signature = evm_signer
        .sign_message_sync(expired_message.as_bytes())
        .expect("Failed to sign message");

    let expired_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: expired_signature,
            message: expired_message.clone(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": expired_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with expired timestamp"
    );

    // Verify that the public key was NOT added
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key)
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

    // Use existing public key for add_recovery_method
    let existing_public_key = contract
        .view_access_keys()
        .await?
        .into_iter()
        .next()
        .unwrap()
        .public_key;
    let current_time = chrono::Utc::now().to_rfc3339();
    let correct_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        existing_public_key,
        current_time
    );

    let correct_signature = evm_signer
        .sign_message_sync(correct_message.as_bytes())
        .expect("Failed to sign message");

    let correct_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: correct_signature,
            message: correct_message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method,
            "message": correct_signature_json
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    // Try to recover with wrong account ID in message
    let wrong_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        "wrong-account.testnet", target_public_key, current_time
    );

    let wrong_signature = evm_signer
        .sign_message_sync(wrong_message.as_bytes())
        .expect("Failed to sign message");

    let wrong_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: wrong_signature,
            message: wrong_message.clone(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": wrong_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with wrong account ID"
    );

    // Verify that the public key was NOT added
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key)
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

    // Use existing public key for add_recovery_method
    let existing_public_key = contract
        .view_access_keys()
        .await?
        .into_iter()
        .next()
        .unwrap()
        .public_key;
    let current_time = chrono::Utc::now().to_rfc3339();
    let correct_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        existing_public_key,
        current_time
    );

    let correct_signature = evm_signer
        .sign_message_sync(correct_message.as_bytes())
        .expect("Failed to sign message");

    let correct_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: correct_signature,
            message: correct_message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method,
            "message": correct_signature_json
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    // Try to recover with invalid message format
    let invalid_message = "This is not the correct format";

    let invalid_signature = evm_signer
        .sign_message_sync(invalid_message.as_bytes())
        .expect("Failed to sign message");

    let invalid_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: invalid_signature,
            message: invalid_message.to_string(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": invalid_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery call should fail with invalid message format"
    );

    // Verify that the public key was NOT added
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key)
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

    let evm_signer1 = LocalSigner::random();
    let evm_signer2 = LocalSigner::random();

    let recovery_method1 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer1.address(),
    });

    let recovery_method2 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer2.address(),
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

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

    // Add first recovery method
    let signature1 = evm_signer1
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json1 = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: signature1,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method1,
            "message": signature_json1.clone()
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Add second recovery method
    let signature2 = evm_signer2
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let signature_json2 = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: signature2,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method2,
            "message": signature_json2.clone()
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;

    assert_eq!(
        recovery_methods.len(),
        2,
        "Should have two recovery methods"
    );

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    let recovery_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let recovery_signature = evm_signer1
        .sign_message_sync(recovery_message.as_bytes())
        .expect("Failed to sign message");

    let recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Test recovery with first signer
    contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

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

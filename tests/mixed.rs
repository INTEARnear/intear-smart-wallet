use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::ext1_recovery::{
    RecoveryMethod, evm_wallet::EvmRecoveryMethod, solana_wallet::SolanaRecoveryMethod,
};
use near_workspaces::types::{KeyType, SecretKey};
use solana_signer::Signer;

#[tokio::test]
async fn test_mixed_recovery_methods() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up both EVM and Solana recovery methods
    let evm_signer = LocalSigner::random();
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let evm_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
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

    // Add EVM recovery method first
    let evm_signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let evm_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: evm_signature,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": evm_recovery_method,
            "message": evm_signature_json.clone()
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Add Solana recovery method
    let solana_recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
    });

    let solana_signature = solana_keypair.sign_message(message.as_bytes());

    let solana_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature: solana_signature,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": solana_recovery_method,
            "message": solana_signature_json
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let stored_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;
    assert_eq!(stored_methods.len(), 2, "Should have two recovery methods");

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    let recovery_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let evm_recovery_signature = evm_signer
        .sign_message_sync(recovery_message.as_bytes())
        .expect("Failed to sign message");

    let evm_recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: evm_recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Test recovery with EVM signer
    let evm_result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": evm_recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(evm_result.is_ok(), "EVM recovery should succeed");

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
async fn test_mixed_recovery_methods_solana() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up both EVM and Solana recovery methods
    let evm_signer = LocalSigner::random();
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let evm_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
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

    // Add EVM recovery method first
    let evm_signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let evm_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: evm_signature,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": evm_recovery_method,
            "message": evm_signature_json
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Add Solana recovery method
    let solana_recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
    });

    let solana_signature = solana_keypair.sign_message(message.as_bytes());

    let solana_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature: solana_signature,
            message: message.clone(),
        },
    )?;

    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": solana_recovery_method,
            "message": solana_signature_json.clone()
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let stored_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;
    assert_eq!(stored_methods.len(), 2, "Should have two recovery methods");

    // Use a different random public key for recovery testing
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
    let recovery_message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let solana_recovery_signature = solana_keypair.sign_message(recovery_message.as_bytes());

    let solana_recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature: solana_recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Test recovery with Solana signer
    let solana_result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": solana_recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(solana_result.is_ok(), "Solana recovery should succeed");

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
async fn test_recovery_fails_with_no_methods() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy contract (uses Default initialization automatically)
    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Verify no recovery methods
    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;
    assert_eq!(recovery_methods.len(), 0, "Should have no recovery methods");

    // Try to recover with any signature - should fail
    let evm_signer = LocalSigner::random();
    let target_public_key = SecretKey::from_random(KeyType::ED25519).public_key();
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

    let signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature,
            message: message.clone(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery should fail when no recovery methods are set"
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
async fn test_add_recovery_method() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Initially no recovery methods
    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("ext1_get_recovery_methods").await?.json()?;
    assert_eq!(
        recovery_methods.len(),
        0,
        "Should start with no recovery methods"
    );

    // Add an EVM recovery method
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

    // Verify the recovery method was added
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

    // Test that recovery works
    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(result.is_ok(), "Recovery should succeed");

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

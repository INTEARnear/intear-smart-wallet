use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::ext1_recovery::{
    RecoveryMethod, evm_wallet::EvmRecoveryMethod, solana_wallet::SolanaRecoveryMethod,
};
use near_workspaces::types::{KeyType, SecretKey};
use solana_signer::Signer;

#[tokio::test]
async fn test_recovery_methods_updated_event_on_add() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
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

    // Add recovery method and capture the transaction outcome
    let outcome = contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method,
            "message": signature_json
        }))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "Transaction should succeed");

    // Check that the RecoveryMethodsUpdated event was emitted
    assert_eq!(
        outcome.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"recovery_methods_updated\",\"data\":[{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}}]}}",
            evm_signer.address().to_string().to_lowercase()
        )]
    );

    Ok(())
}

#[tokio::test]
async fn test_recovery_methods_updated_event_on_set() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    let evm_signer1 = LocalSigner::random();
    let evm_signer2 = LocalSigner::random();

    let recovery_method1 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer1.address(),
    });

    let recovery_method2 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer2.address(),
    });

    let recovery_methods = vec![recovery_method1, recovery_method2];

    // Set recovery methods and capture the transaction outcome
    let outcome = contract
        .call("ext1_set_recovery_methods")
        .args_json(serde_json::json!({
            "recovery_methods": recovery_methods
        }))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "Transaction should succeed");

    // Check that the RecoveryMethodsUpdated event was emitted
    assert_eq!(
        outcome.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"recovery_methods_updated\",\"data\":[{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}},{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}}]}}",
            evm_signer1.address().to_string().to_lowercase(),
            evm_signer2.address().to_string().to_lowercase()
        )]
    );

    Ok(())
}

#[tokio::test]
async fn test_account_recovered_event() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
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

    // Add recovery method first
    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method.clone(),
            "message": signature_json
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

    let recovery_signature = evm_signer
        .sign_message_sync(recovery_message.as_bytes())
        .expect("Failed to sign message");

    let recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::evm_wallet::EvmSignature {
            signature: recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Perform recovery and capture the transaction outcome
    let outcome = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "Recovery should succeed");

    // Check that the AccountRecovered event was emitted
    assert_eq!(
        outcome.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"account_recovered\",\"data\":{{\"recovery_method\":{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}},\"new_public_key\":\"{}\"}}}}",
            evm_signer.address().to_string().to_lowercase(),
            target_public_key
        )]
    );

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
async fn test_multiple_recovery_methods_updated_events() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    let evm_signer1 = LocalSigner::random();
    let evm_signer2 = LocalSigner::random();

    let recovery_method1 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer1.address(),
    });

    let recovery_method2 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer2.address(),
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

    let outcome1 = contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method1,
            "message": signature_json1
        }))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome1.is_success(), "First add should succeed");

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

    let outcome2 = contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method2,
            "message": signature_json2
        }))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome2.is_success(), "Second add should succeed");

    // Verify both transactions emitted RecoveryMethodsUpdated events
    assert_eq!(
        outcome1.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"recovery_methods_updated\",\"data\":[{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}}]}}",
            evm_signer1.address().to_string().to_lowercase()
        )]
    );

    assert_eq!(
        outcome2.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"recovery_methods_updated\",\"data\":[{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}},{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}}]}}",
            evm_signer1.address().to_string().to_lowercase(),
            evm_signer2.address().to_string().to_lowercase()
        )]
    );

    Ok(())
}

#[tokio::test]
async fn test_no_event_on_failed_recovery() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Try to recover without any recovery methods set
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

    // This should fail since no recovery methods are set
    let outcome = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .max_gas()
        .transact()
        .await?;

    let result = outcome.into_result();
    assert!(
        result.is_err(),
        "Recovery should fail when no recovery methods are set"
    );

    // Check the logs from the failed transaction
    if let Err(error) = result {
        // Verify that no events were emitted on failed recovery
        assert_eq!(error.logs(), vec![] as Vec<String>);
    }

    // Verify that the public key was not added
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
async fn test_solana_account_recovered_event() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Create a Solana keypair for testing
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
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

    let signature = solana_keypair.sign_message(message.as_bytes());

    let signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature,
            message: message.clone(),
        },
    )?;

    // Add recovery method first
    contract
        .call("ext1_add_recovery_method")
        .args_json(serde_json::json!({
            "recovery_method": recovery_method.clone(),
            "message": signature_json
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

    let recovery_signature = solana_keypair.sign_message(recovery_message.as_bytes());

    let recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature: recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    // Perform recovery and capture the transaction outcome
    let outcome = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "Recovery should succeed");

    // Check that the AccountRecovered event was emitted
    assert_eq!(
        outcome.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"account_recovered\",\"data\":{{\"recovery_method\":{{\"Solana\":{{\"recovery_wallet_address\":\"{}\"}}}},\"new_public_key\":\"{}\"}}}}",
            solana_keypair.pubkey(),
            target_public_key
        )]
    );

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
async fn test_mixed_recovery_methods_events() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    // Set up both EVM and Solana recovery methods
    let evm_signer = LocalSigner::random();
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let evm_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    let solana_recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
    });

    let recovery_methods = vec![evm_recovery_method, solana_recovery_method];

    // Set both recovery methods and capture the transaction outcome
    let outcome = contract
        .call("ext1_set_recovery_methods")
        .args_json(serde_json::json!({
            "recovery_methods": recovery_methods
        }))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "Transaction should succeed");

    // Check that the RecoveryMethodsUpdated event was emitted
    assert_eq!(
        outcome.logs(),
        vec![format!(
            "EVENT_JSON:{{\"standard\":\"intear-smart-wallet\",\"version\":\"1.0.0\",\"event\":\"recovery_methods_updated\",\"data\":[{{\"Evm\":{{\"recovery_wallet_address\":\"{}\"}}}},{{\"Solana\":{{\"recovery_wallet_address\":\"{}\"}}}}]}}",
            evm_signer.address().to_string().to_lowercase(),
            solana_keypair.pubkey()
        )]
    );

    Ok(())
}

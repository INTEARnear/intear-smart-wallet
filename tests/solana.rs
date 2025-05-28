use intear_smart_wallet::ext1_recovery::{RecoveryMethod, solana_wallet::SolanaRecoveryMethod};
use near_workspaces::types::{KeyType, SecretKey};
use solana_signer::Signer;

#[tokio::test]
async fn test_solana_recovery_success() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Create a Solana keypair for testing
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    // Create Solana recovery method
    let recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
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

    let recovery_signature = solana_keypair.sign_message(recovery_message.as_bytes());

    let recovery_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
            signature: recovery_signature,
            message: recovery_message.clone(),
        },
    )?;

    let result = contract
        .call("ext1_recover")
        .args_json(serde_json::json!({"message": recovery_signature_json}))
        .max_gas()
        .transact()
        .await?
        .into_result();

    assert!(result.is_ok(), "Solana recovery should succeed");

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
async fn test_solana_recovery_with_wrong_signer() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up recovery method with one Solana keypair
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::ext1_recovery::solana_wallet::Pubkey(
            solana_pubkey_bytes,
        ),
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
            "recovery_method": recovery_method,
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

    // Try to recover with a different Solana keypair
    let wrong_keypair = solana_keypair::Keypair::new();
    let wrong_signature = wrong_keypair.sign_message(recovery_message.as_bytes());

    let wrong_signature_json = serde_json::to_string(
        &intear_smart_wallet::ext1_recovery::solana_wallet::SolanaSignature {
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

    assert!(
        result.is_err(),
        "Recovery call should fail with wrong Solana signer"
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

use intear_smart_wallet::RecoveryMethod;
use intear_smart_wallet::SolanaRecoveryMethod;
use near_workspaces::types::PublicKey as WorkspacesPublicKey;
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
        recovery_wallet_address: intear_smart_wallet::solana::Pubkey(solana_pubkey_bytes),
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
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let signature = solana_keypair.sign_message(message.as_bytes());

    let signature_json = serde_json::to_string(&intear_smart_wallet::solana::SolanaSignature {
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

    assert!(result.is_ok(), "Solana recovery should succeed");

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
async fn test_solana_recovery_with_wrong_signer() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up recovery method with one Solana keypair
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::solana::Pubkey(solana_pubkey_bytes),
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Try to recover with a different Solana keypair
    let wrong_keypair = solana_keypair::Keypair::new();
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let signature = wrong_keypair.sign_message(message.as_bytes());

    let signature_json = serde_json::to_string(&intear_smart_wallet::solana::SolanaSignature {
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
        "Recovery call should fail with wrong Solana signer"
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

use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use intear_smart_wallet::EvmRecoveryMethod;
use intear_smart_wallet::RecoveryMethod;
use intear_smart_wallet::SolanaRecoveryMethod;
use near_workspaces::types::PublicKey as WorkspacesPublicKey;
use solana_signer::Signer;

#[tokio::test]
async fn test_mixed_recovery_methods() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up both EVM and Solana recovery methods
    let evm_signer = LocalSigner::random();
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let initial_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": initial_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Add Solana recovery method
    let solana_recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::solana::Pubkey(solana_pubkey_bytes),
    });

    contract
        .call("add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": solana_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let stored_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(stored_methods.len(), 2, "Should have two recovery methods");

    // Test recovery with EVM signer
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let evm_signature = evm_signer
        .sign_message_sync(message.as_bytes())
        .expect("Failed to sign message");

    let evm_signature_json = serde_json::to_string(&intear_smart_wallet::evm::EvmSignature {
        signature: evm_signature,
        message: message.clone(),
    })?;

    let evm_result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": evm_signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(evm_result.is_ok(), "EVM recovery should succeed");

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
async fn test_mixed_recovery_methods_solana() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Set up both EVM and Solana recovery methods
    let evm_signer = LocalSigner::random();
    let solana_keypair = solana_keypair::Keypair::new();
    let solana_pubkey_bytes = solana_keypair.pubkey().to_bytes();

    let initial_recovery_method = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer.address(),
    });

    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": initial_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    // Add Solana recovery method
    let solana_recovery_method = RecoveryMethod::Solana(SolanaRecoveryMethod {
        recovery_wallet_address: intear_smart_wallet::solana::Pubkey(solana_pubkey_bytes),
    });

    contract
        .call("add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": solana_recovery_method}))
        .transact()
        .await?
        .into_result()?;

    let stored_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(stored_methods.len(), 2, "Should have two recovery methods");

    // Test recovery with Solana signer
    let target_public_key = "ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP";
    let current_time = chrono::Utc::now().to_rfc3339();
    let message = format!(
        "I want to sign in to {} with key {}. The current date is {} UTC",
        contract.id(),
        target_public_key,
        current_time
    );

    let solana_signature = solana_keypair.sign_message(message.as_bytes());

    let solana_signature_json =
        serde_json::to_string(&intear_smart_wallet::solana::SolanaSignature {
            signature: solana_signature,
            message: message.clone(),
        })?;

    let solana_result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": solana_signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(solana_result.is_ok(), "Solana recovery should succeed");

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
async fn test_recovery_fails_with_no_methods() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy contract with no initial recovery method
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": null}))
        .transact()
        .await?
        .into_result()?;

    // Verify no recovery methods
    let recovery_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(recovery_methods.len(), 0, "Should have no recovery methods");

    // Try to recover with any message
    let evm_signer = LocalSigner::random();
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

    let result = contract
        .call("recover")
        .args_json(serde_json::json!({"message": signature_json}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?
        .into_result();

    assert!(
        result.is_err(),
        "Recovery should fail when no methods are configured"
    );

    // Verify that the public key was NOT added
    let target_public_key_parsed: WorkspacesPublicKey = target_public_key.parse()?;
    let access_key_result = contract
        .as_account()
        .view_access_key(&target_public_key_parsed)
        .await;

    assert!(
        access_key_result.is_err(),
        "Public key should NOT have been added when no recovery methods are configured"
    );

    Ok(())
}

#[tokio::test]
async fn test_add_recovery_method() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy contract with no initial recovery method
    let contract = worker.dev_deploy(&contract_wasm).await?;

    contract
        .call("new")
        .args_json(serde_json::json!({"initial_recovery_method": null}))
        .transact()
        .await?
        .into_result()?;

    // Initially no recovery methods
    let initial_methods: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(
        initial_methods.len(),
        0,
        "Should start with no recovery methods"
    );

    // Add first recovery method
    let evm_signer1 = LocalSigner::random();
    let recovery_method1 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer1.address(),
    });

    contract
        .call("add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": recovery_method1}))
        .transact()
        .await?
        .into_result()?;

    let methods_after_first: Vec<RecoveryMethod> =
        contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(
        methods_after_first.len(),
        1,
        "Should have one recovery method"
    );

    // Add second recovery method
    let evm_signer2 = LocalSigner::random();
    let recovery_method2 = RecoveryMethod::Evm(EvmRecoveryMethod {
        recovery_wallet_address: evm_signer2.address(),
    });

    contract
        .call("add_recovery_method")
        .args_json(serde_json::json!({"recovery_method": recovery_method2}))
        .transact()
        .await?
        .into_result()?;

    let final_methods: Vec<RecoveryMethod> = contract.view("get_recovery_methods").await?.json()?;
    assert_eq!(final_methods.len(), 2, "Should have two recovery methods");

    Ok(())
}

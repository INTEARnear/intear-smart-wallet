# Intear Smart Wallet contract

The smart contract that is deployed for all Intear Wallet accounts

> WARNING: This smart contract has not been audited, use with caution

## Extensions

The methods are structured as a `ext{X}_{name}`, where `X` is the number of the extension, and `name` is the name of a method.

The contract itself has no initialization function, and all extensions have a default state, and should not do anything unless explicitly enabled or interacted with by the user.

### Extension 1: Recovery

Allows adding EVM or Solana wallet as a recovery method, and using a valid signature from this method to recover (add a full access key) the account. In the future, social auth (e.g. Google) and social recovery (N out of K trusted friends) will be added.

#### Methods

##### `ext1_get_recovery_methods() -> Vec<RecoveryMethod>`

**Access**: View-only method

Returns all configured recovery methods for the current account.

**Returns:** Array of recovery methods (EVM or Solana wallets)

##### `ext1_set_recovery_methods(recovery_methods: Vec<RecoveryMethod>)`

**Access:** Private method (can only be called by the user who owns the contract)

Replaces the entire array of recovery methods with the provided ones.

Note that it doesn't do any validation that the user actually has access to the recovery methods, so it can potentially be dangerous if used without caution.

**Parameters:**
- `recovery_methods`: Array of recovery methods to set

##### `ext1_add_recovery_method(recovery_method: RecoveryMethod, message: String)`

**Access:** Private method (can only be called by the user who owns the contract)

Adds a new recovery method after validating that the caller has access to it by checking the provided signature.

**Parameters:**
- `recovery_method`: The recovery method to add (EVM or Solana)
- `message`: JSON string containing the signature proof (format depends on recovery method type). The message's public key should be the same as the key used to sign this transaction

##### `ext1_recover(message: String)`

**Access**: Public method (can be called by anyone, such as a relayer, if they have a valid signature)

Recovers the account by adding a full access key using a valid signature from one of the configured recovery methods.

**Parameters:**
- `message`: JSON string containing the signature and public key. Check below for exact format for each recovery method

#### Recovery Method Types

##### EVM Recovery Method

For Ethereum-compatible wallets using ERC-191 (`personal_sign`) signatures.

**Structure:**
```json
{
  "Evm": {
    "recovery_wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96c4b4d8b6"
  }
}
```

**Message Format for `ext1_recover`:**
```json
{
  "signature": {
    "r": "0x23ca1f32913f248fd5b5a269a633f616d82b4932fec6c5fdd0d91cfc7a9028af",
    "s": "0x308d08aa15cbbbb1346b5cb1edffcfb82d34f55a6f7a29069d7b7ad670c5adc3", 
    "yParity": "0x1",
    "v": "0x1"
  }, // EIP-712 signature
  "message": "I want to sign in to alice.near with key ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP. The current date is 2025-01-01T00:00:00Z UTC"
}
```

##### Solana Recovery Method

For Solana wallets using Ed25519 signatures.

**Structure:**
```json
{
  "Solana": {
    "recovery_wallet_address": "S1im3nx5z9x4r67evLNr22mcL96NmkRi3XGDw3cSjoj" // Base58 encoded pubkey
  }
}
```

**Message Format for `ext1_recover`:**
```json
{
  "signature": [239,143,125,202,211,7,155,46,67,253,223,54,230,55,1,204,116,13,125,85,207,54,160,25,78,227,245,32,94,12,28,151,105,90,243,136,59,18,49,226,250,225,69,228,6,22,194,96,219,87,239,59,177,98,212,39,92,193,136,21,182,210,121,11], // Solana signature
  "message": "I want to sign in to alice.near with key ed25519:HbRkc1dTdSLwA1wFTDVNxJE4PCQVmpwwXwTzTGrqdhaP. The current date is 2025-01-01T00:00:00Z UTC"
}
```

#### Message Format Requirements

For both EVM and Solana recovery methods, the signed message must follow this exact format:

```
I want to sign in to {ACCOUNT_ID} with key {PUBLIC_KEY}. The current date is {ISO_8601_DATE} UTC
```

Where:
- `{ACCOUNT_ID}`: The NEAR account ID being recovered
- `{PUBLIC_KEY}`: The NEAR public key to be added as a full access key (format: `ed25519:...` or `secp256k1:...`)
- `{ISO_8601_DATE}`: Current date in ISO 8601 format (e.g., `2025-01-01T00:00:00Z`)

**Important:** The signature timestamp must be within 5 minutes of the current block time and cannot be in the future (compared to `near_sdk::env::block_timestamp_ms()`).

## Deployments

This is a global smart contract, where deployments are referenced by `code_hash`. Current deployments with commits:

_Currently none_

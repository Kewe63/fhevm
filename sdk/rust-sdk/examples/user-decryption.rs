use alloy::primitives::address;
use gateway_sdk::utils::validate_address_from_str;
use gateway_sdk::{FhevmError, FhevmSdk, FhevmSdkBuilder};
use serde_json::json;
use std::path::PathBuf;
use tracing::{Level, error, info, warn};

/// Complete user decrypt example - from encrypted input to curl command
///
/// Workflow:
/// 1. Create encrypted inputs (handles)
/// 2. Generate EIP-712 signature for user decrypt
/// 3. Generate user decrypt calldata
/// 4. Prepare curl command for relayer
fn main() -> Result<(), FhevmError> {
    // Initialize logging from environment variables
    gateway_sdk::logging::init_from_env(Level::INFO);

    info!("🚀 Starting Complete User Decrypt Example");

    let mut sdk = create_configured_sdk()?;

    let handles = create_sample_encrypted_inputs(&mut sdk)?;
    let eip712_result = generate_user_decrypt_signature(&sdk)?;
    let calldata = generate_user_decrypt_calldata(&sdk, &handles, &eip712_result)?;
    prepare_relayer_curl_command(&handles, &eip712_result)?;

    info!("🎉 User decrypt example completed successfully");
    Ok(())
}

/// Create a properly configured SDK instance
fn create_configured_sdk() -> Result<FhevmSdk, FhevmError> {
    info!("Creating SDK instance...");

    let sdk = FhevmSdkBuilder::new()
        .with_keys_directory(PathBuf::from("./keys"))
        .with_gateway_chain_id(43113)
        .with_host_chain_id(11155111)
        .with_decryption_contract("0x1234567890123456789012345678901234567bbb")
        .with_input_verification_contract("0x1234567890123456789012345678901234567aaa")
        .with_acl_contract("0x0987654321098765432109876543210987654321")
        .build()?;

    info!("✅ SDK configured successfully");
    Ok(sdk)
}

/// Create sample encrypted inputs and return their handles
fn create_sample_encrypted_inputs(sdk: &mut FhevmSdk) -> Result<Vec<Vec<u8>>, FhevmError> {
    info!("Creating encrypted inputs...");

    let contract_address = validate_address_from_str("0x7777777777777777777777777777777777777777")?;
    let user_address = validate_address_from_str("0x8888888888888888888888888888888888888888")?;

    let mut builder = sdk.create_input_builder()?;
    builder.add_bool(true)?;
    builder.add_u32(42)?;
    builder.add_u64(18446744073709550042)?;
    let encrypted_input = builder.encrypt_and_prove_for(contract_address, user_address)?;

    let handles: Vec<Vec<u8>> = encrypted_input.handles.iter().map(|h| h.to_vec()).collect();

    info!("✅ Created {} encrypted handles", handles.len());
    for (i, handle) in handles.iter().enumerate() {
        info!("   Handle {}: 0x{}", i, hex::encode(handle));
    }

    Ok(handles)
}

/// Generate EIP-712 signature for user decrypt
fn generate_user_decrypt_signature(
    sdk: &FhevmSdk,
) -> Result<gateway_sdk::signature::Eip712Result, FhevmError> {
    info!("Generating EIP-712 signature...");

    let public_key = "2000000000000000a554e431f47ef7b1dd1b72a43432b06213a959953ec93785f2c699af9bc6f331";
    let contract_addresses = vec![
        validate_address_from_str("0x56a24bcaE11890353726596fD6f5cABb5a126Df9")?,
        validate_address_from_str("0x7777777777777777777777777777777777777777")?,
    ];

    let start_timestamp = 1748252823u64;
    let duration_days = 10u64;
    let wallet_private_key = "7136d8dc72f873124f4eded25f3525a20f6cee4296564c76b44f1d582c57640f";

    let eip712_result = sdk
        .create_eip712_signature_builder()
        .with_public_key(public_key)
        .with_contract_addresses_vec(contract_addresses)
        .with_validity_period(start_timestamp, duration_days)
        .with_private_key(wallet_private_key)
        .with_verification(true)
        .generate_and_sign()?;

    if !eip712_result.is_signed() {
        return Err(FhevmError::SignatureError("Failed to generate signature".to_string()));
    }

    if !eip712_result.is_verified() {
        warn!("⚠️ Signature verification failed");
    } else {
        info!("✅ Signature generated and verified successfully");
    }

    Ok(eip712_result)
}

/// Generate user decrypt calldata using the signature
fn generate_user_decrypt_calldata(
    sdk: &FhevmSdk,
    handles: &[Vec<u8>],
    eip712_result: &gateway_sdk::signature::Eip712Result,
) -> Result<Vec<u8>, FhevmError> {
    info!("Generating user decrypt calldata...");

    let user_address = "0xfCefe53c7012a075b8a711df391100d9c431c468";
    let contract_addresses = vec![
        address!("0x56a24bcaE11890353726596fD6f5cABb5a126Df9"),
        address!("0x7777777777777777777777777777777777777777"),
    ];

    let signature_bytes = eip712_result.require_signature()?;
    let signature_hex = hex::encode(signature_bytes);
    let public_key_hex = "2000000000000000a554e431f47ef7b1dd1b72a43432b06213a959953ec93785f2c699af9bc6f331";

    let calldata = sdk
        .create_user_decrypt_request_builder()
        .with_handles_from_bytes(handles, &contract_addresses)?
        .with_user_address_from_str(user_address)?
        .with_signature_from_hex(&signature_hex)?
        .with_public_key_from_hex(public_key_hex)?
        .with_validity(1748252823u64, 10u64)?
        .build_and_generate_calldata()?;

    info!("✅ Calldata generated: {} bytes", calldata.len());
    Ok(calldata)
}

/// Prepare curl command for relayer
fn prepare_relayer_curl_command(
    handles: &[Vec<u8>],
    eip712_result: &gateway_sdk::signature::Eip712Result,
) -> Result<(), FhevmError> {
    info!("Preparing relayer curl command...");

    let handle_contract_pairs: Vec<_> = handles
        .iter()
        .enumerate()
        .map(|(i, handle)| {
            json!({
                "ctHandle": format!("0x{}", hex::encode(handle)),
                "contractAddress": if i == 0 {
                    "0x56a24bcaE11890353726596fD6f5cABb5a126Df9"
                } else {
                    "0x7777777777777777777777777777777777777777"
                }
            })
        })
        .collect();

    let signature_bytes = eip712_result.require_signature()?;
    let signature_hex = hex::encode(signature_bytes);

    let payload = json!({
        "handleContractPairs": handle_contract_pairs,
        "requestValidity": {
            "startTimestamp": "1748252823",
            "durationDays": "10"
        },
        "contractAddresses": [
            "0x56a24bcaE11890353726596fD6f5cABb5a126Df9",
            "0x7777777777777777777777777777777777777777"
        ],
        "userAddress": "0xfCefe53c7012a075b8a711df391100d9c431c468",
        "signature": signature_hex,
        "publicKey": "2000000000000000a554e431f47ef7b1dd1b72a43432b06213a959953ec93785f2c699af9bc6f331"
    });

    let compact_curl = format!(
        r#"curl -X POST 'http://localhost:3000/v1/user-decrypt' -H 'Content-Type: application/json' -d '{}' "#,
        serde_json::to_string(&payload).unwrap()
    );

    info!("📋 Compact curl command:");
    println!("{compact_curl}");

    Ok(())
}

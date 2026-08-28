use std::{
    env,
    io::Write,
    process::{Command, Stdio},
};

use hardware_wallet_chain_api::{
    BoundedBytes, ChainExecution, ChainModule, CryptoOperation, CryptoOutput, Curve,
    ExecutionStep, HashAlgorithm, PublicKeyFormat, SignatureScheme,
};
use hardware_wallet_chain_bitcoin::{
    Bitcoin, Request, Response, extract_p2wpkh_witness, MAX_PSBT_BYTES,
};
use hardware_wallet_core::{
    AccountId, AuthId, Event, HostId, HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId,
    SetupId, State, WalletContextId, update,
};

fn main() {
    let rpc = env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL from chain-sandbox");
    let signer_wallet = env::var("BITCOIN_SIGNER_WALLET").expect("signer wallet from sandbox");
    let expected_pubkey =
        decode_hex(&env::var("BITCOIN_TEST_PUBKEY").expect("test pubkey from sandbox"));
    assert_eq!(expected_pubkey.len(), 33);

    let sandbox_rpc = wallet_url(&rpc, "sandbox");
    let signer_rpc = wallet_url(&rpc, &signer_wallet);
    let destination = rpc_result_string(&rpc_call(
        &sandbox_rpc,
        "getnewaddress",
        "[\"\",\"bech32\"]",
    ));

    let funded_params = format!(
        "[[],[{{\"{destination}\":1.0}}],0,{{\"add_inputs\":true,\"subtractFeeFromOutputs\":[0],\"replaceable\":false}},true]"
    );
    let funded = rpc_call(&signer_rpc, "walletcreatefundedpsbt", &funded_params);
    let psbt_base64 = json_field_string(&funded, "psbt");
    let psbt_bytes = decode_base64(&psbt_base64);
    let psbt = BoundedBytes::<MAX_PSBT_BYTES>::from_slice(&psbt_bytes).expect("PSBT fits firmware budget");

    let request = Request::SignPsbt {
        key: KeyTarget {
            account: AccountId(0),
            path: hardware_wallet_core::DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        },
        psbt,
    };
    let review = Bitcoin::prepare_review(&request).expect("device parses Core PSBT");

    let process_params = format!("[\"{psbt_base64}\",true,\"ALL\",true]");
    let processed = rpc_call(&signer_rpc, "walletprocesspsbt", &process_params);
    let signed_psbt = json_field_string(&processed, "psbt");
    let finalize_params = format!("[\"{signed_psbt}\",true]");
    let finalized = rpc_call(&signer_rpc, "finalizepsbt", &finalize_params);
    let reference_hex = json_field_string(&finalized, "hex");
    let reference_raw = decode_hex(&reference_hex);
    let witness = extract_p2wpkh_witness(&reference_raw).expect("Core reference is P2WPKH");
    assert_eq!(witness.public_key.as_slice(), expected_pubkey.as_slice());

    let mut execution =
        Bitcoin::prepare_execution(&review, unlocked_context()).expect("approved execution");
    let mut step = execution.next(None).expect("first execution step");

    let ours = loop {
        let output = match step {
            ExecutionStep::Crypto(operation) => execute_crypto(&execution, operation, witness),
            ExecutionStep::Complete(Response::SignedTransaction(raw)) => break raw,
            ExecutionStep::Complete(Response::PublicKey(_)) => {
                panic!("PSBT signing unexpectedly completed with a public key")
            }
        };
        step = execution
            .next(Some(&output))
            .expect("chain execution accepts runtime output");
    };

    assert_eq!(ours.as_slice(), reference_raw.as_slice());

    let send_params = format!("[\"{}\"]", encode_hex(ours.as_slice()));
    let send_response = rpc_call(&rpc, "sendrawtransaction", &send_params);
    let txid = rpc_result_string(&send_response);
    assert_eq!(txid.len(), 64);
    let mempool = rpc_call(&rpc, "getmempoolentry", &format!("[\"{txid}\"]"));
    assert!(mempool.contains("\"result\""));

    println!("bitcoin e2e: {txid}");
}

fn execute_crypto(
    execution: &hardware_wallet_chain_bitcoin::Execution,
    operation: CryptoOperation,
    witness: hardware_wallet_chain_bitcoin::P2wpkhWitness,
) -> CryptoOutput {
    match operation {
        CryptoOperation::DerivePublicKey { format, .. } => {
            assert_eq!(format, PublicKeyFormat::Compressed);
            CryptoOutput::PublicKey {
                format,
                bytes: BoundedBytes::from_slice(&witness.public_key).expect("pubkey fits"),
            }
        }
        CryptoOperation::Hash { algorithm, payload } => {
            let bytes = execution
                .payload(payload)
                .unwrap_or_else(|| panic!("missing payload {payload:?}"));
            let digest = match algorithm {
                HashAlgorithm::Hash160 => hash160(bytes),
                HashAlgorithm::DoubleSha256 => double_sha256(bytes),
                _ => panic!("unexpected Bitcoin hash algorithm: {algorithm:?}"),
            };
            CryptoOutput::Digest {
                algorithm,
                bytes: BoundedBytes::from_slice(&digest).expect("digest fits"),
            }
        }
        CryptoOperation::Sign {
            scheme,
            prehash,
            payload,
            ..
        } => {
            assert_eq!(
                scheme,
                SignatureScheme::Ecdsa {
                    curve: Curve::Secp256k1,
                    recoverable: false,
                }
            );
            assert_eq!(prehash, HashAlgorithm::DoubleSha256);
            assert!(execution.payload(payload).is_some());
            CryptoOutput::Signature {
                scheme,
                bytes: BoundedBytes::from_slice(&witness.compact_signature)
                    .expect("signature fits"),
                recovery_id: None,
            }
        }
    }
}

fn hash160(input: &[u8]) -> Vec<u8> {
    digest_once("-ripemd160", &digest_once("-sha256", input))
}

fn double_sha256(input: &[u8]) -> Vec<u8> {
    digest_once("-sha256", &digest_once("-sha256", input))
}

fn digest_once(algorithm: &str, input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(["dgst", algorithm, "-binary"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl must be installed on the CI runner");
    child
        .stdin
        .as_mut()
        .expect("openssl stdin")
        .write_all(input)
        .expect("write digest input");
    let output = child.wait_with_output().expect("wait for openssl");
    assert!(output.status.success(), "openssl digest failed");
    output.stdout
}

fn unlocked_context() -> hardware_wallet_core::ExecutionContext {
    let setup = SetupId(1);
    let host = HostId(7);
    let auth = AuthId(2);
    let mut state = State::default();
    state = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Disabled,
        },
    )
    .state;
    state = update(state, Event::KeyMaterialReady(setup)).state;
    state = update(state, Event::BackupShown(setup)).state;
    state = update(state, Event::BackupVerified(setup)).state;
    state = update(state, Event::PinConfigured(setup)).state;
    state = update(state, Event::ProvisioningPersisted(setup)).state;
    state = update(state, Event::UnlockRequested { id: auth, host }).state;
    state = update(
        state,
        Event::HostTrustResolved {
            id: auth,
            trust: HostTrust::Trusted,
        },
    )
    .state;
    state = update(state, Event::PinVerified(auth)).state;
    state = update(
        state,
        Event::SessionOpened {
            auth,
            session: SessionId(3),
            wallet: WalletContextId(4),
        },
    )
    .state;
    state.execution_context().expect("wallet is unlocked")
}

fn wallet_url(rpc: &str, wallet: &str) -> String {
    format!("{rpc}/wallet/{wallet}")
}

fn rpc_call(url: &str, method: &str, params: &str) -> String {
    let body = format!(
        "{{\"jsonrpc\":\"1.0\",\"id\":\"hardware-wallet-e2e\",\"method\":\"{method}\",\"params\":{params}}}"
    );
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--header",
            "content-type: text/plain;",
            "--data-binary",
            &body,
            url,
        ])
        .output()
        .expect("curl must be available");
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = String::from_utf8(output.stdout).expect("RPC response is UTF-8");
    assert!(
        response.contains("\"error\":null") || response.contains("\"error\": null"),
        "Bitcoin RPC error: {response}"
    );
    response
}

fn rpc_result_string(response: &str) -> String {
    json_string_after_key(response, "result")
}

fn json_field_string(response: &str, key: &str) -> String {
    json_string_after_key(response, key)
}

fn json_string_after_key(response: &str, key: &str) -> String {
    let marker = format!("\"{key}\"");
    let key_start = response
        .find(&marker)
        .unwrap_or_else(|| panic!("missing {marker} in {response}"));
    let rest = &response[key_start + marker.len()..];
    let colon = rest.find(':').expect("JSON colon");
    let value = rest[colon + 1..].trim_start();
    let quoted = value
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("{key} is not a string: {response}"));
    let end = quoted.find('"').expect("JSON string terminator");
    quoted[..end].to_owned()
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex length must be even");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

fn decode_base64(value: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    let mut quartet = [0_u8; 4];
    let mut len = 0_usize;
    for character in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        quartet[len] = character;
        len += 1;
        if len == 4 {
            let a = base64_value(quartet[0]);
            let b = base64_value(quartet[1]);
            output.push((a << 2) | (b >> 4));
            if quartet[2] != b'=' {
                let c = base64_value(quartet[2]);
                output.push((b << 4) | (c >> 2));
                if quartet[3] != b'=' {
                    let d = base64_value(quartet[3]);
                    output.push((c << 6) | d);
                }
            }
            len = 0;
        }
    }
    assert_eq!(len, 0, "base64 must be padded to quartets");
    output
}

fn base64_value(value: u8) -> u8 {
    match value {
        b'A'..=b'Z' => value - b'A',
        b'a'..=b'z' => value - b'a' + 26,
        b'0'..=b'9' => value - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!("invalid base64 digit"),
    }
}

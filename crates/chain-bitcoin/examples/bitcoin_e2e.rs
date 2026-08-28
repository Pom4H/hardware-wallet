use std::{env, process::Command};

use hardware_wallet_chain_api::{ChainExecution, ChainModule, CryptoOperation, ExecutionStep};
use hardware_wallet_chain_bitcoin::{Bitcoin, MAX_PSBT_BYTES, Request, Response};
use hardware_wallet_core::{
    AccountId, AuthId, DerivationPath, Event, HostId, HostTrust, KeyPurpose, KeyTarget,
    PassphraseMode, SessionId, SetupId, State, WalletContextId, update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};

fn main() {
    let rpc = env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL from chain-sandbox");
    let signer_wallet = env::var("BITCOIN_SIGNER_WALLET").expect("signer wallet from sandbox");
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
    let psbt = hardware_wallet_chain_api::BoundedBytes::<MAX_PSBT_BYTES>::from_slice(&psbt_bytes)
        .expect("PSBT fits firmware budget");

    let target = key_target();
    let request = Request::SignPsbt { key: target, psbt };
    let review = Bitcoin::prepare_review(&request).expect("device parses Core PSBT");
    let mut execution =
        Bitcoin::prepare_execution(&review, unlocked_context()).expect("approved execution");

    let mut secret = [0_u8; 32];
    secret[31] = 1;
    let backend = SoftwareKeyBackend::secp256k1(WalletContextId(4), target, secret)
        .expect("known regtest key is valid");
    let runtime = CryptoRuntime::new(backend);

    let mut step = execution.next(None).expect("first execution step");
    let signed = loop {
        match step {
            ExecutionStep::Crypto(operation) => {
                let output = execute_crypto(&runtime, &execution, operation);
                step = execution
                    .next(Some(&output))
                    .expect("chain accepts runtime output");
            }
            ExecutionStep::Complete(Response::SignedTransaction(raw)) => break raw,
            ExecutionStep::Complete(Response::PublicKey(_)) => {
                panic!("PSBT signing unexpectedly completed with a public key")
            }
        }
    };

    let send_params = format!("[\"{}\"]", encode_hex(signed.as_slice()));
    let send_response = rpc_call(&rpc, "sendrawtransaction", &send_params);
    let txid = rpc_result_string(&send_response);
    assert_eq!(txid.len(), 64);
    let mempool = rpc_call(&rpc, "getmempoolentry", &format!("[\"{txid}\"]"));
    assert!(mempool.contains("\"result\""));

    println!("bitcoin crypto-runtime e2e: {txid}");
}

fn execute_crypto(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    execution: &hardware_wallet_chain_bitcoin::Execution,
    operation: CryptoOperation,
) -> hardware_wallet_chain_api::CryptoOutput {
    let payload = match operation {
        CryptoOperation::DerivePublicKey { .. } => None,
        CryptoOperation::Hash { payload, .. } | CryptoOperation::Sign { payload, .. } => execution
            .payload(payload)
            .or_else(|| panic!("missing chain-owned payload {payload:?}")),
    };
    runtime
        .execute(operation, payload)
        .expect("software crypto runtime executes approved operation")
}

fn key_target() -> KeyTarget {
    KeyTarget {
        account: AccountId(0),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    }
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

use std::{env, process::Command};

use hardware_wallet_chain_api::{
    ChainExecution, ChainModule, CryptoOperation, CryptoOutput, ExecutionStep, PublicKeyFormat,
};
use hardware_wallet_chain_bitcoin::{Bitcoin, MAX_PSBT_BYTES, Request, Response};
use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, AuthId, ChildNumber, DerivationPath, Event, HostId,
    HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId, SetupId, State, WalletContextId,
    update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};
use hardware_wallet_hd_key_backend::{HdKeyBackend, KeyFamily};

const TEST_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const HD_WALLET: &str = "hardware-wallet-hd";

fn main() {
    let rpc = env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL from chain-sandbox");
    let sandbox_rpc = wallet_url(&rpc, "sandbox");

    let context = unlocked_context();
    let target = key_target();
    let locator = context.bind_key(target);
    let hd = HdKeyBackend::new(account_descriptor(), KeyFamily::Secp256k1Bip32, &TEST_SEED)
        .expect("HD backend");
    let backend = hd
        .software_backend(locator)
        .expect("derive BIP84 child key");
    let runtime = CryptoRuntime::new(backend);
    let public_key = derive_public_key(&runtime, locator);
    let descriptor = checked_descriptor(&rpc, &format!("wpkh({})", encode_hex(&public_key)));
    let signer_rpc = create_watch_wallet(&rpc, &descriptor);
    let signer_address = first_result_string(&rpc_call(
        &rpc,
        "deriveaddresses",
        &format!("[\"{descriptor}\"]"),
    ));

    let funding_txid = rpc_result_string(&rpc_call(
        &sandbox_rpc,
        "sendtoaddress",
        &format!("[\"{signer_address}\",1.0]"),
    ));
    assert_eq!(funding_txid.len(), 64);
    let miner_address = rpc_result_string(&rpc_call(
        &sandbox_rpc,
        "getnewaddress",
        "[\"\",\"bech32\"]",
    ));
    rpc_call(
        &sandbox_rpc,
        "generatetoaddress",
        &format!("[1,\"{miner_address}\"]"),
    );

    let destination = rpc_result_string(&rpc_call(
        &sandbox_rpc,
        "getnewaddress",
        "[\"\",\"bech32\"]",
    ));
    let funded_params = format!(
        "[[],[{{\"{destination}\":1.0}}],0,{{\"add_inputs\":true,\"includeWatching\":true,\"subtractFeeFromOutputs\":[0],\"replaceable\":false}},true]"
    );
    let funded = rpc_call(&signer_rpc, "walletcreatefundedpsbt", &funded_params);
    let psbt_base64 = json_field_string(&funded, "psbt");
    let psbt_bytes = decode_base64(&psbt_base64);
    let psbt = hardware_wallet_chain_api::BoundedBytes::<MAX_PSBT_BYTES>::from_slice(&psbt_bytes)
        .expect("PSBT fits firmware budget");

    let request = Request::SignPsbt { key: target, psbt };
    let review = Bitcoin::prepare_review(&request).expect("device parses HD-funded Core PSBT");
    let mut execution = Bitcoin::prepare_execution(&review, context).expect("approved execution");

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

    println!("bitcoin HD e2e: {txid}");
}

fn derive_public_key(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    locator: hardware_wallet_core::KeyLocator,
) -> [u8; 33] {
    let output = runtime
        .execute(
            CryptoOperation::DerivePublicKey {
                key: locator,
                format: PublicKeyFormat::Compressed,
            },
            None,
        )
        .expect("derive BIP84 public key");
    let CryptoOutput::PublicKey { bytes, .. } = output else {
        panic!("derive must return public key")
    };
    let mut public_key = [0_u8; 33];
    public_key.copy_from_slice(bytes.as_slice());
    public_key
}

fn checked_descriptor(rpc: &str, descriptor: &str) -> String {
    let info = rpc_call(rpc, "getdescriptorinfo", &format!("[\"{descriptor}\"]"));
    let checksum = json_field_string(&info, "checksum");
    format!("{descriptor}#{checksum}")
}

fn create_watch_wallet(rpc: &str, descriptor: &str) -> String {
    rpc_call(
        rpc,
        "createwallet",
        &format!("[\"{HD_WALLET}\",true,true,\"\",false,true]"),
    );
    let wallet_rpc = wallet_url(rpc, HD_WALLET);
    let imported = rpc_call(
        &wallet_rpc,
        "importdescriptors",
        &format!("[[{{\"desc\":\"{descriptor}\",\"timestamp\":\"now\"}}]]"),
    );
    assert!(
        imported.contains("\"success\":true") || imported.contains("\"success\": true"),
        "descriptor import failed: {imported}"
    );
    wallet_rpc
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
        .expect("HD-derived crypto runtime executes approved operation")
}

fn account_descriptor() -> AccountDescriptor {
    AccountDescriptor {
        id: AccountId(0),
        wallet: WalletContextId(4),
        kind: AccountKind::Hd,
        root: path(&[(84, true), (1, true), (0, true)]),
    }
}

fn key_target() -> KeyTarget {
    KeyTarget {
        account: AccountId(0),
        path: path(&[(0, false), (0, false)]),
        purpose: KeyPurpose::ExternalAddress,
    }
}

fn path(children: &[(u32, bool)]) -> DerivationPath {
    let mut path = DerivationPath::new();
    for &(index, hardened) in children {
        path.push(ChildNumber::new(index, hardened).expect("valid child"))
            .expect("path fits");
    }
    path
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

fn first_result_string(response: &str) -> String {
    let marker = "\"result\"";
    let key_start = response
        .find(marker)
        .unwrap_or_else(|| panic!("missing result in {response}"));
    let rest = &response[key_start + marker.len()..];
    let colon = rest.find(':').expect("JSON colon");
    let value = rest[colon + 1..].trim_start();
    let array = value
        .strip_prefix('[')
        .unwrap_or_else(|| panic!("result is not an array: {response}"))
        .trim_start();
    let quoted = array
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("first array value is not a string: {response}"));
    let end = quoted.find('"').expect("JSON string terminator");
    quoted[..end].to_owned()
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

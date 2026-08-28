use std::{env, process::Command, thread, time::Duration};

use hardware_wallet_chain_api::{
    ChainExecution, ChainModule, CryptoOperation, CryptoOutput, ExecutionStep, HashAlgorithm,
    PayloadId, PublicKeyFormat,
};
use hardware_wallet_chain_ethereum::{Ethereum, Request, Response, encode_native_transfer};
use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, AuthId, ChildNumber, DerivationPath, Event, HostId,
    HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId, SetupId, State, WalletContextId,
    update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};
use hardware_wallet_hd_key_backend::{HdKeyBackend, KeyFamily};

const DESTINATION: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const TEST_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31,
];

fn main() {
    let rpc = env::var("ETHEREUM_RPC_URL").expect("ETHEREUM_RPC_URL from chain-sandbox");
    let context = unlocked_context();
    let target = key_target();
    let locator = context.bind_key(target);
    let hd = HdKeyBackend::new(
        account_descriptor(),
        KeyFamily::Secp256k1Bip32,
        &TEST_SEED,
    )
    .expect("HD backend");
    let backend = hd
        .software_backend(locator)
        .expect("derive Ethereum BIP44 child key");
    let runtime = CryptoRuntime::new(backend);
    let sender = ethereum_address(&runtime, locator);
    fund_sender(&rpc, &sender);

    let destination = decode_address(DESTINATION);
    let unsigned = encode_native_transfer(
        31_337,
        0,
        1_000_000_000,
        2_000_000_000,
        21_000,
        destination,
        1,
    )
    .expect("fixture must encode");

    let request = Request::SignEip1559 {
        key: target,
        unsigned,
    };
    let review = Ethereum::prepare_review(&request).expect("device parses EIP-1559");
    let mut execution = Ethereum::prepare_execution(&review, context).expect("approved execution");

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
                panic!("transaction unexpectedly completed with a public key")
            }
        }
    };

    let send_request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x{}\"]}}",
        encode_hex(signed.as_slice())
    );
    let tx_hash = result_hex(&rpc_call(&rpc, &send_request));
    assert_eq!(tx_hash.len(), 64);

    let receipt = wait_for_receipt(&rpc, &tx_hash);
    assert!(receipt.contains("\"status\":\"0x1\""), "{receipt}");
    let transaction = rpc_call(
        &rpc,
        &format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"eth_getTransactionByHash\",\"params\":[\"0x{tx_hash}\"]}}"
        ),
    );
    assert!(
        transaction.to_ascii_lowercase().contains(&format!("\"from\":\"{sender}\"")),
        "network recovered unexpected sender: {transaction}"
    );

    println!("ethereum HD e2e: 0x{tx_hash} from {sender}");
}

fn ethereum_address(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    locator: hardware_wallet_core::KeyLocator,
) -> String {
    let public = runtime
        .execute(
            CryptoOperation::DerivePublicKey {
                key: locator,
                format: PublicKeyFormat::Uncompressed,
            },
            None,
        )
        .expect("derive Ethereum public key");
    let CryptoOutput::PublicKey { bytes, .. } = public else {
        panic!("derive must return public key")
    };
    assert_eq!(bytes.len(), 65);
    assert_eq!(bytes.as_slice()[0], 0x04);

    let digest = runtime
        .execute(
            CryptoOperation::Hash {
                algorithm: HashAlgorithm::Keccak256,
                payload: PayloadId(0),
            },
            Some(&bytes.as_slice()[1..]),
        )
        .expect("Keccak public key");
    let CryptoOutput::Digest { bytes, .. } = digest else {
        panic!("hash must return digest")
    };
    assert_eq!(bytes.len(), 32);
    format!("0x{}", encode_hex(&bytes.as_slice()[12..]))
}

fn fund_sender(rpc: &str, sender: &str) {
    let response = rpc_call(
        rpc,
        &format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anvil_setBalance\",\"params\":[\"{sender}\",\"0x56bc75e2d63100000\"]}}"
        ),
    );
    assert!(
        response.contains("\"result\":true") || response.contains("\"result\": true"),
        "failed to fund HD account: {response}"
    );
}

fn execute_crypto(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    execution: &hardware_wallet_chain_ethereum::Execution,
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
        root: path(&[(44, true), (60, true), (0, true)]),
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

fn wait_for_receipt(rpc: &str, tx_hash: &str) -> String {
    let request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"0x{tx_hash}\"]}}"
    );
    for _ in 0..50 {
        let response = rpc_call(rpc, &request);
        if response.contains("\"status\":\"0x1\"") {
            return response;
        }
        assert!(
            response.contains("\"result\":null"),
            "unexpected receipt response: {response}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    panic!("transaction 0x{tx_hash} was accepted but no successful receipt appeared")
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

fn rpc_call(url: &str, body: &str) -> String {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--header",
            "content-type: application/json",
            "--data-binary",
            body,
            url,
        ])
        .output()
        .expect("curl must be available on CI runner");
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("RPC response is UTF-8")
}

fn result_hex(response: &str) -> String {
    let marker = "\"result\":\"0x";
    let start = response
        .find(marker)
        .unwrap_or_else(|| panic!("missing hex result: {response}"))
        + marker.len();
    let rest = &response[start..];
    let end = rest.find('"').expect("hex result terminator");
    rest[..end].to_owned()
}

fn decode_address(value: &str) -> [u8; 20] {
    let decoded = decode_hex(value.strip_prefix("0x").expect("0x address"));
    let mut address = [0_u8; 20];
    address.copy_from_slice(&decoded);
    address
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
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

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

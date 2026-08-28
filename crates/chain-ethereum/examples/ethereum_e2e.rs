use std::{env, process::Command, thread, time::Duration};

use hardware_wallet_chain_api::{ChainExecution, ChainModule, CryptoOperation, ExecutionStep};
use hardware_wallet_chain_ethereum::{Ethereum, Request, Response, encode_native_transfer};
use hardware_wallet_core::{
    AccountId, AuthId, DerivationPath, Event, HostId, HostTrust, KeyPurpose, KeyTarget,
    PassphraseMode, SessionId, SetupId, State, WalletContextId, update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};

const SECOND_ACCOUNT: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const FIRST_ACCOUNT_SECRET: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn main() {
    let rpc = env::var("ETHEREUM_RPC_URL").expect("ETHEREUM_RPC_URL from chain-sandbox");
    let destination = decode_address(SECOND_ACCOUNT);
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

    let target = key_target();
    let request = Request::SignEip1559 {
        key: target,
        unsigned,
    };
    let review = Ethereum::prepare_review(&request).expect("device parses EIP-1559");
    let mut execution =
        Ethereum::prepare_execution(&review, unlocked_context()).expect("approved execution");

    let secret_vec = decode_hex(FIRST_ACCOUNT_SECRET);
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&secret_vec);
    let backend = SoftwareKeyBackend::secp256k1(WalletContextId(4), target, secret)
        .expect("Anvil test key is valid");
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

    println!("ethereum crypto-runtime e2e: 0x{tx_hash}");
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
        .expect("software crypto runtime executes approved operation")
}

fn key_target() -> KeyTarget {
    KeyTarget {
        account: AccountId(0),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    }
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

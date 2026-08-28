use std::{env, process::Command};

use hardware_wallet_chain_api::{
    BoundedBytes, ChainExecution, ChainModule, CryptoOutput, Curve, ExecutionStep, HashAlgorithm,
    SignatureScheme,
};
use hardware_wallet_chain_ethereum::{
    Ethereum, Request, Response, encode_native_transfer, signature_from_signed_eip1559,
};
use hardware_wallet_core::{
    AccountId, AuthId, Event, HostId, HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId,
    SetupId, State, WalletContextId, update,
};

const FIRST_ACCOUNT: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const SECOND_ACCOUNT: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

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

    let request = Request::SignEip1559 {
        key: KeyTarget {
            account: AccountId(0),
            path: hardware_wallet_core::DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        },
        unsigned: unsigned.clone(),
    };
    let review = Ethereum::prepare_review(&request).expect("device parses EIP-1559");
    let context = unlocked_context();
    let mut execution = Ethereum::prepare_execution(&review, context).expect("approved execution");

    let signing = execution.next(None).expect("first execution step");
    let ExecutionStep::Crypto(operation) = signing else {
        panic!("EIP-1559 must request a signature")
    };
    let hardware_wallet_core::CryptoOperation::Sign {
        scheme,
        prehash,
        payload,
        ..
    } = operation
    else {
        panic!("EIP-1559 must sign")
    };
    assert_eq!(
        scheme,
        SignatureScheme::Ecdsa {
            curve: Curve::Secp256k1,
            recoverable: true,
        }
    );
    assert_eq!(prehash, HashAlgorithm::Keccak256);
    assert_eq!(execution.payload(payload), Some(unsigned.as_slice()));

    let sign_request = [
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_signTransaction\",\"params\":[{\"type\":\"0x2\",\"from\":\"",
    FIRST_ACCOUNT,
    "\",\"to\":\"",
    SECOND_ACCOUNT,
    "\",\"nonce\":\"0x0\",\"value\":\"0x1\",\"gas\":\"0x5208\",\"maxPriorityFeePerGas\":\"0x3b9aca00\",\"maxFeePerGas\":\"0x77359400\",\"chainId\":\"0x7a69\",\"data\":\"0x\",\"accessList\":[]}]}"
]
.concat();
    let signed_by_anvil = result_hex(&rpc_call(&rpc, &sign_request));
    let signed_bytes = decode_hex(&signed_by_anvil);
    let signature =
        signature_from_signed_eip1559(&signed_bytes).expect("Anvil signed envelope parses");

    let crypto_output = CryptoOutput::Signature {
        scheme,
        bytes: BoundedBytes::from_slice(&signature.compact).expect("compact signature fits"),
        recovery_id: Some(signature.y_parity),
    };
    let completed = execution
        .next(Some(&crypto_output))
        .expect("signature finalizes transaction");
    let ExecutionStep::Complete(Response::SignedTransaction(ours)) = completed else {
        panic!("EIP-1559 execution must complete with a signed transaction")
    };
    assert_eq!(ours.as_slice(), signed_bytes.as_slice());

    let send_request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x{}\"]}}",
        encode_hex(ours.as_slice())
    );
    let send_response = rpc_call(&rpc, &send_request);
    let tx_hash = result_hex(&send_response);
    assert_eq!(tx_hash.len(), 64);

    let receipt_request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"0x{tx_hash}\"]}}"
    );
    let receipt = rpc_call(&rpc, &receipt_request);
    assert!(receipt.contains("\"status\":\"0x1\""), "{receipt}");

    println!("ethereum e2e: 0x{tx_hash}");
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

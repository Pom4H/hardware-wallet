use std::{env, process::Command, thread, time::Duration};

use hardware_wallet_chain_api::{ChainExecution, ChainModule, CryptoOperation, ExecutionStep};
use hardware_wallet_chain_solana::{Request, Response, Solana, encode_system_transfer};
use hardware_wallet_core::{
    AccountId, AuthId, DerivationPath, Event, HostId, HostTrust, KeyPurpose, KeyTarget,
    PassphraseMode, SessionId, SetupId, State, WalletContextId, update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};

const RECIPIENT: &str = "GcQfK48DV9BzDuDeCyV2sShbAAY4vqmK8JSj1NBrwoVZ";

fn main() {
    let rpc = env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL from chain-sandbox");
    let signer_text =
        env::var("SOLANA_TEST_PUBKEY").expect("SOLANA_TEST_PUBKEY from chain-sandbox");
    let cli = env::var("SOLANA_CLI").expect("SOLANA_CLI from chain-sandbox");

    fund_recipient(&cli, &rpc);
    let blockhash_text = latest_blockhash(&rpc);
    let signer = decode_base58::<32>(&signer_text);
    let recipient = decode_base58::<32>(RECIPIENT);
    let blockhash = decode_base58::<32>(&blockhash_text);
    let message = encode_system_transfer(signer, recipient, blockhash, 1).expect("message fits");

    let target = key_target();
    let request = Request::SignSystemTransfer {
        key: target,
        message,
    };
    let review = Solana::prepare_review(&request).expect("device parses system transfer");
    let mut execution =
        Solana::prepare_execution(&review, unlocked_context()).expect("approved execution");

    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::try_from(index + 1).expect("1..=32 fits u8");
    }
    let backend = SoftwareKeyBackend::ed25519(WalletContextId(4), target, secret);
    let runtime = CryptoRuntime::new(backend);

    let mut step = execution.next(None).expect("first execution step");
    let transaction = loop {
        match step {
            ExecutionStep::Crypto(operation) => {
                let output = execute_crypto(&runtime, &execution, operation);
                step = execution
                    .next(Some(&output))
                    .expect("chain accepts runtime output");
            }
            ExecutionStep::Complete(Response::SignedTransaction(raw)) => break raw,
            ExecutionStep::Complete(Response::PublicKey(_)) => {
                panic!("transfer unexpectedly completed with a public key")
            }
        }
    };

    let encoded = encode_base64(transaction.as_slice());
    let send = [
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"sendTransaction\",\"params\":[\"",
        &encoded,
        "\",{\"encoding\":\"base64\",\"preflightCommitment\":\"confirmed\"}]}",
    ]
    .concat();
    let sent_signature = result_string(&rpc_call(&rpc, &send));
    wait_for_confirmation(&rpc, &sent_signature);

    println!("solana crypto-runtime e2e: {sent_signature}");
}

fn execute_crypto(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    execution: &hardware_wallet_chain_solana::Execution,
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

fn fund_recipient(cli: &str, rpc: &str) {
    let output = Command::new(cli)
        .args(["airdrop", "1", RECIPIENT, "--url", rpc])
        .output()
        .expect("solana CLI must run");
    assert!(
        output.status.success(),
        "recipient airdrop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn latest_blockhash(rpc: &str) -> String {
    let response = rpc_call(
        rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLatestBlockhash\",\"params\":[]}",
    );
    json_string_after(&response, "\"blockhash\":\"")
}

fn wait_for_confirmation(rpc: &str, signature: &str) {
    let request = [
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"getSignatureStatuses\",\"params\":[[\"",
        signature,
        "\"],{\"searchTransactionHistory\":true}]}",
    ]
    .concat();
    for _ in 0..50 {
        let response = rpc_call(rpc, &request);
        if response.contains("\"err\":null")
            && (response.contains("\"confirmationStatus\":\"confirmed\"")
                || response.contains("\"confirmationStatus\":\"finalized\""))
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("transaction {signature} was sent but not confirmed")
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
        .expect("curl must be available");
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("RPC response is UTF-8")
}

fn result_string(response: &str) -> String {
    json_string_after(response, "\"result\":\"")
}

fn json_string_after(response: &str, marker: &str) -> String {
    let start = response
        .find(marker)
        .unwrap_or_else(|| panic!("missing {marker} in {response}"))
        + marker.len();
    let rest = &response[start..];
    let end = rest.find('"').expect("JSON string terminator");
    rest[..end].to_owned()
}

fn decode_base58<const N: usize>(value: &str) -> [u8; N] {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut output = [0_u8; N];
    for character in value.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .unwrap_or_else(|| panic!("invalid base58 character"));
        let mut carry = u32::try_from(digit).expect("base58 digit fits");
        for byte in output.iter_mut().rev() {
            let accumulator = u32::from(*byte) * 58 + carry;
            *byte = u8::try_from(accumulator & 0xff).expect("masked byte fits");
            carry = accumulator >> 8;
        }
        assert_eq!(carry, 0, "base58 value exceeds fixed output");
    }
    output
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((a & 0x03) << 4) | (b >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((b & 0x0f) << 2) | (c >> 6))],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(c & 0x3f)]));
        } else {
            output.push('=');
        }
    }
    output
}

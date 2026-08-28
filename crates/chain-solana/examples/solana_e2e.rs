use std::{env, process::Command, thread, time::Duration};

use hardware_wallet_chain_api::{
    ChainExecution, ChainModule, CryptoOperation, CryptoOutput, ExecutionStep, PublicKeyFormat,
};
use hardware_wallet_chain_solana::{Request, Response, Solana, encode_system_transfer};
use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, AuthId, ChildNumber, DerivationPath, Event, HostId,
    HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId, SetupId, State, WalletContextId,
    update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};
use hardware_wallet_hd_key_backend::{HdKeyBackend, KeyFamily};
use hardware_wallet_key_lifecycle::test_utils::{FixedEntropySource, MemorySecretStore};
use hardware_wallet_key_lifecycle::{KeyLifecycle, MnemonicSize, NormalizedPassphrase};

const RECIPIENT: &str = "GcQfK48DV9BzDuDeCyV2sShbAAY4vqmK8JSj1NBrwoVZ";
const TEST_ENTROPY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn main() {
    let rpc = env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL from chain-sandbox");
    let cli = env::var("SOLANA_CLI").expect("SOLANA_CLI from chain-sandbox");

    let mut lifecycle = KeyLifecycle::new(
        MemorySecretStore::new(),
        FixedEntropySource::new(TEST_ENTROPY),
    );
    lifecycle
        .begin_create(MnemonicSize::Words24)
        .expect("device entropy creates BIP39 wallet");
    lifecycle
        .commit_pending()
        .expect("provisioning persists root entropy");
    let wallet = lifecycle
        .open_context(&NormalizedPassphrase::empty())
        .expect("open base wallet context");

    let context = unlocked_context(wallet.id());
    let target = key_target();
    let locator = context.bind_key(target);
    let hd = HdKeyBackend::new(
        account_descriptor(wallet.id()),
        KeyFamily::Ed25519Slip10,
        wallet.seed(),
    )
    .expect("HD backend");
    let backend = hd
        .software_backend(locator)
        .expect("derive Solana SLIP-0010 child key");
    let runtime = CryptoRuntime::new(backend);
    let signer = derive_public_key(&runtime, locator);
    let signer_text = bs58::encode(signer).into_string();

    fund_address(&cli, &rpc, &signer_text, "10");
    fund_address(&cli, &rpc, RECIPIENT, "1");
    let blockhash_text = latest_blockhash(&rpc);
    let recipient = decode_base58::<32>(RECIPIENT);
    let blockhash = decode_base58::<32>(&blockhash_text);
    let message = encode_system_transfer(signer, recipient, blockhash, 1).expect("message fits");

    let request = Request::SignSystemTransfer {
        key: target,
        message,
    };
    let review = Solana::prepare_review(&request).expect("device parses system transfer");
    let mut execution = Solana::prepare_execution(&review, context).expect("approved execution");

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

    println!("solana HD e2e: {sent_signature} from {signer_text}");
}

fn derive_public_key(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    locator: hardware_wallet_core::KeyLocator,
) -> [u8; 32] {
    let output = runtime
        .execute(
            CryptoOperation::DerivePublicKey {
                key: locator,
                format: PublicKeyFormat::Raw,
            },
            None,
        )
        .expect("derive Solana public key");
    let CryptoOutput::PublicKey { bytes, .. } = output else {
        panic!("derive must return public key")
    };
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(bytes.as_slice());
    public_key
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
        .expect("HD-derived crypto runtime executes approved operation")
}

fn account_descriptor(wallet: WalletContextId) -> AccountDescriptor {
    AccountDescriptor {
        id: AccountId(0),
        wallet,
        kind: AccountKind::Hd,
        root: path(&[(44, true), (501, true), (0, true)]),
    }
}

fn key_target() -> KeyTarget {
    KeyTarget {
        account: AccountId(0),
        path: path(&[(0, true)]),
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

fn fund_address(cli: &str, rpc: &str, address: &str, amount: &str) {
    let output = Command::new(cli)
        .args(["airdrop", amount, address, "--url", rpc])
        .output()
        .expect("solana CLI must run");
    assert!(
        output.status.success(),
        "airdrop to {address} failed: {}",
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

fn unlocked_context(wallet: WalletContextId) -> hardware_wallet_core::ExecutionContext {
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
            wallet,
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

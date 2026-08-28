use std::{env, process::Command, thread, time::Duration};

use hardware_wallet_chain_api::{
    BoundedBytes, ChainExecution, ChainModule, CryptoOperation, CryptoOutput, ExecutionStep,
    HashAlgorithm, PublicKeyFormat, SignatureScheme,
};
use hardware_wallet_chain_solana::{
    Solana, Request, Response, encode_system_transfer,
};
use hardware_wallet_core::{
    AccountId, AuthId, Event, HostId, HostTrust, KeyPurpose, KeyTarget, PassphraseMode, SessionId,
    SetupId, State, WalletContextId, update,
};

const RECIPIENT: &str = "GcQfK48DV9BzDuDeCyV2sShbAAY4vqmK8JSj1NBrwoVZ";

fn main() {
    let rpc = env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL from chain-sandbox");
    let signer_text = env::var("SOLANA_TEST_PUBKEY").expect("SOLANA_TEST_PUBKEY from chain-sandbox");
    let keypair = env::var("SOLANA_TEST_KEYPAIR").expect("SOLANA_TEST_KEYPAIR from chain-sandbox");
    let cli = env::var("SOLANA_CLI").expect("SOLANA_CLI from chain-sandbox");

    fund_recipient(&cli, &rpc);
    let blockhash_text = latest_blockhash(&rpc);
    let signer = decode_base58::<32>(&signer_text);
    let recipient = decode_base58::<32>(RECIPIENT);
    let blockhash = decode_base58::<32>(&blockhash_text);
    let message = encode_system_transfer(signer, recipient, blockhash, 1).expect("message fits");

    let request = Request::SignSystemTransfer {
        key: KeyTarget {
            account: AccountId(0),
            path: hardware_wallet_core::DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        },
        message: message.clone(),
    };
    let review = Solana::prepare_review(&request).expect("device parses system transfer");
    let mut execution = Solana::prepare_execution(&review, unlocked_context()).expect("execution");

    let derive = execution.next(None).expect("derive step");
    assert!(matches!(
        derive,
        ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
            format: PublicKeyFormat::Raw,
            ..
        })
    ));

    let public_key = CryptoOutput::PublicKey {
        format: PublicKeyFormat::Raw,
        bytes: BoundedBytes::from_slice(&signer).expect("pubkey fits"),
    };
    let signing = execution
        .next(Some(&public_key))
        .expect("matching signer permits signing");
    let ExecutionStep::Crypto(CryptoOperation::Sign {
        scheme,
        prehash,
        payload,
        ..
    }) = signing
    else {
        panic!("transfer must request Ed25519 signing after key validation")
    };
    assert_eq!(scheme, SignatureScheme::Ed25519);
    assert_eq!(prehash, HashAlgorithm::None);
    assert_eq!(execution.payload(payload), Some(message.as_slice()));

    let reference_signature = reference_signature(
        &cli,
        &rpc,
        &keypair,
        &signer_text,
        &blockhash_text,
    );
    let signature_bytes = decode_base58::<64>(&reference_signature);
    let crypto_signature = CryptoOutput::Signature {
        scheme: SignatureScheme::Ed25519,
        bytes: BoundedBytes::from_slice(&signature_bytes).expect("signature fits"),
        recovery_id: None,
    };
    let completed = execution
        .next(Some(&crypto_signature))
        .expect("signature finalizes transaction");
    let ExecutionStep::Complete(Response::SignedTransaction(transaction)) = completed else {
        panic!("transfer must complete with signed transaction")
    };

    let encoded = encode_base64(transaction.as_slice());
    let send = [
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"sendTransaction\",\"params\":[\"",
        &encoded,
        "\",{\"encoding\":\"base64\",\"preflightCommitment\":\"confirmed\"}]}",
    ]
    .concat();
    let sent_signature = result_string(&rpc_call(&rpc, &send));
    assert_eq!(sent_signature, reference_signature);
    wait_for_confirmation(&rpc, &sent_signature);

    println!("solana e2e: {sent_signature}");
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

fn reference_signature(
    cli: &str,
    rpc: &str,
    keypair: &str,
    signer: &str,
    blockhash: &str,
) -> String {
    let output = Command::new(cli)
        .args([
            "transfer",
            RECIPIENT,
            "0.000000001",
            "--allow-unfunded-recipient",
            "--from",
            signer,
            "--fee-payer",
            keypair,
            "--blockhash",
            blockhash,
            "--sign-only",
            "--keypair",
            keypair,
            "--url",
            rpc,
        ])
        .output()
        .expect("solana transfer --sign-only must run");
    assert!(
        output.status.success(),
        "reference signing failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("CLI output is UTF-8");
    let prefix = format!("{signer}=");
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("signature not found in CLI output: {stdout}"))
        .to_owned()
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
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut output = [0_u8; N];
    for character in value.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .unwrap_or_else(|| panic!("invalid base58 character"));
        let mut carry = digit as u32;
        for byte in output.iter_mut().rev() {
            let accumulator = u32::from(*byte) * 58 + carry;
            *byte = (accumulator & 0xff) as u8;
            carry = accumulator >> 8;
        }
        assert_eq!(carry, 0, "base58 value exceeds fixed output size");
    }
    output
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

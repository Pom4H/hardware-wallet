use super::*;

#[test]
fn derivation_path_is_fixed_capacity_and_ordered() {
    let mut path = DerivationPath::new();
    let first = ChildNumber::new(44, true).unwrap();
    let second = ChildNumber::new(60, true).unwrap();
    let third = ChildNumber::new(0, false).unwrap();

    path.push(first).unwrap();
    path.push(second).unwrap();
    path.push(third).unwrap();

    assert_eq!(path.depth(), 3);
    assert_eq!(path.as_slice(), &[first, second, third]);
}

#[test]
fn derivation_path_rejects_invalid_index_and_excess_depth() {
    assert_eq!(
        ChildNumber::new(ChildNumber::MAX_INDEX + 1, false),
        Err(DerivationError::IndexOutOfRange)
    );

    let mut path = DerivationPath::new();
    let child = ChildNumber::new(0, false).unwrap();
    for _ in 0..MAX_DERIVATION_DEPTH {
        path.push(child).unwrap();
    }
    assert_eq!(path.push(child), Err(DerivationError::TooDeep));
}

#[test]
fn locked_state_cannot_bind_a_key() {
    let state = provisioned_state(PassphraseMode::Disabled);
    assert_eq!(state.execution_context(), None);
}

#[test]
fn execution_context_binds_key_to_authorized_wallet() {
    let wallet = WalletContextId(42);
    let state = unlocked_state_with_wallet(HostTrust::Trusted, wallet);
    let context = state.execution_context().unwrap();
    let target = KeyTarget {
        account: AccountId(3),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    };

    let key = context.bind_key(target);
    assert_eq!(key.wallet(), wallet);
    assert_eq!(key.target(), target);
}

#[test]
fn crypto_operations_make_secret_use_explicit() {
    let state = unlocked_state_with_wallet(HostTrust::Trusted, WalletContextId(7));
    let context = state.execution_context().unwrap();
    let key = context.bind_key(KeyTarget {
        account: AccountId(3),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    });

    let public = CryptoOperation::DerivePublicKey {
        key,
        format: PublicKeyFormat::Compressed,
    };
    let digest = CryptoOperation::Hash {
        algorithm: HashAlgorithm::Hash160,
        payload: PayloadId(10),
    };
    let signing = CryptoOperation::Sign {
        key,
        scheme: SignatureScheme::Ecdsa {
            curve: Curve::Secp256k1,
            recoverable: true,
        },
        prehash: HashAlgorithm::Keccak256,
        payload: PayloadId(11),
    };

    assert!(!public.uses_private_key());
    assert!(!digest.uses_private_key());
    assert!(signing.uses_private_key());
    assert_eq!(public.key(), Some(key));
    assert_eq!(digest.key(), None);
    assert_eq!(signing.key(), Some(key));
}

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
fn crypto_operations_make_secret_use_explicit() {
    let key = KeyLocator {
        wallet: WalletContextId(7),
        account: AccountId(3),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    };

    let public = CryptoOperation::DerivePublicKey {
        key,
        format: PublicKeyFormat::Compressed,
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
    assert!(signing.uses_private_key());
    assert_eq!(signing.key(), key);
}

use super::*;

#[test]
fn reboot_restores_wallet_locked_and_drops_transient_session() {
    let state = unlocked_state_with_wallet(HostTrust::Trusted, WalletContextId(77));
    let snapshot = state.persistent_snapshot().expect("provisioned wallet snapshot");
    let restored = State::restore(snapshot);

    assert_eq!(restored.wallet_metadata(), state.wallet_metadata());
    assert!(matches!(restored.auth(), AuthState::Locked { .. }));
    assert_eq!(restored.flow(), FlowState::Idle);
    assert!(!restored.is_unlocked());
}

#[test]
fn provisioning_and_wiping_are_not_snapshotable() {
    let setup = SetupId(10);
    let provisioning = update(
        State::default(),
        Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Disabled,
        },
    )
    .state;
    assert_eq!(provisioning.persistent_snapshot(), None);

    let wiping = update(provisioned_state(PassphraseMode::Disabled), Event::TamperDetected).state;
    assert_eq!(wiping.lifecycle(), Lifecycle::Wiping);
    assert_eq!(wiping.persistent_snapshot(), None);
}

#[test]
fn policy_survives_reboot() {
    let policy = SecurityPolicy {
        blind_signing: BlindSigningPolicy::Allow,
        ..SecurityPolicy::default()
    };
    let empty = State::new(policy);
    let snapshot = empty.persistent_snapshot().expect("empty snapshot");
    assert_eq!(State::restore(snapshot).policy(), policy);
}

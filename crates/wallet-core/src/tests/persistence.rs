use super::*;

#[test]
fn reboot_restores_wallet_locked_and_drops_transient_session() {
    let state = unlocked_state_with_wallet(HostTrust::Trusted, WalletContextId(77));
    let snapshot = state
        .persistent_snapshot()
        .expect("provisioned wallet snapshot");
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

    let wiping = update(
        provisioned_state(PassphraseMode::Disabled),
        Event::TamperDetected,
    )
    .state;
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

#[test]
fn reboot_discards_confirmed_but_unpersisted_setting_change() {
    let id = SettingsId(40);
    let change = SettingChange::Security(SecuritySetting::BlindSigning(BlindSigningPolicy::Allow));
    let state = unlocked_state(HostTrust::Trusted);
    let snapshot = state
        .persistent_snapshot()
        .expect("provisioned wallet snapshot");

    let state = update(
        state,
        Event::SettingChangeRequested {
            id,
            host: HostId(7),
            change,
        },
    )
    .state;
    let state = update(state, Event::SettingChangeConfirmed(id)).state;
    assert_eq!(state.policy().blind_signing, BlindSigningPolicy::Deny);

    let restored = State::restore(snapshot);
    let stale = update(restored, Event::SettingChangePersisted(id));
    assert_eq!(stale.effect, Effect::Reject(RejectReason::InvalidState));
    assert_eq!(stale.state.policy().blind_signing, BlindSigningPolicy::Deny);
}

#[test]
fn reboot_discards_inflight_operation_and_its_completion_callback() {
    let operation = OperationId(41);
    let state = unlocked_state(HostTrust::Trusted);
    let snapshot = state
        .persistent_snapshot()
        .expect("provisioned wallet snapshot");
    let state = update(
        state,
        Event::OperationRequested {
            id: operation,
            host: HostId(7),
        },
    )
    .state;
    assert!(matches!(state.flow(), FlowState::Operation(_)));

    let restored = State::restore(snapshot);
    let stale = update(restored, Event::OperationCompleted(operation));
    assert_eq!(stale.effect, Effect::Reject(RejectReason::InvalidState));
    assert_eq!(stale.state.flow(), FlowState::Idle);
}

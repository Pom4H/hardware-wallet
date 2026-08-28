use super::*;

#[test]
fn session_and_operation_share_same_wallet_context() {
    let wallet = WalletContextId(42);
    let state = unlocked_state_with_wallet(HostTrust::Trusted, wallet);

    assert!(matches!(
        state.auth(),
        AuthState::Unlocked(Session {
            wallet: active_wallet,
            ..
        }) if active_wallet == wallet
    ));

    let state = update(
        state,
        Event::OperationRequested {
            id: OperationId(43),
            host: HostId(7),
        },
    )
    .state;
    assert!(matches!(
        state.flow(),
        FlowState::Operation(PendingOperation {
            wallet: operation_wallet,
            ..
        }) if operation_wallet == wallet
    ));
}

#[test]
fn blind_signing_changes_only_after_confirmed_persistence() {
    let id = SettingsId(100);
    let change = SettingChange::Security(SecuritySetting::BlindSigning(
        BlindSigningPolicy::Allow,
    ));
    let state = unlocked_state(HostTrust::Trusted);
    assert_eq!(state.policy().blind_signing, BlindSigningPolicy::Deny);

    let transition = update(
        state,
        Event::SettingChangeRequested {
            id,
            host: HostId(7),
            change,
        },
    );
    assert_eq!(
        transition.effect,
        Effect::RenderSettingChange { id, change }
    );
    assert_eq!(
        transition.state.policy().blind_signing,
        BlindSigningPolicy::Deny
    );

    let transition = update(transition.state, Event::SettingChangeConfirmed(id));
    assert_eq!(
        transition.effect,
        Effect::PersistSettingChange { id, change }
    );
    assert_eq!(
        transition.state.policy().blind_signing,
        BlindSigningPolicy::Deny
    );

    let transition = update(transition.state, Event::SettingChangePersisted(id));
    assert_eq!(
        transition.state.policy().blind_signing,
        BlindSigningPolicy::Allow
    );
    assert_eq!(transition.effect, Effect::SettingChangeComplete(id));
}

#[test]
fn rejected_setting_change_has_no_effect() {
    let id = SettingsId(101);
    let change = SettingChange::Security(SecuritySetting::SigningHosts(
        SigningHostPolicy::TrustedOnly,
    ));
    let state = unlocked_state(HostTrust::Trusted);

    let state = update(
        state,
        Event::SettingChangeRequested {
            id,
            host: HostId(7),
            change,
        },
    )
    .state;
    let transition = update(state, Event::SettingChangeRejected(id));

    assert_eq!(transition.state.flow(), FlowState::Idle);
    assert_eq!(
        transition.state.policy().signing_hosts,
        SigningHostPolicy::AnySessionHost
    );
    assert_eq!(transition.effect, Effect::SettingChangeRejected(id));
}

#[test]
fn passphrase_setting_updates_metadata_only_after_persistence() {
    let id = SettingsId(102);
    let change = SettingChange::Passphrase(PassphraseMode::Required);
    let state = unlocked_state(HostTrust::Trusted);
    assert_eq!(
        state.wallet_metadata().map(|metadata| metadata.passphrase),
        Some(PassphraseMode::Disabled)
    );

    let state = update(
        state,
        Event::SettingChangeRequested {
            id,
            host: HostId(7),
            change,
        },
    )
    .state;
    let transition = update(state, Event::SettingChangeConfirmed(id));
    assert_eq!(
        transition
            .state
            .wallet_metadata()
            .map(|metadata| metadata.passphrase),
        Some(PassphraseMode::Disabled)
    );

    let transition = update(transition.state, Event::SettingChangePersisted(id));
    assert_eq!(
        transition
            .state
            .wallet_metadata()
            .map(|metadata| metadata.passphrase),
        Some(PassphraseMode::Required)
    );
}

#[test]
fn revoking_active_host_downgrades_current_session_trust() {
    let id = SettingsId(103);
    let host = HostId(7);
    let change = SettingChange::RevokeHost(host);
    let state = unlocked_state(HostTrust::Trusted);

    let state = update(
        state,
        Event::SettingChangeRequested { id, host, change },
    )
    .state;
    let state = update(state, Event::SettingChangeConfirmed(id)).state;
    let transition = update(state, Event::SettingChangePersisted(id));

    assert!(matches!(
        transition.state.auth(),
        AuthState::Unlocked(Session {
            trust: HostTrust::Untrusted,
            ..
        })
    ));
}

#[test]
fn another_host_cannot_change_wallet_settings() {
    let state = unlocked_state(HostTrust::Trusted);
    let transition = update(
        state,
        Event::SettingChangeRequested {
            id: SettingsId(104),
            host: HostId(999),
            change: SettingChange::Security(SecuritySetting::BlindSigning(
                BlindSigningPolicy::Allow,
            )),
        },
    );

    assert_eq!(transition.effect, Effect::Reject(RejectReason::WrongHost));
    assert_eq!(
        transition.state.policy().blind_signing,
        BlindSigningPolicy::Deny
    );
}

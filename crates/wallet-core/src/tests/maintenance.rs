use super::*;

#[test]
fn factory_reset_requires_confirmation_then_returns_to_empty() {
    let host = HostId(7);
    let id = MaintenanceId(50);
    let state = unlocked_state(HostTrust::Trusted);

    let transition = update(state, Event::FactoryResetRequested { id, host });
    assert_eq!(transition.effect, Effect::RenderFactoryResetWarning(id));

    let transition = update(transition.state, Event::FactoryResetConfirmed(id));
    assert_eq!(transition.effect, Effect::WipeWallet);
    assert_eq!(transition.state.lifecycle(), Lifecycle::Wiping);

    let transition = update(transition.state, Event::WipeCompleted);
    assert_eq!(transition.state.lifecycle(), Lifecycle::Empty);
    assert_eq!(transition.effect, Effect::WalletWiped);
}

#[test]
fn backup_check_reports_invalid_without_destroying_wallet() {
    let host = HostId(7);
    let id = MaintenanceId(51);
    let state = unlocked_state(HostTrust::Trusted);

    let transition = update(state, Event::BackupCheckRequested { id, host });
    assert_eq!(transition.effect, Effect::VerifyBackup(id));

    let transition = update(
        transition.state,
        Event::BackupCheckCompleted { id, valid: false },
    );
    assert!(matches!(transition.state.auth(), AuthState::Unlocked(_)));
    assert_eq!(transition.state.flow(), FlowState::Idle);
    assert_eq!(transition.effect, Effect::ReportBackupInvalid(id));
}

#[test]
fn backup_check_marks_recovered_wallet_verified() {
    let setup = SetupId(70);
    let host = HostId(7);
    let auth = AuthId(71);
    let id = MaintenanceId(72);
    let mut state = State::default();

    state = update(
        state,
        Event::StartRecovery {
            id: setup,
            format: RecoveryFormat::Shamir,
            passphrase: PassphraseMode::Disabled,
        },
    )
    .state;
    state = update(state, Event::RecoveryMaterialCaptured(setup)).state;
    state = update(state, Event::KeyMaterialReady(setup)).state;
    state = update(state, Event::PinConfigured(setup)).state;
    state = update(state, Event::ProvisioningPersisted(setup)).state;
    assert_eq!(
        state.wallet_metadata().map(|metadata| metadata.backup),
        Some(BackupStatus::RecoverySource)
    );

    state = update(
        state,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Trusted,
        },
    )
    .state;
    state = update(state, Event::PinVerified(auth)).state;
    state = update(
        state,
        Event::SessionOpened {
            auth,
            session: SessionId(73),
        },
    )
    .state;

    state = update(state, Event::BackupCheckRequested { id, host }).state;
    let transition = update(state, Event::BackupCheckCompleted { id, valid: true });

    assert_eq!(
        transition
            .state
            .wallet_metadata()
            .map(|metadata| metadata.backup),
        Some(BackupStatus::Verified)
    );
    assert_eq!(transition.effect, Effect::MaintenanceComplete(id));
}

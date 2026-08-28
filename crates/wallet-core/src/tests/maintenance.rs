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

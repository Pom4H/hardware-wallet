mod auth;
mod common;
mod maintenance;
mod operation;
mod provisioning;
mod settings;

use crate::{Event, State, Transition};

#[must_use]
pub fn update(state: State, event: Event) -> Transition {
    match event {
        Event::StartCreate { id, passphrase } => provisioning::start_create(state, id, passphrase),
        Event::StartRecovery {
            id,
            format,
            passphrase,
        } => provisioning::start_recovery(state, id, format, passphrase),
        Event::RecoveryMaterialCaptured(id) => provisioning::recovery_material_captured(state, id),
        Event::KeyMaterialReady(id) => provisioning::key_material_ready(state, id),
        Event::BackupShown(id) => provisioning::backup_shown(state, id),
        Event::BackupVerified(id) => provisioning::backup_verified(state, id),
        Event::PinConfigured(id) => provisioning::pin_configured(state, id),
        Event::ProvisioningPersisted(id) => provisioning::provisioning_persisted(state, id),

        Event::UnlockRequested { id, host, trust } => {
            auth::unlock_requested(state, id, host, trust)
        }
        Event::PinVerified(id) => auth::pin_verified(state, id),
        Event::PinRejected {
            id,
            failed_attempts,
        } => auth::pin_rejected(state, id, failed_attempts),
        Event::PassphraseProvided(id) => auth::passphrase_provided(state, id),
        Event::PassphraseSkipped(id) => auth::passphrase_skipped(state, id),
        Event::SessionOpened {
            auth,
            session,
            wallet,
        } => auth::session_opened(state, auth, session, wallet),
        Event::LockRequested => auth::lock(state),
        Event::SessionExpired(session) => auth::session_expired(state, session),
        Event::HostDisconnected(host) => auth::host_disconnected(state, host),

        Event::PairingRequested { id, host } => auth::pairing_requested(state, id, host),
        Event::PairingConfirmed(id) => auth::pairing_confirmed(state, id),
        Event::PairingRejected(id) => auth::pairing_rejected(state, id),
        Event::TrustedHostPersisted(id) => auth::trusted_host_persisted(state, id),

        Event::OperationRequested { id, host } => operation::operation_requested(state, id, host),
        Event::ReviewPrepared { id, plan } => operation::review_prepared(state, id, plan),
        Event::ReviewDisplayed(id) => operation::review_displayed(state, id),
        Event::OperationConfirmed(id) => operation::operation_confirmed(state, id),
        Event::OperationRejected(id) => operation::operation_rejected(state, id),
        Event::OperationCompleted(id) => operation::operation_completed(state, id),
        Event::OperationFailed(id) => operation::operation_failed(state, id),
        Event::OperationCancelled(id) => operation::operation_cancelled(state, id),

        Event::SettingChangeRequested { id, host, change } => {
            settings::setting_change_requested(state, id, host, change)
        }
        Event::SettingChangeConfirmed(id) => settings::setting_change_confirmed(state, id),
        Event::SettingChangeRejected(id) => settings::setting_change_rejected(state, id),
        Event::SettingChangePersisted(id) => settings::setting_change_persisted(state, id),

        Event::ChangePinRequested { id, host } => {
            maintenance::change_pin_requested(state, id, host)
        }
        Event::PinChanged(id) => maintenance::pin_changed(state, id),
        Event::BackupCheckRequested { id, host } => {
            maintenance::backup_check_requested(state, id, host)
        }
        Event::BackupCheckCompleted { id, valid } => {
            maintenance::backup_check_completed(state, id, valid)
        }
        Event::FactoryResetRequested { id, host } => {
            maintenance::factory_reset_requested(state, id, host)
        }
        Event::FactoryResetConfirmed(id) => maintenance::factory_reset_confirmed(state, id),
        Event::FactoryResetRejected(id) => maintenance::factory_reset_rejected(state, id),
        Event::WipeCompleted => maintenance::wipe_completed(state),

        Event::RuntimeFailure => common::runtime_failure(state),
        Event::TamperDetected => common::tamper_detected(state),
    }
}

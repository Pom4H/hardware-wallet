use crate::{
    AuthState, Effect, FlowState, Lifecycle, PassphraseMode, ProvisioningMode, ProvisioningStage,
    RejectReason, State, Transition,
};

use super::common::reject;

pub(super) fn start_create(
    state: State,
    id: crate::SetupId,
    passphrase: PassphraseMode,
) -> Transition {
    if state.lifecycle() != Lifecycle::Empty {
        return reject(state, RejectReason::AlreadyProvisioned);
    }

    let lifecycle = Lifecycle::Provisioning {
        id,
        mode: ProvisioningMode::Create,
        passphrase,
        stage: ProvisioningStage::CreatingKeyMaterial,
    };
    Transition::new(
        state.with_lifecycle(lifecycle),
        Effect::GenerateKeyMaterial(id),
    )
}

pub(super) fn start_recovery(
    state: State,
    id: crate::SetupId,
    format: crate::RecoveryFormat,
    passphrase: PassphraseMode,
) -> Transition {
    if state.lifecycle() != Lifecycle::Empty {
        return reject(state, RejectReason::AlreadyProvisioned);
    }

    let lifecycle = Lifecycle::Provisioning {
        id,
        mode: ProvisioningMode::Recover(format),
        passphrase,
        stage: ProvisioningStage::CapturingRecoveryMaterial,
    };
    Transition::new(
        state.with_lifecycle(lifecycle),
        Effect::CaptureRecoveryMaterial { id, format },
    )
}

pub(super) fn recovery_material_captured(state: State, actual: crate::SetupId) -> Transition {
    let Lifecycle::Provisioning {
        id,
        mode,
        passphrase,
        stage: ProvisioningStage::CapturingRecoveryMaterial,
    } = state.lifecycle()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if !matches!(mode, ProvisioningMode::Recover(_)) {
        return reject(state, RejectReason::InvalidState);
    }

    Transition::new(
        state.with_lifecycle(Lifecycle::Provisioning {
            id,
            mode,
            passphrase,
            stage: ProvisioningStage::DerivingRecoveredKeyMaterial,
        }),
        Effect::DeriveRecoveredKeyMaterial(id),
    )
}

pub(super) fn key_material_ready(state: State, actual: crate::SetupId) -> Transition {
    let Lifecycle::Provisioning {
        id,
        mode,
        passphrase,
        stage,
    } = state.lifecycle()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    match (mode, stage) {
        (ProvisioningMode::Create, ProvisioningStage::CreatingKeyMaterial) => Transition::new(
            state.with_lifecycle(Lifecycle::Provisioning {
                id,
                mode,
                passphrase,
                stage: ProvisioningStage::ShowingBackup,
            }),
            Effect::ShowBackup(id),
        ),
        (
            ProvisioningMode::Recover(_),
            ProvisioningStage::DerivingRecoveredKeyMaterial,
        ) => Transition::new(
            state.with_lifecycle(Lifecycle::Provisioning {
                id,
                mode,
                passphrase,
                stage: ProvisioningStage::ConfiguringPin,
            }),
            Effect::ConfigurePin(id),
        ),
        _ => reject(state, RejectReason::InvalidState),
    }
}

pub(super) fn backup_shown(state: State, actual: crate::SetupId) -> Transition {
    advance_provisioning(
        state,
        actual,
        ProvisioningStage::ShowingBackup,
        ProvisioningStage::VerifyingBackup,
        Effect::ChallengeBackup(actual),
    )
}

pub(super) fn backup_verified(state: State, actual: crate::SetupId) -> Transition {
    advance_provisioning(
        state,
        actual,
        ProvisioningStage::VerifyingBackup,
        ProvisioningStage::ConfiguringPin,
        Effect::ConfigurePin(actual),
    )
}

pub(super) fn pin_configured(state: State, actual: crate::SetupId) -> Transition {
    advance_provisioning(
        state,
        actual,
        ProvisioningStage::ConfiguringPin,
        ProvisioningStage::Persisting,
        Effect::PersistProvisioning(actual),
    )
}

pub(super) fn provisioning_persisted(state: State, actual: crate::SetupId) -> Transition {
    let Lifecycle::Provisioning {
        id,
        passphrase,
        stage: ProvisioningStage::Persisting,
        ..
    } = state.lifecycle()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let next = state
        .with_lifecycle(Lifecycle::Provisioned { passphrase })
        .with_auth(AuthState::Locked { failed_attempts: 0 })
        .with_flow(FlowState::Idle);
    Transition::new(next, Effect::ProvisioningComplete(id))
}

fn advance_provisioning(
    state: State,
    actual: crate::SetupId,
    expected_stage: ProvisioningStage,
    next_stage: ProvisioningStage,
    effect: Effect,
) -> Transition {
    let Lifecycle::Provisioning {
        id,
        mode,
        passphrase,
        stage,
    } = state.lifecycle()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if stage != expected_stage {
        return reject(state, RejectReason::InvalidState);
    }

    Transition::new(
        state.with_lifecycle(Lifecycle::Provisioning {
            id,
            mode,
            passphrase,
            stage: next_stage,
        }),
        effect,
    )
}

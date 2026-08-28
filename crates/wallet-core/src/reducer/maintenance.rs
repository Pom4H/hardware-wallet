use crate::{
    AuthState, Effect, FlowState, Lifecycle, MaintenanceKind, RejectReason, State, Transition,
};

use super::common::{reject, unlocked_session};

pub(super) fn change_pin_requested(
    state: State,
    id: crate::MaintenanceId,
    host: crate::HostId,
) -> Transition {
    maintenance_requested(
        state,
        id,
        host,
        MaintenanceKind::ChangePin,
        Effect::ChangePin(id),
    )
}

pub(super) fn pin_changed(state: State, actual: crate::MaintenanceId) -> Transition {
    maintenance_completed(state, actual, MaintenanceKind::ChangePin)
}

pub(super) fn backup_check_requested(
    state: State,
    id: crate::MaintenanceId,
    host: crate::HostId,
) -> Transition {
    maintenance_requested(
        state,
        id,
        host,
        MaintenanceKind::VerifyBackup,
        Effect::VerifyBackup(id),
    )
}

pub(super) fn backup_check_completed(
    state: State,
    actual: crate::MaintenanceId,
    valid: bool,
) -> Transition {
    let FlowState::Maintenance {
        id,
        kind: MaintenanceKind::VerifyBackup,
    } = state.flow()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let state = state.with_flow(FlowState::Idle);
    if valid {
        Transition::new(state, Effect::MaintenanceComplete(id))
    } else {
        Transition::new(state, Effect::ReportBackupInvalid(id))
    }
}

pub(super) fn factory_reset_requested(
    state: State,
    id: crate::MaintenanceId,
    host: crate::HostId,
) -> Transition {
    let Some(session) = unlocked_session(state) else {
        return reject(state, RejectReason::Locked);
    };
    if session.host != host {
        return reject(state, RejectReason::WrongHost);
    }
    if state.flow() != FlowState::Idle {
        return reject(state, RejectReason::Busy);
    }

    Transition::new(
        state.with_flow(FlowState::FactoryReset { id, host }),
        Effect::RenderFactoryResetWarning(id),
    )
}

pub(super) fn factory_reset_confirmed(state: State, actual: crate::MaintenanceId) -> Transition {
    let FlowState::FactoryReset { id, .. } = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let next = state
        .with_lifecycle(Lifecycle::Wiping)
        .with_auth(AuthState::Unavailable)
        .with_flow(FlowState::Idle);
    Transition::new(next, Effect::WipeWallet)
}

pub(super) fn factory_reset_rejected(state: State, actual: crate::MaintenanceId) -> Transition {
    let FlowState::FactoryReset { id, .. } = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    Transition::new(
        state.with_flow(FlowState::Idle),
        Effect::FactoryResetRejected(id),
    )
}

pub(super) fn wipe_completed(state: State) -> Transition {
    if state.lifecycle() != Lifecycle::Wiping {
        return reject(state, RejectReason::InvalidState);
    }
    let next = state
        .with_lifecycle(Lifecycle::Empty)
        .with_auth(AuthState::Unavailable)
        .with_flow(FlowState::Idle);
    Transition::new(next, Effect::WalletWiped)
}

fn maintenance_requested(
    state: State,
    id: crate::MaintenanceId,
    host: crate::HostId,
    kind: MaintenanceKind,
    effect: Effect,
) -> Transition {
    let Some(session) = unlocked_session(state) else {
        return reject(state, RejectReason::Locked);
    };
    if session.host != host {
        return reject(state, RejectReason::WrongHost);
    }
    if state.flow() != FlowState::Idle {
        return reject(state, RejectReason::Busy);
    }

    Transition::new(
        state.with_flow(FlowState::Maintenance { id, kind }),
        effect,
    )
}

fn maintenance_completed(
    state: State,
    actual: crate::MaintenanceId,
    expected_kind: MaintenanceKind,
) -> Transition {
    let FlowState::Maintenance { id, kind } = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if kind != expected_kind {
        return reject(state, RejectReason::InvalidState);
    }
    Transition::new(
        state.with_flow(FlowState::Idle),
        Effect::MaintenanceComplete(id),
    )
}

use crate::{
    BlindSigningPolicy, Effect, FlowState, HostTrust, Interaction, OperationKind, OperationStage,
    PendingOperation, RejectReason, ReviewAssurance, ReviewPlan, SigningHostPolicy, State,
    Transition,
};

use super::common::{reject, reject_operation, unlocked_session};

pub(super) fn operation_requested(
    state: State,
    id: crate::OperationId,
    host: crate::HostId,
) -> Transition {
    let Some(session) = unlocked_session(state) else {
        return reject_operation(state, id, RejectReason::Locked);
    };
    if session.host != host {
        return reject_operation(state, id, RejectReason::WrongHost);
    }
    if state.flow() != FlowState::Idle {
        return reject_operation(state, id, RejectReason::Busy);
    }
    let pending = PendingOperation {
        id,
        host,
        wallet: session.wallet,
        kind: None,
        stage: OperationStage::PreparingReview,
    };
    Transition::new(
        state.with_flow(FlowState::Operation(pending)),
        Effect::PrepareOperationReview(id),
    )
}

pub(super) fn review_prepared(
    state: State,
    actual: crate::OperationId,
    mut plan: ReviewPlan,
) -> Transition {
    let FlowState::Operation(mut pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if pending.stage != OperationStage::PreparingReview {
        return reject_operation(state, actual, RejectReason::InvalidState);
    }

    let Some(session) = unlocked_session(state) else {
        return reject_operation(
            state.with_flow(FlowState::Idle),
            actual,
            RejectReason::Locked,
        );
    };
    if session.host != pending.host || session.wallet != pending.wallet {
        return reject_operation(
            state.with_flow(FlowState::Idle),
            actual,
            RejectReason::InvalidState,
        );
    }

    let uses_private_key = plan.uses_private_key || plan.kind.uses_private_key();
    plan.uses_private_key = uses_private_key;

    if plan.assurance == ReviewAssurance::Blind
        && state.policy().blind_signing == BlindSigningPolicy::Deny
    {
        return reject_operation(
            state.with_flow(FlowState::Idle),
            actual,
            RejectReason::BlindSigningDisabled,
        );
    }

    if uses_private_key && state.policy().signing_hosts == SigningHostPolicy::TrustedOnly {
        if session.trust != HostTrust::Trusted {
            return reject_operation(
                state.with_flow(FlowState::Idle),
                actual,
                RejectReason::UntrustedHost,
            );
        }
    }

    pending.kind = Some(plan.kind);
    plan.interaction = strongest_interaction(
        plan.interaction,
        minimum_interaction(plan.kind, uses_private_key),
    );
    if plan.interaction == Interaction::Silent {
        pending.stage = OperationStage::Executing;
        return Transition::new(
            state.with_flow(FlowState::Operation(pending)),
            Effect::ExecuteOperation(actual),
        );
    }

    pending.stage = OperationStage::Displaying { plan };
    Transition::new(
        state.with_flow(FlowState::Operation(pending)),
        Effect::RenderOperationReview(actual),
    )
}

pub(super) fn review_displayed(state: State, actual: crate::OperationId) -> Transition {
    let FlowState::Operation(mut pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    let OperationStage::Displaying { plan } = pending.stage else {
        return reject_operation(state, actual, RejectReason::InvalidState);
    };

    match plan.interaction {
        Interaction::Display => {
            pending.stage = OperationStage::Executing;
            Transition::new(
                state.with_flow(FlowState::Operation(pending)),
                Effect::ExecuteOperation(actual),
            )
        }
        Interaction::Confirm => {
            pending.stage = OperationStage::Reviewing { plan };
            Transition::new(state.with_flow(FlowState::Operation(pending)), Effect::None)
        }
        Interaction::Silent => reject_operation(state, actual, RejectReason::InvalidState),
    }
}

pub(super) fn operation_confirmed(state: State, actual: crate::OperationId) -> Transition {
    let FlowState::Operation(mut pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    let OperationStage::Reviewing { plan } = pending.stage else {
        return reject_operation(state, actual, RejectReason::InvalidState);
    };
    if plan.interaction != Interaction::Confirm {
        return reject_operation(state, actual, RejectReason::InvalidState);
    }

    let Some(session) = unlocked_session(state) else {
        return reject_operation(
            state.with_flow(FlowState::Idle),
            actual,
            RejectReason::Locked,
        );
    };
    if session.host != pending.host || session.wallet != pending.wallet {
        return reject_operation(
            state.with_flow(FlowState::Idle),
            actual,
            RejectReason::InvalidState,
        );
    }

    pending.stage = OperationStage::Executing;
    Transition::new(
        state.with_flow(FlowState::Operation(pending)),
        Effect::ExecuteOperation(actual),
    )
}

pub(super) fn operation_rejected(state: State, actual: crate::OperationId) -> Transition {
    let FlowState::Operation(pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if !matches!(
        pending.stage,
        OperationStage::Displaying { .. } | OperationStage::Reviewing { .. }
    ) {
        return reject_operation(state, actual, RejectReason::InvalidState);
    }

    reject_operation(
        state.with_flow(FlowState::Idle),
        actual,
        RejectReason::UserRejected,
    )
}

pub(super) fn operation_completed(state: State, actual: crate::OperationId) -> Transition {
    operation_finished(state, actual, true)
}

pub(super) fn operation_failed(state: State, actual: crate::OperationId) -> Transition {
    operation_finished(state, actual, false)
}

fn operation_finished(state: State, actual: crate::OperationId, success: bool) -> Transition {
    let FlowState::Operation(pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if pending.stage != OperationStage::Executing {
        return reject_operation(state, actual, RejectReason::InvalidState);
    }

    let state = state.with_flow(FlowState::Idle);
    if success {
        Transition::new(state, Effect::CompleteOperation(actual))
    } else {
        reject_operation(state, actual, RejectReason::ExecutionFailed)
    }
}

pub(super) fn operation_cancelled(state: State, actual: crate::OperationId) -> Transition {
    let FlowState::Operation(pending) = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if pending.id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    Transition::new(
        state.with_flow(FlowState::Idle),
        Effect::AbortOperation(actual),
    )
}

const fn minimum_interaction(kind: OperationKind, uses_private_key: bool) -> Interaction {
    if uses_private_key {
        return Interaction::Confirm;
    }
    match kind {
        OperationKind::ShowAddress | OperationKind::CreateAccount => Interaction::Display,
        OperationKind::ExportPublicKey
        | OperationKind::SignTransaction
        | OperationKind::SignMessage
        | OperationKind::SignTypedData
        | OperationKind::SignArbitraryData => Interaction::Confirm,
        OperationKind::Custom(_) => Interaction::Silent,
    }
}

const fn strongest_interaction(left: Interaction, right: Interaction) -> Interaction {
    match (left, right) {
        (Interaction::Confirm, _) | (_, Interaction::Confirm) => Interaction::Confirm,
        (Interaction::Display, _) | (_, Interaction::Display) => Interaction::Display,
        (Interaction::Silent, Interaction::Silent) => Interaction::Silent,
    }
}

use crate::{
    AuthState, Effect, FlowState, Lifecycle, RejectReason, Session, State, Transition,
};

pub(super) fn runtime_failure(state: State) -> Transition {
    match state.lifecycle() {
        Lifecycle::Provisioned { .. } => super::auth::lock(state),
        Lifecycle::Provisioning { .. } => Transition::new(
            state
                .with_lifecycle(Lifecycle::Empty)
                .with_auth(AuthState::Unavailable)
                .with_flow(FlowState::Idle),
            Effect::ClearSensitiveState,
        ),
        Lifecycle::Empty | Lifecycle::Wiping => Transition::new(state, Effect::None),
    }
}

pub(super) fn tamper_detected(state: State) -> Transition {
    if state.lifecycle() == Lifecycle::Empty {
        return Transition::new(state, Effect::None);
    }
    let next = state
        .with_lifecycle(Lifecycle::Wiping)
        .with_auth(AuthState::Unavailable)
        .with_flow(FlowState::Idle);
    Transition::new(next, Effect::WipeWallet)
}

pub(super) const fn unlocked_session(state: State) -> Option<Session> {
    match state.auth() {
        AuthState::Unlocked(session) => Some(session),
        _ => None,
    }
}

pub(super) const fn failed_attempts(auth: AuthState) -> u8 {
    match auth {
        AuthState::Locked { failed_attempts }
        | AuthState::VerifyingPin {
            failed_attempts, ..
        }
        | AuthState::AwaitingPassphrase {
            failed_attempts, ..
        }
        | AuthState::OpeningSession {
            failed_attempts, ..
        } => failed_attempts,
        AuthState::Unavailable | AuthState::Unlocked(_) => 0,
    }
}

pub(super) const fn reject(state: State, reason: RejectReason) -> Transition {
    Transition::new(state, Effect::Reject(reason))
}

pub(super) const fn reject_operation(
    state: State,
    id: crate::OperationId,
    reason: RejectReason,
) -> Transition {
    Transition::new(state, Effect::RejectOperation { id, reason })
}

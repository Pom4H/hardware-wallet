use crate::{
    AuthState, Effect, FlowState, HostTrust, Lifecycle, PassphraseMode, RejectReason, Session, State,
    Transition,
};

use super::common::{failed_attempts, reject, unlocked_session};

pub(super) fn unlock_requested(
    state: State,
    id: crate::AuthId,
    host: crate::HostId,
    trust: HostTrust,
) -> Transition {
    if !matches!(state.lifecycle(), Lifecycle::Provisioned { .. }) {
        return reject(state, RejectReason::NotProvisioned);
    }
    if state.flow() != FlowState::Idle {
        return reject(state, RejectReason::Busy);
    }
    let AuthState::Locked { failed_attempts } = state.auth() else {
        return reject(state, RejectReason::InvalidState);
    };

    let auth = AuthState::VerifyingPin {
        id,
        host,
        trust,
        failed_attempts,
    };
    Transition::new(state.with_auth(auth), Effect::VerifyPin { id, host })
}

pub(super) fn pin_verified(state: State, actual: crate::AuthId) -> Transition {
    let AuthState::VerifyingPin {
        id,
        host,
        trust,
        failed_attempts,
    } = state.auth()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let passphrase = match state.lifecycle() {
        Lifecycle::Provisioned { passphrase } => passphrase,
        _ => return reject(state, RejectReason::NotProvisioned),
    };

    if passphrase == PassphraseMode::Disabled {
        let auth = AuthState::OpeningSession {
            id,
            host,
            trust,
            failed_attempts,
        };
        Transition::new(state.with_auth(auth), Effect::OpenSession { id, host })
    } else {
        let auth = AuthState::AwaitingPassphrase {
            id,
            host,
            trust,
            failed_attempts,
        };
        Transition::new(state.with_auth(auth), Effect::RequestPassphrase(id))
    }
}

pub(super) fn pin_rejected(state: State, actual: crate::AuthId) -> Transition {
    let AuthState::VerifyingPin {
        id,
        failed_attempts,
        ..
    } = state.auth()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let failed_attempts = failed_attempts.saturating_add(1);
    let policy = state.policy();
    let exhausted = failed_attempts >= policy.max_pin_attempts;
    if exhausted && policy.wipe_on_max_pin_attempts {
        let next = state
            .with_lifecycle(Lifecycle::Wiping)
            .with_auth(AuthState::Unavailable)
            .with_flow(FlowState::Idle);
        return Transition::new(next, Effect::WipeWallet);
    }

    let remaining_attempts = policy.max_pin_attempts.saturating_sub(failed_attempts);
    Transition::new(
        state.with_auth(AuthState::Locked { failed_attempts }),
        Effect::AuthenticationFailed { remaining_attempts },
    )
}

pub(super) fn passphrase_provided(state: State, actual: crate::AuthId) -> Transition {
    let AuthState::AwaitingPassphrase {
        id,
        host,
        trust,
        failed_attempts,
    } = state.auth()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let auth = AuthState::OpeningSession {
        id,
        host,
        trust,
        failed_attempts,
    };
    Transition::new(state.with_auth(auth), Effect::OpenSession { id, host })
}

pub(super) fn passphrase_skipped(state: State, actual: crate::AuthId) -> Transition {
    let AuthState::AwaitingPassphrase {
        id,
        host,
        trust,
        failed_attempts,
    } = state.auth()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    if !matches!(
        state.lifecycle(),
        Lifecycle::Provisioned {
            passphrase: PassphraseMode::Optional
        }
    ) {
        return reject(state, RejectReason::InvalidState);
    }

    let auth = AuthState::OpeningSession {
        id,
        host,
        trust,
        failed_attempts,
    };
    Transition::new(state.with_auth(auth), Effect::OpenSession { id, host })
}

pub(super) fn session_opened(
    state: State,
    actual: crate::AuthId,
    session: crate::SessionId,
) -> Transition {
    let AuthState::OpeningSession {
        id, host, trust, ..
    } = state.auth()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let auth = AuthState::Unlocked(Session {
        id: session,
        host,
        trust,
    });
    Transition::new(state.with_auth(auth), Effect::SessionReady)
}

pub(super) fn lock(state: State) -> Transition {
    if matches!(state.auth(), AuthState::Unavailable | AuthState::Locked { .. }) {
        return Transition::new(state.with_flow(FlowState::Idle), Effect::None);
    }

    let failed_attempts = failed_attempts(state.auth());
    let next = state
        .with_auth(AuthState::Locked { failed_attempts })
        .with_flow(FlowState::Idle);
    Transition::new(next, Effect::ClearSensitiveState)
}

pub(super) fn session_expired(state: State, session: crate::SessionId) -> Transition {
    let AuthState::Unlocked(active) = state.auth() else {
        return reject(state, RejectReason::InvalidState);
    };
    if active.id != session {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    lock(state)
}

pub(super) fn host_disconnected(state: State, host: crate::HostId) -> Transition {
    if !state.policy().lock_on_host_disconnect {
        return Transition::new(state, Effect::None);
    }

    let bound_host = match state.auth() {
        AuthState::Unlocked(session) => Some(session.host),
        AuthState::VerifyingPin { host, .. }
        | AuthState::AwaitingPassphrase { host, .. }
        | AuthState::OpeningSession { host, .. } => Some(host),
        AuthState::Unavailable | AuthState::Locked { .. } => None,
    };

    if bound_host == Some(host) {
        lock(state)
    } else {
        Transition::new(state, Effect::None)
    }
}

pub(super) fn pairing_requested(
    state: State,
    id: crate::PairingId,
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
        state.with_flow(FlowState::Pairing {
            id,
            host,
            persisted: false,
        }),
        Effect::RenderPairing { id, host },
    )
}

pub(super) fn pairing_confirmed(state: State, actual: crate::PairingId) -> Transition {
    let FlowState::Pairing {
        id,
        host,
        persisted: false,
    } = state.flow()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    Transition::new(
        state.with_flow(FlowState::Pairing {
            id,
            host,
            persisted: true,
        }),
        Effect::PersistTrustedHost { id, host },
    )
}

pub(super) fn pairing_rejected(state: State, actual: crate::PairingId) -> Transition {
    let FlowState::Pairing { id, .. } = state.flow() else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    Transition::new(
        state.with_flow(FlowState::Idle),
        Effect::PairingRejected(id),
    )
}

pub(super) fn trusted_host_persisted(state: State, actual: crate::PairingId) -> Transition {
    let FlowState::Pairing {
        id,
        persisted: true,
        ..
    } = state.flow()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }
    Transition::new(
        state.with_flow(FlowState::Idle),
        Effect::PairingComplete(id),
    )
}

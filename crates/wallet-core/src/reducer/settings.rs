use crate::{
    AuthState, Effect, FlowState, HostTrust, Lifecycle, RejectReason, SettingChange, SettingsStage,
    State, Transition,
};

use super::common::{reject, unlocked_session};

pub(super) fn setting_change_requested(
    state: State,
    id: crate::SettingsId,
    host: crate::HostId,
    change: SettingChange,
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
        state.with_flow(FlowState::Settings {
            id,
            host,
            change,
            stage: SettingsStage::Reviewing,
        }),
        Effect::RenderSettingChange { id, change },
    )
}

pub(super) fn setting_change_confirmed(state: State, actual: crate::SettingsId) -> Transition {
    let FlowState::Settings {
        id,
        host,
        change,
        stage: SettingsStage::Reviewing,
    } = state.flow()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let Some(session) = unlocked_session(state) else {
        return reject(state, RejectReason::Locked);
    };
    if session.host != host {
        return reject(state, RejectReason::WrongHost);
    }

    Transition::new(
        state.with_flow(FlowState::Settings {
            id,
            host,
            change,
            stage: SettingsStage::Persisting,
        }),
        Effect::PersistSettingChange { id, change },
    )
}

pub(super) fn setting_change_rejected(state: State, actual: crate::SettingsId) -> Transition {
    let FlowState::Settings {
        id,
        stage: SettingsStage::Reviewing,
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
        Effect::SettingChangeRejected(id),
    )
}

pub(super) fn setting_change_persisted(state: State, actual: crate::SettingsId) -> Transition {
    let FlowState::Settings {
        id,
        change,
        stage: SettingsStage::Persisting,
        ..
    } = state.flow()
    else {
        return reject(state, RejectReason::InvalidState);
    };
    if id != actual {
        return reject(state, RejectReason::CorrelationMismatch);
    }

    let state = state.with_flow(FlowState::Idle);
    let next = match change {
        SettingChange::Security(setting) => state.with_policy(state.policy().apply(setting)),
        SettingChange::Passphrase(passphrase) => {
            let Some(mut metadata) = state.wallet_metadata() else {
                return reject(state, RejectReason::NotProvisioned);
            };
            metadata.passphrase = passphrase;
            state.with_lifecycle(Lifecycle::Provisioned { metadata })
        }
        SettingChange::RevokeHost(host) => downgrade_active_host(state, Some(host)),
        SettingChange::RevokeAllHosts => downgrade_active_host(state, None),
    };

    Transition::new(next, Effect::SettingChangeComplete(id))
}

fn downgrade_active_host(state: State, revoked: Option<crate::HostId>) -> State {
    let AuthState::Unlocked(mut session) = state.auth() else {
        return state;
    };
    if revoked.is_none() || revoked == Some(session.host) {
        session.trust = HostTrust::Untrusted;
        state.with_auth(AuthState::Unlocked(session))
    } else {
        state
    }
}

use super::*;

mod auth;
mod maintenance;
mod operations;
mod provisioning;

fn provisioned_state(passphrase: PassphraseMode) -> State {
    let setup = SetupId(1);
    let mut state = State::default();

    state = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase,
        },
    )
    .state;
    state = update(state, Event::KeyMaterialReady(setup)).state;
    state = update(state, Event::BackupShown(setup)).state;
    state = update(state, Event::BackupVerified(setup)).state;
    state = update(state, Event::PinConfigured(setup)).state;
    update(state, Event::ProvisioningPersisted(setup)).state
}

fn unlocked_state(trust: HostTrust) -> State {
    let host = HostId(7);
    let auth = AuthId(2);
    let session = SessionId(3);
    let mut state = provisioned_state(PassphraseMode::Disabled);

    state = update(
        state,
        Event::UnlockRequested {
            id: auth,
            host,
            trust,
        },
    )
    .state;
    state = update(state, Event::PinVerified(auth)).state;
    update(state, Event::SessionOpened { auth, session }).state
}

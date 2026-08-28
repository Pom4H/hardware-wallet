use super::*;

mod auth;
mod keys;
mod maintenance;
mod operations;
mod provisioning;
mod settings;

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
    unlocked_state_with_wallet(trust, WalletContextId(1))
}

fn unlocked_state_with_wallet(trust: HostTrust, wallet: WalletContextId) -> State {
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
    update(
        state,
        Event::SessionOpened {
            auth,
            session,
            wallet,
        },
    )
    .state
}

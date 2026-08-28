use super::*;

#[test]
fn passphrase_wallet_does_not_open_session_after_pin_only() {
    let mut state = provisioned_state(PassphraseMode::Required);
    let auth = AuthId(12);
    let host = HostId(5);

    state = update(
        state,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Untrusted,
        },
    )
    .state;
    let transition = update(state, Event::PinVerified(auth));

    assert!(matches!(
        transition.state.auth(),
        AuthState::AwaitingPassphrase { .. }
    ));
    assert_eq!(transition.effect, Effect::RequestPassphrase(auth));
}

#[test]
fn optional_passphrase_can_be_skipped_but_required_one_cannot() {
    let host = HostId(7);
    let auth = AuthId(70);
    let mut optional = provisioned_state(PassphraseMode::Optional);
    optional = update(
        optional,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Trusted,
        },
    )
    .state;
    optional = update(optional, Event::PinVerified(auth)).state;
    let skipped = update(optional, Event::PassphraseSkipped(auth));
    assert_eq!(skipped.effect, Effect::OpenSession { id: auth, host });

    let mut required = provisioned_state(PassphraseMode::Required);
    required = update(
        required,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Trusted,
        },
    )
    .state;
    required = update(required, Event::PinVerified(auth)).state;
    let rejected = update(required, Event::PassphraseSkipped(auth));
    assert_eq!(rejected.effect, Effect::Reject(RejectReason::InvalidState));
}

#[test]
fn wrong_pin_counts_attempts_and_eventually_wipes() {
    let mut state = provisioned_state(PassphraseMode::Disabled);
    let host = HostId(1);

    for attempt in 0..10_u32 {
        let auth = AuthId(100 + attempt);
        state = update(
            state,
            Event::UnlockRequested {
                id: auth,
                host,
                trust: HostTrust::Untrusted,
            },
        )
        .state;
        let transition = update(state, Event::PinRejected(auth));
        state = transition.state;

        if attempt < 9 {
            assert!(matches!(state.auth(), AuthState::Locked { .. }));
        } else {
            assert_eq!(state.lifecycle(), Lifecycle::Wiping);
            assert_eq!(transition.effect, Effect::WipeWallet);
        }
    }
}

#[test]
fn disconnect_during_unlock_cancels_authentication() {
    let host = HostId(80);
    let auth = AuthId(81);
    let state = provisioned_state(PassphraseMode::Required);
    let state = update(
        state,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Untrusted,
        },
    )
    .state;
    let state = update(state, Event::PinVerified(auth)).state;
    assert!(matches!(state.auth(), AuthState::AwaitingPassphrase { .. }));

    let transition = update(state, Event::HostDisconnected(host));
    assert!(matches!(transition.state.auth(), AuthState::Locked { .. }));
    assert_eq!(transition.effect, Effect::ClearSensitiveState);
}

#[test]
fn pairing_is_bound_to_current_session_host() {
    let state = unlocked_state(HostTrust::Untrusted);
    let transition = update(
        state,
        Event::PairingRequested {
            id: PairingId(60),
            host: HostId(999),
        },
    );
    assert_eq!(transition.effect, Effect::Reject(RejectReason::WrongHost));
}

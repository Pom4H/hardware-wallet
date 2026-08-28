use super::*;

fn begin_unlock(state: State, auth: AuthId, host: HostId, trust: HostTrust) -> State {
    let transition = update(state, Event::UnlockRequested { id: auth, host });
    assert_eq!(
        transition.effect,
        Effect::ResolveHostTrust { id: auth, host }
    );
    let transition = update(
        transition.state,
        Event::HostTrustResolved { id: auth, trust },
    );
    assert_eq!(transition.effect, Effect::VerifyPin { id: auth, host });
    transition.state
}

#[test]
fn passphrase_wallet_does_not_open_session_after_pin_only() {
    let state = provisioned_state(PassphraseMode::Required);
    let auth = AuthId(12);
    let host = HostId(5);

    let state = begin_unlock(state, auth, host, HostTrust::Untrusted);
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
    let optional = begin_unlock(
        provisioned_state(PassphraseMode::Optional),
        auth,
        host,
        HostTrust::Trusted,
    );
    let optional = update(optional, Event::PinVerified(auth)).state;
    let skipped = update(optional, Event::PassphraseSkipped(auth));
    assert_eq!(skipped.effect, Effect::OpenSession { id: auth, host });

    let required = begin_unlock(
        provisioned_state(PassphraseMode::Required),
        auth,
        host,
        HostTrust::Trusted,
    );
    let required = update(required, Event::PinVerified(auth)).state;
    let rejected = update(required, Event::PassphraseSkipped(auth));
    assert_eq!(rejected.effect, Effect::Reject(RejectReason::InvalidState));
}

#[test]
fn wrong_pin_uses_durable_attempt_count_and_eventually_wipes() {
    let mut state = provisioned_state(PassphraseMode::Disabled);
    let host = HostId(1);

    for attempt in 1..=10_u8 {
        let auth = AuthId(100 + u32::from(attempt));
        state = begin_unlock(state, auth, host, HostTrust::Untrusted);
        let transition = update(
            state,
            Event::PinRejected {
                id: auth,
                failed_attempts: attempt,
            },
        );
        state = transition.state;

        if attempt < 10 {
            assert!(matches!(state.auth(), AuthState::Locked { .. }));
        } else {
            assert_eq!(state.lifecycle(), Lifecycle::Wiping);
            assert_eq!(transition.effect, Effect::WipeWallet);
        }
    }
}

#[test]
fn stale_retry_count_is_rejected() {
    let host = HostId(1);
    let auth1 = AuthId(1);
    let state = begin_unlock(
        provisioned_state(PassphraseMode::Disabled),
        auth1,
        host,
        HostTrust::Untrusted,
    );
    let state = update(
        state,
        Event::PinRejected {
            id: auth1,
            failed_attempts: 4,
        },
    )
    .state;

    let auth2 = AuthId(2);
    let state = begin_unlock(state, auth2, host, HostTrust::Untrusted);
    let transition = update(
        state,
        Event::PinRejected {
            id: auth2,
            failed_attempts: 4,
        },
    );
    assert_eq!(
        transition.effect,
        Effect::Reject(RejectReason::InvalidState)
    );
}

#[test]
fn disconnect_during_unlock_cancels_authentication() {
    let host = HostId(80);
    let auth = AuthId(81);
    let state = begin_unlock(
        provisioned_state(PassphraseMode::Required),
        auth,
        host,
        HostTrust::Untrusted,
    );
    let state = update(state, Event::PinVerified(auth)).state;
    assert!(matches!(state.auth(), AuthState::AwaitingPassphrase { .. }));

    let transition = update(state, Event::HostDisconnected(host));
    assert!(matches!(transition.state.auth(), AuthState::Locked { .. }));
    assert_eq!(transition.effect, Effect::ClearSensitiveState);
}

#[test]
fn host_cannot_supply_its_own_trust_level() {
    let host = HostId(90);
    let auth = AuthId(91);
    let state = provisioned_state(PassphraseMode::Disabled);
    let transition = update(state, Event::UnlockRequested { id: auth, host });

    assert!(matches!(
        transition.state.auth(),
        AuthState::ResolvingHost { .. }
    ));
    assert_eq!(
        transition.effect,
        Effect::ResolveHostTrust { id: auth, host }
    );
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

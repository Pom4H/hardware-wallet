use super::*;

fn request_operation(state: State, operation: OperationId) -> State {
    update(
        state,
        Event::OperationRequested {
            id: operation,
            host: HostId(7),
        },
    )
    .state
}

#[test]
fn operation_is_bound_to_active_wallet_context() {
    let wallet = WalletContextId(42);
    let operation = OperationId(19);
    let state = request_operation(
        unlocked_state_with_wallet(HostTrust::Trusted, wallet),
        operation,
    );

    assert!(matches!(
        state.flow(),
        FlowState::Operation(PendingOperation {
            wallet: pending_wallet,
            ..
        }) if pending_wallet == wallet
    ));
}

#[test]
fn signing_always_requires_physical_confirmation() {
    let operation = OperationId(20);
    let state = request_operation(unlocked_state(HostTrust::Trusted), operation);

    let transition = update(
        state,
        Event::ReviewPrepared {
            id: operation,
            plan: ReviewPlan {
                kind: OperationKind::SignTransaction,
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Silent,
            },
        },
    );
    assert_eq!(transition.effect, Effect::RenderOperationReview(operation));

    let transition = update(transition.state, Event::ReviewDisplayed(operation));
    assert_eq!(transition.effect, Effect::None);
    assert!(matches!(
        transition.state.flow(),
        FlowState::Operation(PendingOperation {
            stage: OperationStage::Reviewing { .. },
            ..
        })
    ));

    let transition = update(transition.state, Event::OperationConfirmed(operation));
    assert_eq!(transition.effect, Effect::ExecuteOperation(operation));
}

#[test]
fn custom_private_key_operation_is_forced_to_confirm() {
    let operation = OperationId(90);
    let state = request_operation(unlocked_state(HostTrust::Trusted), operation);

    let transition = update(
        state,
        Event::ReviewPrepared {
            id: operation,
            plan: ReviewPlan {
                kind: OperationKind::Custom(0xCAFE),
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Silent,
            },
        },
    );
    assert_eq!(transition.effect, Effect::RenderOperationReview(operation));

    let transition = update(transition.state, Event::ReviewDisplayed(operation));
    assert!(matches!(
        transition.state.flow(),
        FlowState::Operation(PendingOperation {
            stage: OperationStage::Reviewing { .. },
            ..
        })
    ));
    assert_eq!(transition.effect, Effect::None);
}

#[test]
fn blind_signing_is_rejected_by_default() {
    let operation = OperationId(21);
    let state = request_operation(unlocked_state(HostTrust::Trusted), operation);

    let transition = update(
        state,
        Event::ReviewPrepared {
            id: operation,
            plan: ReviewPlan {
                kind: OperationKind::SignMessage,
                uses_private_key: true,
                assurance: ReviewAssurance::Blind,
                interaction: Interaction::Confirm,
            },
        },
    );

    assert_eq!(transition.state.flow(), FlowState::Idle);
    assert_eq!(
        transition.effect,
        Effect::RejectOperation {
            id: operation,
            reason: RejectReason::BlindSigningDisabled,
        }
    );
}

#[test]
fn untrusted_host_can_be_forbidden_from_signing() {
    let mut policy = SecurityPolicy::strict();
    policy.signing_hosts = SigningHostPolicy::TrustedOnly;

    let setup = SetupId(1);
    let mut state = State::new(policy);
    state = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Disabled,
        },
    )
    .state;
    state = update(state, Event::KeyMaterialReady(setup)).state;
    state = update(state, Event::BackupShown(setup)).state;
    state = update(state, Event::BackupVerified(setup)).state;
    state = update(state, Event::PinConfigured(setup)).state;
    state = update(state, Event::ProvisioningPersisted(setup)).state;

    let auth = AuthId(2);
    let host = HostId(7);
    state = update(
        state,
        Event::UnlockRequested {
            id: auth,
            host,
            trust: HostTrust::Untrusted,
        },
    )
    .state;
    state = update(state, Event::PinVerified(auth)).state;
    state = update(
        state,
        Event::SessionOpened {
            auth,
            session: SessionId(3),
            wallet: WalletContextId(1),
        },
    )
    .state;

    let operation = OperationId(22);
    state = request_operation(state, operation);
    let transition = update(
        state,
        Event::ReviewPrepared {
            id: operation,
            plan: ReviewPlan {
                kind: OperationKind::SignTransaction,
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Confirm,
            },
        },
    );
    assert_eq!(
        transition.effect,
        Effect::RejectOperation {
            id: operation,
            reason: RejectReason::UntrustedHost,
        }
    );
}

#[test]
fn host_disconnect_locks_and_drops_foreground_flow() {
    let host = HostId(7);
    let operation = OperationId(30);
    let state = request_operation(unlocked_state(HostTrust::Trusted), operation);

    let transition = update(state, Event::HostDisconnected(host));
    assert!(matches!(transition.state.auth(), AuthState::Locked { .. }));
    assert_eq!(transition.state.flow(), FlowState::Idle);
    assert_eq!(transition.effect, Effect::ClearSensitiveState);
}

#[test]
fn request_correlation_mismatch_never_advances_operation() {
    let operation = OperationId(40);
    let state = request_operation(unlocked_state(HostTrust::Trusted), operation);
    let before = state;

    let transition = update(
        state,
        Event::ReviewPrepared {
            id: OperationId(999),
            plan: ReviewPlan {
                kind: OperationKind::SignTransaction,
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Confirm,
            },
        },
    );

    assert_eq!(transition.state, before);
    assert_eq!(
        transition.effect,
        Effect::Reject(RejectReason::CorrelationMismatch)
    );
}

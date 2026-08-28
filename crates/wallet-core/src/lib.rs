#![no_std]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Locked,
    Ready,
    Reviewing(RequestId),
    AwaitingSignature(RequestId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Unlocked,
    Locked,
    SigningRequested(RequestId),
    ReviewPrepared(RequestId),
    Confirmed,
    Rejected,
    SignatureCompleted(RequestId),
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    None,
    PrepareReview(RequestId),
    RenderReview(RequestId),
    PerformSignature(RequestId),
    ReplySigned(RequestId),
    ReplyRejected(RequestId),
    ClearSensitiveState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub state: State,
    pub effect: Effect,
}

/// Pure wallet state transition.
///
/// This function has no knowledge of chains, USB, displays, flash, secure
/// elements or any particular MCU. Platform code executes the returned effect
/// and feeds the result back as another event.
#[must_use]
pub const fn update(state: State, event: Event) -> Transition {
    match (state, event) {
        (State::Locked, Event::Unlocked) => Transition {
            state: State::Ready,
            effect: Effect::None,
        },
        (_, Event::Locked) => Transition {
            state: State::Locked,
            effect: Effect::ClearSensitiveState,
        },
        (State::Ready, Event::SigningRequested(id)) => Transition {
            state: State::Reviewing(id),
            effect: Effect::PrepareReview(id),
        },
        (State::Reviewing(expected), Event::ReviewPrepared(actual)) if expected.0 == actual.0 => {
            Transition {
                state,
                effect: Effect::RenderReview(actual),
            }
        }
        (State::Reviewing(id), Event::Confirmed) => Transition {
            state: State::AwaitingSignature(id),
            effect: Effect::PerformSignature(id),
        },
        (State::Reviewing(id), Event::Rejected) => Transition {
            state: State::Ready,
            effect: Effect::ReplyRejected(id),
        },
        (State::AwaitingSignature(expected), Event::SignatureCompleted(actual))
            if expected.0 == actual.0 =>
        {
            Transition {
                state: State::Ready,
                effect: Effect::ReplySigned(actual),
            }
        }
        (_, Event::Failed) => Transition {
            state: State::Locked,
            effect: Effect::ClearSensitiveState,
        },
        _ => Transition {
            state,
            effect: Effect::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_requires_review_and_confirmation() {
        let id = RequestId(7);

        let transition = update(State::Ready, Event::SigningRequested(id));
        assert_eq!(transition.state, State::Reviewing(id));
        assert_eq!(transition.effect, Effect::PrepareReview(id));

        let transition = update(transition.state, Event::ReviewPrepared(id));
        assert_eq!(transition.state, State::Reviewing(id));
        assert_eq!(transition.effect, Effect::RenderReview(id));

        let transition = update(transition.state, Event::Confirmed);
        assert_eq!(transition.state, State::AwaitingSignature(id));
        assert_eq!(transition.effect, Effect::PerformSignature(id));
    }

    #[test]
    fn rejection_never_signs() {
        let id = RequestId(9);
        let transition = update(State::Reviewing(id), Event::Rejected);

        assert_eq!(transition.state, State::Ready);
        assert_eq!(transition.effect, Effect::ReplyRejected(id));
    }

    #[test]
    fn failure_locks_and_clears_sensitive_state() {
        let transition = update(State::AwaitingSignature(RequestId(1)), Event::Failed);

        assert_eq!(transition.state, State::Locked);
        assert_eq!(transition.effect, Effect::ClearSensitiveState);
    }
}

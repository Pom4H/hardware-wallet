#![no_std]

use hardware_wallet_core::{
    update, AuthId, AuthState, BackupStatus, Effect, Event, FlowState, HostId, HostTrust,
    Interaction, OperationId, OperationKind, PassphraseMode, PersistentState, ReviewAssurance,
    ReviewPlan, SecurityPolicy, SessionId, State, WalletContextId, WalletMetadata, WalletOrigin,
};

pub const FRAME_MAGIC: [u8; 4] = *b"WLT1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_CAPACITY: usize = 224;

const HOST: HostId = HostId(1);
const AUTH: AuthId = AuthId(1);
const SESSION: SessionId = SessionId(1);
const WALLET: WalletContextId = WalletContextId(1);
const OPERATION: OperationId = OperationId(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Button {
    Left = 0,
    Right = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScreenState {
    Locked = 0,
    Ready = 1,
    Review = 2,
    Signing = 3,
    Signed = 4,
    Rejected = 5,
    Error = 6,
}

impl ScreenState {
    #[must_use]
    pub const fn signing_active(self) -> bool {
        matches!(self, Self::Signing)
    }

    #[must_use]
    pub const fn review_active(self) -> bool {
        matches!(self, Self::Review)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreenCopy {
    pub title: &'static str,
    pub line1: &'static str,
    pub line2: &'static str,
    pub footer: &'static str,
    pub left: &'static str,
    pub right: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub sequence: u8,
    pub state: ScreenState,
    pub session_unlocked: bool,
    pub copy: ScreenCopy,
}

impl Frame {
    #[must_use]
    pub fn encode(self, output: &mut [u8; FRAME_CAPACITY]) -> usize {
        output.fill(0);
        output[..4].copy_from_slice(&FRAME_MAGIC);
        output[4] = FRAME_VERSION;
        output[5] = self.state as u8;
        output[6] = u8::from(self.state.signing_active())
            | (u8::from(self.session_unlocked) << 1)
            | (u8::from(self.state.review_active()) << 2)
            | (1 << 3);
        output[7] = self.sequence;

        let mut cursor = 8;
        cursor = write_field(output, cursor, self.copy.title);
        cursor = write_field(output, cursor, self.copy.line1);
        cursor = write_field(output, cursor, self.copy.line2);
        cursor = write_field(output, cursor, self.copy.footer);
        cursor = write_field(output, cursor, self.copy.left);
        write_field(output, cursor, self.copy.right)
    }
}

fn write_field(output: &mut [u8; FRAME_CAPACITY], mut cursor: usize, value: &str) -> usize {
    for byte in value.bytes() {
        if cursor + 1 >= output.len() {
            break;
        }
        output[cursor] = if byte.is_ascii() { byte } else { b'?' };
        cursor += 1;
    }
    if cursor < output.len() {
        output[cursor] = 0;
        cursor += 1;
    }
    cursor
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletDemo {
    state: State,
    screen: ScreenState,
    sequence: u8,
    signing_ticks: u16,
    last_effect: Effect,
}

impl WalletDemo {
    #[must_use]
    pub fn new() -> Self {
        let state = State::restore(PersistentState {
            wallet: Some(WalletMetadata {
                origin: WalletOrigin::Generated,
                backup: BackupStatus::Verified,
                passphrase: PassphraseMode::Disabled,
            }),
            policy: SecurityPolicy::strict(),
        });
        Self {
            state,
            screen: ScreenState::Locked,
            sequence: 0,
            signing_ticks: 0,
            last_effect: Effect::None,
        }
    }

    #[must_use]
    pub const fn screen(self) -> ScreenState {
        self.screen
    }

    #[must_use]
    pub const fn state(self) -> State {
        self.state
    }

    #[must_use]
    pub const fn last_effect(self) -> Effect {
        self.last_effect
    }

    #[must_use]
    pub fn frame(self) -> Frame {
        Frame {
            sequence: self.sequence,
            state: self.screen,
            session_unlocked: matches!(self.state.auth(), AuthState::Unlocked(_)),
            copy: copy_for(self.screen),
        }
    }

    pub fn press(&mut self, button: Button) {
        match (self.screen, button) {
            (ScreenState::Locked, Button::Right) => self.unlock(),
            (ScreenState::Locked, Button::Left) => {}
            (ScreenState::Ready, Button::Right) => self.begin_review(),
            (ScreenState::Ready, Button::Left) => self.lock(),
            (ScreenState::Review, Button::Right) => self.confirm(),
            (ScreenState::Review, Button::Left) => self.reject(),
            (ScreenState::Signing, _) => {}
            (ScreenState::Signed | ScreenState::Rejected | ScreenState::Error, _) => {
                self.set_screen(if self.state.is_unlocked() {
                    ScreenState::Ready
                } else {
                    ScreenState::Locked
                });
            }
        }
    }

    /// Advance deterministic firmware time. Signing completes only after the
    /// reducer has authorized execution and the isolated runtime has received
    /// enough ticks to finish the demo operation.
    pub fn tick(&mut self, ticks: u16) {
        if self.screen != ScreenState::Signing {
            return;
        }
        self.signing_ticks = self.signing_ticks.saturating_add(ticks);
        if self.signing_ticks < 180 {
            return;
        }
        self.apply(Event::OperationCompleted(OPERATION));
        if matches!(self.last_effect, Effect::CompleteOperation(id) if id == OPERATION) {
            self.set_screen(ScreenState::Signed);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn unlock(&mut self) {
        self.apply(Event::UnlockRequested {
            id: AUTH,
            host: HOST,
        });
        if self.last_effect != (Effect::ResolveHostTrust { id: AUTH, host: HOST }) {
            self.set_screen(ScreenState::Error);
            return;
        }
        self.apply(Event::HostTrustResolved {
            id: AUTH,
            trust: HostTrust::Trusted,
        });
        self.apply(Event::PinVerified(AUTH));
        self.apply(Event::SessionOpened {
            auth: AUTH,
            session: SESSION,
            wallet: WALLET,
        });
        if self.state.is_unlocked() && self.last_effect == Effect::SessionReady {
            self.set_screen(ScreenState::Ready);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn lock(&mut self) {
        self.apply(Event::LockRequested);
        if matches!(self.state.auth(), AuthState::Locked { .. }) {
            self.set_screen(ScreenState::Locked);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn begin_review(&mut self) {
        self.apply(Event::OperationRequested {
            id: OPERATION,
            host: HOST,
        });
        if self.last_effect != Effect::PrepareOperationReview(OPERATION) {
            self.set_screen(ScreenState::Error);
            return;
        }

        self.apply(Event::ReviewPrepared {
            id: OPERATION,
            plan: ReviewPlan {
                kind: OperationKind::SignTransaction,
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Confirm,
            },
        });
        if self.last_effect != Effect::RenderOperationReview(OPERATION) {
            self.set_screen(ScreenState::Error);
            return;
        }

        self.apply(Event::ReviewDisplayed(OPERATION));
        if matches!(self.state.flow(), FlowState::Operation(_)) && self.last_effect == Effect::None {
            self.set_screen(ScreenState::Review);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn confirm(&mut self) {
        self.apply(Event::OperationConfirmed(OPERATION));
        if self.last_effect == Effect::ExecuteOperation(OPERATION) {
            self.signing_ticks = 0;
            self.set_screen(ScreenState::Signing);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn reject(&mut self) {
        self.apply(Event::OperationRejected(OPERATION));
        if matches!(
            self.last_effect,
            Effect::RejectOperation {
                id: OPERATION,
                reason: hardware_wallet_core::RejectReason::UserRejected,
            }
        ) {
            self.set_screen(ScreenState::Rejected);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn apply(&mut self, event: Event) {
        let transition = update(self.state, event);
        self.state = transition.state;
        self.last_effect = transition.effect;
    }

    fn set_screen(&mut self, screen: ScreenState) {
        if self.screen != screen {
            self.screen = screen;
            self.sequence = self.sequence.wrapping_add(1);
        }
    }
}

impl Default for WalletDemo {
    fn default() -> Self {
        Self::new()
    }
}

const fn copy_for(state: ScreenState) -> ScreenCopy {
    match state {
        ScreenState::Locked => ScreenCopy {
            title: "WALLET LOCKED",
            line1: "PRIVATE KEYS SEALED",
            line2: "PRESS RIGHT TO UNLOCK",
            footer: "FIRMVERSE / WALLET-CORE",
            left: "",
            right: "UNLOCK",
        },
        ScreenState::Ready => ScreenCopy {
            title: "DEVICE READY",
            line1: "HOST SESSION VERIFIED",
            line2: "REVIEW A TRANSACTION",
            footer: "KEY CONTEXT IS OPAQUE",
            left: "LOCK",
            right: "REVIEW",
        },
        ScreenState::Review => ScreenCopy {
            title: "REVIEW TRANSACTION",
            line1: "SEND 0.10 BTC",
            line2: "TO BC1Q...7X2",
            footer: "VERIFY DEVICE DISPLAY",
            left: "REJECT",
            right: "CONFIRM",
        },
        ScreenState::Signing => ScreenCopy {
            title: "APPROVED",
            line1: "SIGNING SECP256K1",
            line2: "PRIVATE KEY NOT EXPORTED",
            footer: "ISOLATED RUNTIME ACTIVE",
            left: "WAIT",
            right: "WAIT",
        },
        ScreenState::Signed => ScreenCopy {
            title: "SIGNATURE READY",
            line1: "RETURNED TO HOST",
            line2: "PRIVATE KEY STAYED HERE",
            footer: "PRESS EITHER BUTTON",
            left: "DONE",
            right: "DONE",
        },
        ScreenState::Rejected => ScreenCopy {
            title: "REQUEST REJECTED",
            line1: "NOTHING WAS SIGNED",
            line2: "HOST RECEIVES AN ERROR",
            footer: "PRESS EITHER BUTTON",
            left: "BACK",
            right: "BACK",
        },
        ScreenState::Error => ScreenCopy {
            title: "FAIL CLOSED",
            line1: "INVALID DOMAIN STATE",
            line2: "NO SIGNATURE CREATED",
            footer: "RESET THE DEMO",
            left: "RESET",
            right: "RESET",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardware_wallet_core::{OperationStage, RejectReason};

    #[test]
    fn physical_confirmation_drives_the_real_reducer() {
        let mut demo = WalletDemo::new();
        demo.press(Button::Right);
        assert_eq!(demo.screen(), ScreenState::Ready);
        assert!(demo.state().is_unlocked());

        demo.press(Button::Right);
        assert_eq!(demo.screen(), ScreenState::Review);
        assert!(matches!(
            demo.state().flow(),
            FlowState::Operation(operation)
                if matches!(operation.stage, OperationStage::Reviewing { .. })
        ));

        demo.press(Button::Right);
        assert_eq!(demo.screen(), ScreenState::Signing);
        assert_eq!(demo.last_effect(), Effect::ExecuteOperation(OPERATION));

        demo.tick(180);
        assert_eq!(demo.screen(), ScreenState::Signed);
        assert_eq!(demo.last_effect(), Effect::CompleteOperation(OPERATION));
        assert_eq!(demo.state().flow(), FlowState::Idle);
    }

    #[test]
    fn left_button_rejects_without_executing_private_key_work() {
        let mut demo = WalletDemo::new();
        demo.press(Button::Right);
        demo.press(Button::Right);
        demo.press(Button::Left);

        assert_eq!(demo.screen(), ScreenState::Rejected);
        assert_eq!(
            demo.last_effect(),
            Effect::RejectOperation {
                id: OPERATION,
                reason: RejectReason::UserRejected,
            }
        );
        assert_eq!(demo.state().flow(), FlowState::Idle);
    }

    #[test]
    fn frame_is_bounded_and_carries_firmware_owned_copy() {
        let mut demo = WalletDemo::new();
        demo.press(Button::Right);
        demo.press(Button::Right);
        let mut encoded = [0_u8; FRAME_CAPACITY];
        let length = demo.frame().encode(&mut encoded);

        assert!(length <= FRAME_CAPACITY);
        assert_eq!(&encoded[..4], b"WLT1");
        assert_eq!(encoded[5], ScreenState::Review as u8);
        assert!(encoded[..length]
            .windows(b"VERIFY DEVICE DISPLAY".len())
            .any(|window| window == b"VERIFY DEVICE DISPLAY"));
    }
}

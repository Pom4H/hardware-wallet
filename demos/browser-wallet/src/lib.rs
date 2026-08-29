#![no_std]

use hardware_wallet_core::{
    update, AuthId, AuthState, BackupStatus, Effect, Event, FlowState, HostId, HostTrust,
    Interaction, OperationId, OperationKind, PassphraseMode, PersistentState, ReviewAssurance,
    ReviewPlan, SecurityPolicy, SessionId, State, WalletContextId, WalletMetadata, WalletOrigin,
};

pub const FRAME_MAGIC: [u8; 4] = *b"WLT1";
pub const FRAME_VERSION: u8 = 2;
pub const FRAME_CAPACITY: usize = 224;

const HOST: HostId = HostId(1);
const AUTH: AuthId = AuthId(1);
const SESSION: SessionId = SessionId(1);
const WALLET: WalletContextId = WalletContextId(1);
const OPERATION: OperationId = OperationId(1);
const PIN_DIGITS: usize = 4;
const AUTO_SLEEP_MS: u32 = 30_000;

const RECOVERY_WORDS: [&str; 24] = [
    "LETTER", "ADVICE", "CAGE", "ABSURD", "AMOUNT", "DOCTOR", "ACOUSTIC", "AVOID",
    "LETTER", "ADVICE", "CAGE", "ABSURD", "AMOUNT", "DOCTOR", "ACOUSTIC", "AVOID",
    "LETTER", "ADVICE", "CAGE", "ABSURD", "AMOUNT", "DOCTOR", "ACOUSTIC", "BLESS",
];
const CHECK_ONE: [&str; 4] = ["CABLE", "CACTUS", "CAGE", "CALL"];
const CHECK_TWO: [&str; 4] = ["BLANKET", "BLAST", "BLESS", "BLIND"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Button {
    Left = 0,
    Right = 1,
    Both = 2,
    BothHeld = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScreenState {
    Welcome = 0,
    SetupChoice = 1,
    PinCreate = 2,
    PinConfirm = 3,
    PinMismatch = 4,
    RecoveryIntro = 5,
    RecoveryWord = 6,
    RecoveryCheck = 7,
    RecoveryCheckFailed = 8,
    SetupComplete = 9,
    Dashboard = 10,
    BitcoinApp = 11,
    Settings = 12,
    SecuritySettings = 13,
    DisplaySettings = 14,
    PowerSettings = 15,
    About = 16,
    Information = 17,
    ControlCenter = 18,
    Locked = 19,
    PinUnlock = 20,
    PinWrong = 21,
    Review = 22,
    Signing = 23,
    Signed = 24,
    Rejected = 25,
    Sleeping = 26,
    Error = 27,
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

    #[must_use]
    pub const fn display_on(self) -> bool {
        !matches!(self, Self::Sleeping)
    }

    #[must_use]
    pub const fn sleeping(self) -> bool {
        matches!(self, Self::Sleeping)
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
    pub setup_complete: bool,
    pub wake_count: u8,
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
            | (u8::from(self.state.display_on()) << 3)
            | (u8::from(self.state.sleeping()) << 4)
            | (u8::from(self.setup_complete) << 5);
        output[7] = self.sequence;

        let mut cursor = 8;
        cursor = write_field(output, cursor, self.copy.title);
        cursor = write_field(output, cursor, self.copy.line1);
        cursor = write_field(output, cursor, self.copy.line2);
        cursor = write_field(output, cursor, self.copy.footer);
        cursor = write_field(output, cursor, self.copy.left);
        cursor = write_field(output, cursor, self.copy.right);
        if cursor < output.len() {
            output[cursor] = self.wake_count;
            cursor += 1;
        }
        cursor
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

#[derive(Debug)]
pub struct WalletDemo {
    state: State,
    screen: ScreenState,
    sequence: u8,
    signing_ticks: u16,
    inactivity_ms: u32,
    last_effect: Effect,
    setup_choice: u8,
    pin: [u8; PIN_DIGITS],
    pin_confirmation: [u8; PIN_DIGITS],
    pin_entry: [u8; PIN_DIGITS],
    pin_position: u8,
    selected_digit: u8,
    recovery_index: u8,
    recovery_check_step: u8,
    recovery_check_choice: u8,
    home_index: u8,
    settings_index: u8,
    security_index: u8,
    display_index: u8,
    power_index: u8,
    control_index: u8,
    brightness: u8,
    wake_count: u8,
    setup_complete: bool,
}

impl WalletDemo {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: blank_state(),
            screen: ScreenState::Welcome,
            sequence: 0,
            signing_ticks: 0,
            inactivity_ms: 0,
            last_effect: Effect::None,
            setup_choice: 0,
            pin: [0; PIN_DIGITS],
            pin_confirmation: [0; PIN_DIGITS],
            pin_entry: [0; PIN_DIGITS],
            pin_position: 0,
            selected_digit: 0,
            recovery_index: 0,
            recovery_check_step: 0,
            recovery_check_choice: 0,
            home_index: 0,
            settings_index: 0,
            security_index: 0,
            display_index: 1,
            power_index: 0,
            control_index: 0,
            brightness: 1,
            wake_count: 0,
            setup_complete: false,
        }
    }

    #[must_use]
    pub const fn screen(&self) -> ScreenState {
        self.screen
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn last_effect(&self) -> Effect {
        self.last_effect
    }

    #[must_use]
    pub const fn wake_count(&self) -> u8 {
        self.wake_count
    }

    #[must_use]
    pub const fn setup_complete(&self) -> bool {
        self.setup_complete
    }

    #[must_use]
    pub const fn sleeping(&self) -> bool {
        self.screen.sleeping()
    }

    #[must_use]
    pub fn frame(&self) -> Frame {
        Frame {
            sequence: self.sequence,
            state: self.screen,
            session_unlocked: matches!(self.state.auth(), AuthState::Unlocked(_)),
            setup_complete: self.setup_complete,
            wake_count: self.wake_count,
            copy: self.copy(),
        }
    }

    pub fn press(&mut self, button: Button) {
        if self.screen == ScreenState::Sleeping {
            self.wake_count = self.wake_count.saturating_add(1);
            self.inactivity_ms = 0;
            self.set_screen(ScreenState::Locked);
            return;
        }

        self.inactivity_ms = 0;

        if button == Button::BothHeld && self.can_open_control_center() {
            self.control_index = 0;
            self.set_screen(ScreenState::ControlCenter);
            return;
        }

        match self.screen {
            ScreenState::Welcome => {
                if button == Button::Both {
                    self.set_screen(ScreenState::SetupChoice);
                }
            }
            ScreenState::SetupChoice => match button {
                Button::Left | Button::Right => {
                    self.setup_choice ^= 1;
                    self.bump_frame();
                }
                Button::Both if self.setup_choice == 0 => self.start_pin_creation(),
                Button::Both => self.set_screen(ScreenState::Information),
                Button::BothHeld => {}
            },
            ScreenState::PinCreate => self.edit_pin(button, false),
            ScreenState::PinConfirm => self.edit_pin(button, true),
            ScreenState::PinMismatch => {
                if button == Button::Both {
                    self.start_pin_creation();
                }
            }
            ScreenState::RecoveryIntro => {
                if button == Button::Both {
                    self.recovery_index = 0;
                    self.set_screen(ScreenState::RecoveryWord);
                }
            }
            ScreenState::RecoveryWord => match button {
                Button::Left => {
                    self.recovery_index = self.recovery_index.saturating_sub(1);
                    self.bump_frame();
                }
                Button::Right => {
                    self.recovery_index = self.recovery_index.saturating_add(1).min(23);
                    self.bump_frame();
                }
                Button::Both if self.recovery_index == 23 => {
                    self.recovery_check_step = 0;
                    self.recovery_check_choice = 0;
                    self.set_screen(ScreenState::RecoveryCheck);
                }
                Button::Both | Button::BothHeld => {}
            },
            ScreenState::RecoveryCheck => self.verify_recovery_word(button),
            ScreenState::RecoveryCheckFailed => {
                if button == Button::Both {
                    self.recovery_check_choice = 0;
                    self.set_screen(ScreenState::RecoveryCheck);
                }
            }
            ScreenState::SetupComplete => {
                if button == Button::Both {
                    self.home_index = 0;
                    self.set_screen(ScreenState::Dashboard);
                }
            }
            ScreenState::Dashboard => self.dashboard_input(button),
            ScreenState::BitcoinApp => match button {
                Button::Left => self.set_screen(ScreenState::Dashboard),
                Button::Both => self.begin_review(),
                Button::Right | Button::BothHeld => {}
            },
            ScreenState::Settings => self.settings_input(button),
            ScreenState::SecuritySettings => self.security_input(button),
            ScreenState::DisplaySettings => self.display_input(button),
            ScreenState::PowerSettings => self.power_input(button),
            ScreenState::About | ScreenState::Information => {
                if button == Button::Both || button == Button::Left {
                    self.set_screen(if self.setup_complete {
                        ScreenState::Dashboard
                    } else {
                        ScreenState::SetupChoice
                    });
                }
            }
            ScreenState::ControlCenter => self.control_input(button),
            ScreenState::Locked => {
                if button == Button::Both {
                    self.pin_entry.fill(0);
                    self.pin_position = 0;
                    self.selected_digit = 0;
                    self.set_screen(ScreenState::PinUnlock);
                }
            }
            ScreenState::PinUnlock => self.unlock_pin_input(button),
            ScreenState::PinWrong => {
                if button == Button::Both {
                    self.pin_entry.fill(0);
                    self.pin_position = 0;
                    self.selected_digit = 0;
                    self.set_screen(ScreenState::PinUnlock);
                }
            }
            ScreenState::Review => self.review_input(button),
            ScreenState::Signing => {}
            ScreenState::Signed | ScreenState::Rejected => {
                if matches!(button, Button::Left | Button::Right | Button::Both) {
                    self.set_screen(ScreenState::BitcoinApp);
                }
            }
            ScreenState::Error => {
                if button == Button::Both {
                    self.set_screen(if self.setup_complete {
                        ScreenState::Locked
                    } else {
                        ScreenState::Welcome
                    });
                }
            }
            ScreenState::Sleeping => unreachable!(),
        }
    }

    /// Advance deterministic firmware time. Signing completes only after the
    /// reducer has authorized execution and the isolated runtime has received
    /// enough ticks to finish the demo operation.
    pub fn tick(&mut self, ticks: u16) {
        if self.screen == ScreenState::Signing {
            self.signing_ticks = self.signing_ticks.saturating_add(ticks);
            if self.signing_ticks >= 180 {
                self.apply(Event::OperationCompleted(OPERATION));
                if matches!(self.last_effect, Effect::CompleteOperation(id) if id == OPERATION) {
                    self.set_screen(ScreenState::Signed);
                } else {
                    self.set_screen(ScreenState::Error);
                }
            }
            return;
        }

        if self.setup_complete
            && self.state.is_unlocked()
            && !matches!(
                self.screen,
                ScreenState::Welcome
                    | ScreenState::SetupChoice
                    | ScreenState::PinCreate
                    | ScreenState::PinConfirm
                    | ScreenState::RecoveryIntro
                    | ScreenState::RecoveryWord
                    | ScreenState::RecoveryCheck
                    | ScreenState::Sleeping
            )
        {
            self.inactivity_ms = self.inactivity_ms.saturating_add(u32::from(ticks));
            if self.inactivity_ms >= AUTO_SLEEP_MS {
                self.enter_sleep();
            }
        }
    }

    fn start_pin_creation(&mut self) {
        self.pin.fill(0);
        self.pin_confirmation.fill(0);
        self.pin_position = 0;
        self.selected_digit = 0;
        self.set_screen(ScreenState::PinCreate);
    }

    fn edit_pin(&mut self, button: Button, confirmation: bool) {
        match button {
            Button::Left => {
                self.selected_digit = self.selected_digit.checked_sub(1).unwrap_or(9);
                self.bump_frame();
            }
            Button::Right => {
                self.selected_digit = (self.selected_digit + 1) % 10;
                self.bump_frame();
            }
            Button::Both => {
                let position = usize::from(self.pin_position);
                if confirmation {
                    self.pin_confirmation[position] = self.selected_digit;
                } else {
                    self.pin[position] = self.selected_digit;
                }
                self.pin_position += 1;
                self.selected_digit = 0;
                if usize::from(self.pin_position) < PIN_DIGITS {
                    self.bump_frame();
                } else if confirmation {
                    self.pin_position = 0;
                    if self.pin == self.pin_confirmation {
                        self.set_screen(ScreenState::RecoveryIntro);
                    } else {
                        self.set_screen(ScreenState::PinMismatch);
                    }
                } else {
                    self.pin_position = 0;
                    self.set_screen(ScreenState::PinConfirm);
                }
            }
            Button::BothHeld => {}
        }
    }

    fn verify_recovery_word(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.recovery_check_choice = self.recovery_check_choice.checked_sub(1).unwrap_or(3);
                self.bump_frame();
            }
            Button::Right => {
                self.recovery_check_choice = (self.recovery_check_choice + 1) % 4;
                self.bump_frame();
            }
            Button::Both => {
                if self.recovery_check_choice != 2 {
                    self.set_screen(ScreenState::RecoveryCheckFailed);
                    return;
                }
                if self.recovery_check_step == 0 {
                    self.recovery_check_step = 1;
                    self.recovery_check_choice = 0;
                    self.bump_frame();
                } else {
                    self.complete_setup();
                }
            }
            Button::BothHeld => {}
        }
    }

    fn complete_setup(&mut self) {
        self.state = provisioned_state();
        self.setup_complete = true;
        self.unlock_domain();
        if self.state.is_unlocked() {
            self.set_screen(ScreenState::SetupComplete);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn dashboard_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.home_index = previous(self.home_index, 3);
                self.bump_frame();
            }
            Button::Right => {
                self.home_index = next(self.home_index, 3);
                self.bump_frame();
            }
            Button::Both => match self.home_index {
                0 => self.set_screen(ScreenState::BitcoinApp),
                1 => {
                    self.settings_index = 0;
                    self.set_screen(ScreenState::Settings);
                }
                _ => self.set_screen(ScreenState::About),
            },
            Button::BothHeld => {}
        }
    }

    fn settings_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.settings_index = previous(self.settings_index, 4);
                self.bump_frame();
            }
            Button::Right => {
                self.settings_index = next(self.settings_index, 4);
                self.bump_frame();
            }
            Button::Both => match self.settings_index {
                0 => {
                    self.security_index = 0;
                    self.set_screen(ScreenState::SecuritySettings);
                }
                1 => {
                    self.display_index = self.brightness;
                    self.set_screen(ScreenState::DisplaySettings);
                }
                2 => {
                    self.power_index = 0;
                    self.set_screen(ScreenState::PowerSettings);
                }
                _ => self.set_screen(ScreenState::Dashboard),
            },
            Button::BothHeld => {}
        }
    }

    fn security_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.security_index = previous(self.security_index, 3);
                self.bump_frame();
            }
            Button::Right => {
                self.security_index = next(self.security_index, 3);
                self.bump_frame();
            }
            Button::Both => {
                if self.security_index == 2 {
                    self.set_screen(ScreenState::Settings);
                } else {
                    self.set_screen(ScreenState::Information);
                }
            }
            Button::BothHeld => {}
        }
    }

    fn display_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.display_index = previous(self.display_index, 4);
                self.bump_frame();
            }
            Button::Right => {
                self.display_index = next(self.display_index, 4);
                self.bump_frame();
            }
            Button::Both => {
                if self.display_index == 3 {
                    self.set_screen(ScreenState::Settings);
                } else {
                    self.brightness = self.display_index;
                    self.set_screen(ScreenState::Settings);
                }
            }
            Button::BothHeld => {}
        }
    }

    fn power_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.power_index = previous(self.power_index, 3);
                self.bump_frame();
            }
            Button::Right => {
                self.power_index = next(self.power_index, 3);
                self.bump_frame();
            }
            Button::Both => match self.power_index {
                0 => self.enter_sleep(),
                1 => self.set_screen(ScreenState::Information),
                _ => self.set_screen(ScreenState::Settings),
            },
            Button::BothHeld => {}
        }
    }

    fn control_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.control_index = previous(self.control_index, 4);
                self.bump_frame();
            }
            Button::Right => {
                self.control_index = next(self.control_index, 4);
                self.bump_frame();
            }
            Button::Both => match self.control_index {
                0 => self.lock(),
                1 => {
                    self.settings_index = 0;
                    self.set_screen(ScreenState::Settings);
                }
                2 => self.enter_sleep(),
                _ => self.set_screen(ScreenState::Dashboard),
            },
            Button::BothHeld => {}
        }
    }

    fn unlock_pin_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.selected_digit = self.selected_digit.checked_sub(1).unwrap_or(9);
                self.bump_frame();
            }
            Button::Right => {
                self.selected_digit = (self.selected_digit + 1) % 10;
                self.bump_frame();
            }
            Button::Both => {
                let position = usize::from(self.pin_position);
                self.pin_entry[position] = self.selected_digit;
                self.pin_position += 1;
                self.selected_digit = 0;
                if usize::from(self.pin_position) < PIN_DIGITS {
                    self.bump_frame();
                    return;
                }
                self.pin_position = 0;
                if self.pin_entry == self.pin {
                    self.unlock_domain();
                    if self.state.is_unlocked() {
                        self.home_index = 0;
                        self.set_screen(ScreenState::Dashboard);
                    } else {
                        self.set_screen(ScreenState::Error);
                    }
                } else {
                    self.set_screen(ScreenState::PinWrong);
                }
            }
            Button::BothHeld => {}
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
            self.review_index = 0;
            self.set_screen(ScreenState::Review);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn review_input(&mut self, button: Button) {
        match button {
            Button::Left => {
                self.review_index = previous(self.review_index, 5);
                self.bump_frame();
            }
            Button::Right => {
                self.review_index = next(self.review_index, 5);
                self.bump_frame();
            }
            Button::Both if self.review_index == 3 => self.confirm(),
            Button::Both if self.review_index == 4 => self.reject(),
            Button::Both | Button::BothHeld => {}
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

    fn unlock_domain(&mut self) {
        if self.state.is_unlocked() {
            return;
        }
        self.apply(Event::UnlockRequested {
            id: AUTH,
            host: HOST,
        });
        if self.last_effect != (Effect::ResolveHostTrust { id: AUTH, host: HOST }) {
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
    }

    fn lock(&mut self) {
        if self.state.is_unlocked() {
            self.apply(Event::LockRequested);
        }
        if matches!(self.state.auth(), AuthState::Locked { .. }) {
            self.set_screen(ScreenState::Locked);
        } else {
            self.set_screen(ScreenState::Error);
        }
    }

    fn enter_sleep(&mut self) {
        if self.state.is_unlocked() {
            self.apply(Event::LockRequested);
        }
        self.inactivity_ms = 0;
        self.set_screen(ScreenState::Sleeping);
    }

    fn can_open_control_center(&self) -> bool {
        self.setup_complete
            && self.state.is_unlocked()
            && !matches!(
                self.screen,
                ScreenState::Signing
                    | ScreenState::Review
                    | ScreenState::PinUnlock
                    | ScreenState::Sleeping
            )
    }

    fn apply(&mut self, event: Event) {
        let transition = update(self.state, event);
        self.state = transition.state;
        self.last_effect = transition.effect;
    }

    fn set_screen(&mut self, screen: ScreenState) {
        if self.screen != screen {
            self.screen = screen;
            self.bump_frame();
        }
    }

    fn bump_frame(&mut self) {
        self.sequence = self.sequence.wrapping_add(1);
    }

    fn copy(&self) -> ScreenCopy {
        match self.screen {
            ScreenState::Welcome => copy(
                "TWO-BUTTON WALLET OS",
                "LEFT / RIGHT = MOVE",
                "BOTH BUTTONS = ENTER",
                "PRESS BOTH TO BEGIN",
                "<",
                ">",
            ),
            ScreenState::SetupChoice => {
                if self.setup_choice == 0 {
                    copy(
                        "INITIALIZATION",
                        "SET UP AS NEW DEVICE",
                        "GENERATE KEYS ON DEVICE",
                        "BOTH = ENTER",
                        "<",
                        ">",
                    )
                } else {
                    copy(
                        "INITIALIZATION",
                        "RESTORE FROM BACKUP",
                        "ENTER RECOVERY WORDS",
                        "BOTH = ENTER",
                        "<",
                        ">",
                    )
                }
            }
            ScreenState::PinCreate => pin_copy("CREATE PIN", self.pin_position, self.selected_digit),
            ScreenState::PinConfirm => {
                pin_copy("CONFIRM PIN", self.pin_position, self.selected_digit)
            }
            ScreenState::PinMismatch => copy(
                "PIN MISMATCH",
                "THE TWO ENTRIES DIFFER",
                "NO PIN WAS STORED",
                "BOTH = TRY AGAIN",
                "",
                "",
            ),
            ScreenState::RecoveryIntro => copy(
                "RECOVERY BACKUP",
                "24 WORDS WILL FOLLOW",
                "WRITE THEM DOWN OFFLINE",
                "BOTH = SHOW WORDS",
                "",
                "",
            ),
            ScreenState::RecoveryWord => copy(
                recovery_title(self.recovery_index),
                RECOVERY_WORDS[usize::from(self.recovery_index)],
                "WRITE IN THIS ORDER",
                "LEFT / RIGHT TO REVIEW",
                "<",
                ">",
            ),
            ScreenState::RecoveryCheck => copy(
                if self.recovery_check_step == 0 {
                    "VERIFY WORD #03"
                } else {
                    "VERIFY WORD #24"
                },
                recovery_candidate(self.recovery_check_step, self.recovery_check_choice),
                "SELECT WHAT YOU WROTE",
                "BOTH = ENTER",
                "<",
                ">",
            ),
            ScreenState::RecoveryCheckFailed => copy(
                "BACKUP CHECK FAILED",
                "WRONG RECOVERY WORD",
                "REVIEW YOUR PAPER COPY",
                "BOTH = TRY AGAIN",
                "",
                "",
            ),
            ScreenState::SetupComplete => copy(
                "DEVICE IS READY",
                "PIN AND BACKUP VERIFIED",
                "KEY ROOT COMMITTED",
                "BOTH = OPEN DASHBOARD",
                "",
                "",
            ),
            ScreenState::Dashboard => dashboard_copy(self.home_index),
            ScreenState::BitcoinApp => copy(
                "BITCOIN",
                "APP READY",
                "HOST MAY PROPOSE A TX",
                "BOTH = OPEN DEMO REVIEW",
                "BACK",
                "",
            ),
            ScreenState::Settings => settings_copy(self.settings_index),
            ScreenState::SecuritySettings => security_copy(self.security_index),
            ScreenState::DisplaySettings => display_copy(self.display_index),
            ScreenState::PowerSettings => power_copy(self.power_index),
            ScreenState::About => copy(
                "ABOUT DEVICE",
                "WALLET OS DEMO 2.0",
                "CORTEX-M IN FIRMVERSE",
                "BOTH = BACK",
                "",
                "",
            ),
            ScreenState::Information => copy(
                "INFORMATION",
                "FLOW EXISTS IN PRODUCT",
                "SHORTENED IN THIS LESSON",
                "BOTH = BACK",
                "",
                "",
            ),
            ScreenState::ControlCenter => control_copy(self.control_index),
            ScreenState::Locked => copy(
                "DEVICE LOCKED",
                "PRIVATE KEYS SEALED",
                "PIN REQUIRED",
                "BOTH = ENTER PIN",
                "",
                "",
            ),
            ScreenState::PinUnlock => pin_copy("ENTER PIN", self.pin_position, self.selected_digit),
            ScreenState::PinWrong => copy(
                "WRONG PIN",
                "ACCESS DENIED",
                "ATTEMPT NOT ACCEPTED",
                "BOTH = TRY AGAIN",
                "",
                "",
            ),
            ScreenState::Review => review_copy(self.review_index),
            ScreenState::Signing => copy(
                "APPROVED",
                "SIGNING SECP256K1",
                "PRIVATE KEY NOT EXPORTED",
                "PHYSICAL INPUT LOCKED",
                "WAIT",
                "WAIT",
            ),
            ScreenState::Signed => copy(
                "SIGNATURE READY",
                "RETURNED TO HOST",
                "PRIVATE KEY STAYED HERE",
                "BOTH = BACK TO BITCOIN",
                "",
                "",
            ),
            ScreenState::Rejected => copy(
                "REQUEST REJECTED",
                "NOTHING WAS SIGNED",
                "HOST RECEIVES AN ERROR",
                "BOTH = BACK TO BITCOIN",
                "",
                "",
            ),
            ScreenState::Sleeping => copy("", "", "", "DISPLAY AND CPU ASLEEP", "", ""),
            ScreenState::Error => copy(
                "FAIL CLOSED",
                "INVALID DOMAIN STATE",
                "NO SIGNATURE CREATED",
                "BOTH = RESET VIEW",
                "",
                "",
            ),
        }
    }
}

impl Default for WalletDemo {
    fn default() -> Self {
        Self::new()
    }
}

fn blank_state() -> State {
    State::restore(PersistentState {
        wallet: None,
        policy: SecurityPolicy::strict(),
    })
}

fn provisioned_state() -> State {
    State::restore(PersistentState {
        wallet: Some(WalletMetadata {
            origin: WalletOrigin::Generated,
            backup: BackupStatus::Verified,
            passphrase: PassphraseMode::Disabled,
        }),
        policy: SecurityPolicy::strict(),
    })
}

const fn previous(value: u8, count: u8) -> u8 {
    if value == 0 { count - 1 } else { value - 1 }
}

const fn next(value: u8, count: u8) -> u8 {
    (value + 1) % count
}

const fn copy(
    title: &'static str,
    line1: &'static str,
    line2: &'static str,
    footer: &'static str,
    left: &'static str,
    right: &'static str,
) -> ScreenCopy {
    ScreenCopy {
        title,
        line1,
        line2,
        footer,
        left,
        right,
    }
}

fn pin_copy(title: &'static str, position: u8, digit: u8) -> ScreenCopy {
    copy(
        title,
        pin_progress(position),
        selected_digit(digit),
        "LEFT / RIGHT · BOTH ENTER",
        "-",
        "+",
    )
}

const fn pin_progress(position: u8) -> &'static str {
    match position {
        0 => "_  _  _  _",
        1 => "*  _  _  _",
        2 => "*  *  _  _",
        _ => "*  *  *  _",
    }
}

const fn selected_digit(digit: u8) -> &'static str {
    match digit {
        0 => "SELECT DIGIT 0",
        1 => "SELECT DIGIT 1",
        2 => "SELECT DIGIT 2",
        3 => "SELECT DIGIT 3",
        4 => "SELECT DIGIT 4",
        5 => "SELECT DIGIT 5",
        6 => "SELECT DIGIT 6",
        7 => "SELECT DIGIT 7",
        8 => "SELECT DIGIT 8",
        _ => "SELECT DIGIT 9",
    }
}

const fn recovery_title(index: u8) -> &'static str {
    match index {
        0 => "RECOVERY WORD 01 / 24",
        1 => "RECOVERY WORD 02 / 24",
        2 => "RECOVERY WORD 03 / 24",
        3 => "RECOVERY WORD 04 / 24",
        4 => "RECOVERY WORD 05 / 24",
        5 => "RECOVERY WORD 06 / 24",
        6 => "RECOVERY WORD 07 / 24",
        7 => "RECOVERY WORD 08 / 24",
        8 => "RECOVERY WORD 09 / 24",
        9 => "RECOVERY WORD 10 / 24",
        10 => "RECOVERY WORD 11 / 24",
        11 => "RECOVERY WORD 12 / 24",
        12 => "RECOVERY WORD 13 / 24",
        13 => "RECOVERY WORD 14 / 24",
        14 => "RECOVERY WORD 15 / 24",
        15 => "RECOVERY WORD 16 / 24",
        16 => "RECOVERY WORD 17 / 24",
        17 => "RECOVERY WORD 18 / 24",
        18 => "RECOVERY WORD 19 / 24",
        19 => "RECOVERY WORD 20 / 24",
        20 => "RECOVERY WORD 21 / 24",
        21 => "RECOVERY WORD 22 / 24",
        22 => "RECOVERY WORD 23 / 24",
        _ => "RECOVERY WORD 24 / 24",
    }
}

const fn recovery_candidate(step: u8, choice: u8) -> &'static str {
    if step == 0 {
        CHECK_ONE[choice as usize]
    } else {
        CHECK_TWO[choice as usize]
    }
}

const fn dashboard_copy(index: u8) -> ScreenCopy {
    match index {
        0 => copy(
            "DASHBOARD",
            "BITCOIN",
            "OPEN INSTALLED APP",
            "BOTH = ENTER",
            "<",
            ">",
        ),
        1 => copy(
            "DASHBOARD",
            "SETTINGS",
            "SECURITY · DISPLAY · POWER",
            "BOTH = ENTER",
            "<",
            ">",
        ),
        _ => copy(
            "DASHBOARD",
            "ABOUT",
            "FIRMWARE AND DEVICE INFO",
            "BOTH = ENTER",
            "<",
            ">",
        ),
    }
}

const fn settings_copy(index: u8) -> ScreenCopy {
    match index {
        0 => menu("SETTINGS", "SECURITY"),
        1 => menu("SETTINGS", "DISPLAY"),
        2 => menu("SETTINGS", "POWER"),
        _ => menu("SETTINGS", "BACK TO DASHBOARD"),
    }
}

const fn security_copy(index: u8) -> ScreenCopy {
    match index {
        0 => menu("SECURITY", "CHANGE PIN"),
        1 => menu("SECURITY", "PASSPHRASE"),
        _ => menu("SECURITY", "BACK"),
    }
}

const fn display_copy(index: u8) -> ScreenCopy {
    match index {
        0 => menu("DISPLAY", "BRIGHTNESS LOW"),
        1 => menu("DISPLAY", "BRIGHTNESS MEDIUM"),
        2 => menu("DISPLAY", "BRIGHTNESS HIGH"),
        _ => menu("DISPLAY", "BACK"),
    }
}

const fn power_copy(index: u8) -> ScreenCopy {
    match index {
        0 => copy(
            "POWER",
            "SLEEP NOW",
            "CPU WILL EXECUTE WFI",
            "BOTH = ENTER",
            "<",
            ">",
        ),
        1 => copy(
            "POWER",
            "AUTO-SLEEP 30 SECONDS",
            "LOCK BEFORE SLEEP",
            "BOTH = DETAILS",
            "<",
            ">",
        ),
        _ => menu("POWER", "BACK"),
    }
}

const fn control_copy(index: u8) -> ScreenCopy {
    match index {
        0 => menu("CONTROL CENTER", "LOCK DEVICE"),
        1 => menu("CONTROL CENTER", "SETTINGS"),
        2 => menu("CONTROL CENTER", "SLEEP"),
        _ => menu("CONTROL CENTER", "CLOSE"),
    }
}

const fn menu(title: &'static str, item: &'static str) -> ScreenCopy {
    copy(
        title,
        item,
        "LEFT / RIGHT TO MOVE",
        "BOTH = ENTER",
        "<",
        ">",
    )
}

const fn review_copy(index: u8) -> ScreenCopy {
    match index {
        0 => copy(
            "REVIEW TRANSACTION",
            "BITCOIN · 1 OF 5",
            "SCROLL EVERY FIELD",
            "RIGHT = NEXT",
            "<",
            ">",
        ),
        1 => copy(
            "AMOUNT",
            "0.10 BTC",
            "NETWORK: BITCOIN",
            "VERIFY ON DEVICE",
            "<",
            ">",
        ),
        2 => copy(
            "RECIPIENT",
            "BC1Q...7X2",
            "FEE 0.00012 BTC",
            "VERIFY ON DEVICE",
            "<",
            ">",
        ),
        3 => copy(
            "APPROVE",
            "SIGN THIS TRANSACTION",
            "PRIVATE KEY STAYS INSIDE",
            "PRESS BOTH BUTTONS",
            "<",
            ">",
        ),
        _ => copy(
            "REJECT",
            "CANCEL THIS REQUEST",
            "NO PRIVATE-KEY OPERATION",
            "PRESS BOTH BUTTONS",
            "<",
            ">",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardware_wallet_core::{OperationStage, RejectReason};

    fn provisioned_demo() -> WalletDemo {
        let mut demo = WalletDemo::new();
        demo.press(Button::Both);
        demo.press(Button::Both);
        for _ in 0..PIN_DIGITS * 2 {
            demo.press(Button::Both);
        }
        assert_eq!(demo.screen(), ScreenState::RecoveryIntro);
        demo.press(Button::Both);
        for _ in 0..23 {
            demo.press(Button::Right);
        }
        demo.press(Button::Both);
        for _ in 0..2 {
            demo.press(Button::Right);
        }
        demo.press(Button::Both);
        for _ in 0..2 {
            demo.press(Button::Right);
        }
        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::SetupComplete);
        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::Dashboard);
        demo
    }

    #[test]
    fn onboarding_creates_pin_shows_24_words_and_verifies_backup() {
        let demo = provisioned_demo();
        assert!(demo.setup_complete());
        assert!(demo.state().is_unlocked());
        assert_eq!(demo.frame().copy.title, "DASHBOARD");
    }

    #[test]
    fn both_buttons_are_required_to_authorize_signing() {
        let mut demo = provisioned_demo();
        demo.press(Button::Both);
        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::Review);
        assert!(matches!(
            demo.state().flow(),
            FlowState::Operation(operation)
                if matches!(operation.stage, OperationStage::Reviewing { .. })
        ));

        for _ in 0..3 {
            demo.press(Button::Right);
        }
        assert_eq!(demo.screen(), ScreenState::Review);
        assert_ne!(demo.last_effect(), Effect::ExecuteOperation(OPERATION));

        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::Signing);
        assert_eq!(demo.last_effect(), Effect::ExecuteOperation(OPERATION));
        demo.tick(180);
        assert_eq!(demo.screen(), ScreenState::Signed);
    }

    #[test]
    fn reject_page_never_executes_private_key_work() {
        let mut demo = provisioned_demo();
        demo.press(Button::Both);
        demo.press(Button::Both);
        for _ in 0..4 {
            demo.press(Button::Right);
        }
        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::Rejected);
        assert_eq!(
            demo.last_effect(),
            Effect::RejectOperation {
                id: OPERATION,
                reason: RejectReason::UserRejected,
            }
        );
    }

    #[test]
    fn sleep_locks_and_a_gpio_gesture_returns_to_pin_entry() {
        let mut demo = provisioned_demo();
        demo.press(Button::Right);
        demo.press(Button::Both);
        demo.press(Button::Right);
        demo.press(Button::Right);
        demo.press(Button::Both);
        demo.press(Button::Both);
        assert_eq!(demo.screen(), ScreenState::Sleeping);
        assert!(!demo.state().is_unlocked());

        demo.press(Button::Left);
        assert_eq!(demo.screen(), ScreenState::Locked);
        assert_eq!(demo.wake_count(), 1);
        demo.press(Button::Both);
        for _ in 0..PIN_DIGITS {
            demo.press(Button::Both);
        }
        assert_eq!(demo.screen(), ScreenState::Dashboard);
        assert!(demo.state().is_unlocked());
    }

    #[test]
    fn frame_flags_publish_display_sleep_and_setup_state() {
        let mut demo = provisioned_demo();
        demo.press(Button::Right);
        demo.press(Button::Both);
        demo.press(Button::Right);
        demo.press(Button::Right);
        demo.press(Button::Both);
        demo.press(Button::Both);
        let frame = demo.frame();
        let mut encoded = [0_u8; FRAME_CAPACITY];
        let length = frame.encode(&mut encoded);
        assert!(length <= FRAME_CAPACITY);
        assert_eq!(&encoded[..4], b"WLT1");
        assert_eq!(encoded[4], FRAME_VERSION);
        assert_ne!(encoded[6] & (1 << 4), 0);
        assert_eq!(encoded[6] & (1 << 3), 0);
        assert_ne!(encoded[6] & (1 << 5), 0);
    }
}

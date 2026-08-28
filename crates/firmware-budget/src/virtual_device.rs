//! Deterministic virtual hardware exercised by the real Cortex-M firmware in CI.
//!
//! This is intentionally a tiny behavioral model. It proves firmware-visible
//! semantics for input, display, entropy, atomic persistence and the secure
//! element boundary without pretending to model electrical or side-channel
//! behavior.

use core::sync::atomic::{AtomicU32, Ordering};

const FVD1_MAGIC: u32 = 0x3144_5646;
const FVD1_VERSION: u32 = 1;
const FVD1_BYTES: u32 = 64;
const STATUS_RUNNING: u32 = 0;
const STATUS_PASS: u32 = 1;
const STATUS_FAIL: u32 = 2;
const CAP_BUTTONS: u32 = 1;
const CAP_DISPLAY: u32 = 2;
const CAP_TRNG: u32 = 4;
const CAP_STORAGE: u32 = 8;
const CAP_SECURE_ELEMENT: u32 = 16;
const ALL_CAPABILITIES: u32 =
    CAP_BUTTONS | CAP_DISPLAY | CAP_TRNG | CAP_STORAGE | CAP_SECURE_ELEMENT;

// FVD1 is deliberately an array of atomics: the symbol is writable RAM while
// the repository-wide `unsafe_code = "forbid"` invariant remains intact.
#[used]
#[allow(non_upper_case_globals)]
pub static firmverse_device_trace: [AtomicU32; 16] = [
    AtomicU32::new(FVD1_MAGIC),
    AtomicU32::new(FVD1_VERSION),
    AtomicU32::new(FVD1_BYTES),
    AtomicU32::new(STATUS_RUNNING),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

#[derive(Clone, Copy)]
enum Button {
    Left,
    Right,
}

struct VirtualButtons {
    consumed: u32,
}

impl VirtualButtons {
    const fn new() -> Self {
        Self { consumed: 0 }
    }

    fn consume(&mut self, button: Button) -> u8 {
        self.consumed += 1;
        match button {
            Button::Left => 0x4c,
            Button::Right => 0x52,
        }
    }
}

struct VirtualDisplay {
    framebuffer: [u8; 128 * 64 / 8],
    frames: u32,
    digest: u32,
}

impl VirtualDisplay {
    const fn new() -> Self {
        Self {
            framebuffer: [0; 128 * 64 / 8],
            frames: 0,
            digest: 0,
        }
    }

    fn present(&mut self, seed: u8) {
        let mut index = 0;
        while index < self.framebuffer.len() {
            let lane = u8::try_from(index & 0xff).unwrap_or(0);
            self.framebuffer[index] = seed.rotate_left((index & 7) as u32) ^ lane;
            index += 1;
        }
        self.frames += 1;
        self.digest = digest(&self.framebuffer);
    }
}

struct VirtualTrng {
    state: u32,
    produced: u32,
}

impl VirtualTrng {
    fn new(seed: u8) -> Self {
        Self {
            state: 0x9e37_79b9 ^ u32::from(seed),
            produced: 0,
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output.iter_mut() {
            let mut value = self.state;
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            self.state = value;
            *byte = value as u8;
            self.produced += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    digest: u32,
    valid: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 0,
        digest: 0,
        valid: false,
    };
}

struct AtomicStore {
    slots: [Slot; 2],
    commits: u32,
}

impl AtomicStore {
    const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; 2],
            commits: 0,
        }
    }

    fn commit(&mut self, payload: &[u8]) {
        let next_generation = self.selected().map_or(1, |slot| slot.generation + 1);
        let target = usize::try_from((next_generation - 1) & 1).unwrap_or(0);

        // A record becomes selectable only after all fields are populated.
        self.slots[target].valid = false;
        self.slots[target].generation = next_generation;
        self.slots[target].digest = digest(payload);
        self.slots[target].valid = true;
        self.commits += 1;
    }

    fn selected(&self) -> Option<Slot> {
        self.slots
            .iter()
            .copied()
            .filter(|slot| slot.valid)
            .max_by_key(|slot| slot.generation)
    }
}

struct SecureElementBoundary {
    operations: u32,
    response_digest: u32,
}

impl SecureElementBoundary {
    const fn new() -> Self {
        Self {
            operations: 0,
            response_digest: 0,
        }
    }

    fn authorize(&mut self, request_digest: u32, physical_confirmed: bool) -> bool {
        self.operations += 1;
        let response = if physical_confirmed {
            request_digest ^ 0xa55a_5aa5
        } else {
            0
        };
        self.response_digest = digest(&response.to_le_bytes());
        physical_confirmed
    }
}

pub fn run(selector: u8) -> bool {
    reset_trace();

    let mut buttons = VirtualButtons::new();
    let left = buttons.consume(Button::Left);
    let right = buttons.consume(Button::Right);
    let confirm = buttons.consume(Button::Right);

    let mut display = VirtualDisplay::new();
    display.present(selector ^ left);
    display.present(selector ^ right ^ confirm);

    let mut trng = VirtualTrng::new(selector);
    let mut entropy = [0_u8; 32];
    trng.fill(&mut entropy);
    let entropy_digest = digest(&entropy);

    let mut storage = AtomicStore::new();
    storage.commit(&entropy[..16]);
    storage.commit(&entropy[16..]);
    let selected = match storage.selected() {
        Some(slot) => slot,
        None => return fail(1),
    };
    if selected.generation != 2 || storage.commits != 2 {
        return fail(2);
    }

    let request_digest = display.digest ^ entropy_digest ^ selected.digest;
    let mut secure_element = SecureElementBoundary::new();
    if !secure_element.authorize(request_digest, confirm == 0x52) {
        return fail(3);
    }

    // Keep the existing domain/crypto lifecycle probe as part of the same real
    // firmware execution. Virtual hardware is not a substitute for domain tests.
    if !super::firmverse_self_test(selector) {
        return fail(4);
    }

    store(4, ALL_CAPABILITIES);
    store(5, buttons.consumed);
    store(6, display.frames);
    store(7, display.digest);
    store(8, trng.produced);
    store(9, entropy_digest);
    store(10, storage.commits);
    store(11, selected.generation);
    store(12, selected.digest);
    store(13, secure_element.operations);
    store(14, secure_element.response_digest);
    store(15, 0);
    store(3, STATUS_PASS);
    true
}

fn reset_trace() {
    store(0, FVD1_MAGIC);
    store(1, FVD1_VERSION);
    store(2, FVD1_BYTES);
    store(3, STATUS_RUNNING);
    for word in 4..16 {
        store(word, 0);
    }
}

fn fail(code: u32) -> bool {
    store(15, code);
    store(3, STATUS_FAIL);
    false
}

fn store(word: usize, value: u32) {
    firmverse_device_trace[word].store(value, Ordering::SeqCst);
}

fn digest(bytes: &[u8]) -> u32 {
    let mut value = 0x811c_9dc5_u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        value = value.wrapping_mul(0x0100_0193);
    }
    value
}

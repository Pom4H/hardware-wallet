#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use cortex_m_rt::entry;
use hardware_wallet_browser_demo::{Button, FRAME_CAPACITY, WalletDemo};
use panic_halt as _;

const GPIO_BASE: usize = 0x4000_8000;
const GPIO_DR: usize = GPIO_BASE;
const GPIO_DDR: usize = GPIO_BASE + 0x04;
const GPIO_EXT: usize = GPIO_BASE + 0x50;

const PIN_LED: u32 = 7; // PB-03F P11
const PIN_LEFT: u32 = 8; // PB-03F P14
const PIN_RIGHT: u32 = 10; // PB-03F P16
const MASK_LEFT: u32 = 1 << PIN_LEFT;
const MASK_RIGHT: u32 = 1 << PIN_RIGHT;
const MASK_BUTTONS: u32 = MASK_LEFT | MASK_RIGHT;
const CONTROL_CENTER_HOLD_MS: u32 = 1_500;

const MAILBOX_BASE: usize = 0x2000_0000;
const MAILBOX_MAGIC: usize = MAILBOX_BASE;
const MAILBOX_TX_SEQ: usize = MAILBOX_BASE + 272;
const MAILBOX_TX_LEN: usize = MAILBOX_BASE + 276;
const MAILBOX_TX: usize = MAILBOX_BASE + 280;
const MAILBOX_TICK_MS: usize = MAILBOX_BASE + 536;
const MAGIC_PHY2: u32 = 0x5048_5932;

#[entry]
fn main() -> ! {
    mmio_write(GPIO_DDR, 1 << PIN_LED);
    mmio_write(GPIO_DR, 1 << PIN_LED);
    mmio_write(MAILBOX_MAGIC, MAGIC_PHY2);

    let mut demo = WalletDemo::new();
    let mut last_frame_sequence = u8::MAX;
    let mut previous_tick = mmio_read(MAILBOX_TICK_MS);
    let mut gesture_mask = 0_u32;
    let mut gesture_started = 0_u32;
    let mut long_gesture_sent = false;

    loop {
        let now = mmio_read(MAILBOX_TICK_MS);
        let elapsed = now.wrapping_sub(previous_tick).min(u32::from(u16::MAX));
        if elapsed != 0 {
            previous_tick = now;
            demo.tick(elapsed as u16);
        }

        let active = mmio_read(GPIO_EXT) & MASK_BUTTONS;
        if active != 0 {
            if gesture_mask == 0 {
                gesture_started = now;
                long_gesture_sent = false;
            }
            gesture_mask |= active;
            if gesture_mask == MASK_BUTTONS
                && !long_gesture_sent
                && now.wrapping_sub(gesture_started) >= CONTROL_CENTER_HOLD_MS
            {
                demo.press(Button::BothHeld);
                long_gesture_sent = true;
            }
        } else if gesture_mask != 0 {
            if !long_gesture_sent {
                demo.press(match gesture_mask {
                    MASK_LEFT => Button::Left,
                    MASK_RIGHT => Button::Right,
                    _ => Button::Both,
                });
            }
            gesture_mask = 0;
            long_gesture_sent = false;
        }

        let frame = demo.frame();
        if frame.sequence != last_frame_sequence {
            last_frame_sequence = frame.sequence;
            let mut encoded = [0_u8; FRAME_CAPACITY];
            let length = frame.encode(&mut encoded);
            mailbox_send(&encoded[..length]);
        }

        // The LED reports that firmware is alive. Signing uses a slow blink;
        // sleep turns it off before the Cortex-M executes WFI.
        let led_on = if demo.sleeping() {
            false
        } else if demo.screen().signing_active() {
            (now / 80) & 1 == 0
        } else {
            true
        };
        mmio_write(GPIO_DR, if led_on { 1 << PIN_LED } else { 0 });

        if demo.sleeping() {
            // Firmverse now preserves the architectural WFI state until a
            // rising GPIO edge arrives. The same P14/P16 input that wakes the
            // core is then consumed by the firmware gesture recognizer above.
            cortex_m::asm::wfi();
        } else {
            cortex_m::asm::nop();
        }
    }
}

fn mailbox_send(payload: &[u8]) {
    let length = payload.len().min(256);
    for (index, byte) in payload.iter().copied().take(length).enumerate() {
        mmio_write_u8(MAILBOX_TX + index, byte);
    }
    mmio_write(MAILBOX_TX_LEN, length as u32);
    let sequence = mmio_read(MAILBOX_TX_SEQ).wrapping_add(1);
    mmio_write(MAILBOX_TX_SEQ, sequence);
}

fn mmio_read(address: usize) -> u32 {
    // SAFETY: these addresses are the documented Firmverse PHY6252 MMIO and
    // mailbox surfaces. Access is volatile and confined to this target binary.
    unsafe { read_volatile(address as *const u32) }
}

fn mmio_write(address: usize, value: u32) {
    // SAFETY: see `mmio_read`; the target owns these writable MMIO registers.
    unsafe { write_volatile(address as *mut u32, value) }
}

fn mmio_write_u8(address: usize, value: u8) {
    // SAFETY: the mailbox payload region is byte-addressable writable SRAM.
    unsafe { write_volatile(address as *mut u8, value) }
}

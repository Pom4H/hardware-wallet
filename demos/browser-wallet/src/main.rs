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
    let mut previous_inputs = 0_u32;
    let mut previous_tick = mmio_read(MAILBOX_TICK_MS);

    loop {
        let now = mmio_read(MAILBOX_TICK_MS);
        let elapsed = now.wrapping_sub(previous_tick).min(u32::from(u16::MAX));
        if elapsed != 0 {
            previous_tick = now;
            demo.tick(elapsed as u16);
        }

        let inputs = mmio_read(GPIO_EXT);
        let rising = inputs & !previous_inputs;
        previous_inputs = inputs;

        if rising & (1 << PIN_LEFT) != 0 {
            demo.press(Button::Left);
        }
        if rising & (1 << PIN_RIGHT) != 0 {
            demo.press(Button::Right);
        }

        let frame = demo.frame();
        if frame.sequence != last_frame_sequence {
            last_frame_sequence = frame.sequence;
            let mut encoded = [0_u8; FRAME_CAPACITY];
            let length = frame.encode(&mut encoded);
            mailbox_send(&encoded[..length]);
        }

        // The LED reports that firmware is alive. Signing uses a slow blink so
        // the physical twin and electrical model can expose the extra load.
        let led_on = if demo.screen().signing_active() {
            (now / 80) & 1 == 0
        } else {
            true
        };
        mmio_write(GPIO_DR, if led_on { 1 << PIN_LED } else { 0 });
        cortex_m::asm::nop();
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

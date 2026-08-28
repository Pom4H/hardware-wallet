from __future__ import annotations

import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import firmverse_measurement


def config() -> dict:
    return {
        "projection": {
            "ram_alignment_bytes": 1024,
            "ram_margin_percent": 25,
            "stack_high_water_margin_percent": 50,
            "provisional_stack_bytes": 32 * 1024,
            "interrupt_stack_reserve_bytes": 4 * 1024,
            "platform_static_ram_reserve_bytes": 8 * 1024,
            "transport_buffers_bytes": 8 * 1024,
            "display_framebuffer_bytes": 1024,
            "storage_scratch_bytes": 4 * 1024,
            "future_ram_reserve_bytes": 8 * 1024,
        },
        "classes": {"ram_kib": [32, 64, 96, 128, 256]},
    }


class FirmverseMeasurementTests(unittest.TestCase):
    def test_parses_machine_probe_line(self) -> None:
        probe = firmverse_measurement.parse_probe_line(
            "PROBE status=ok board=hardware-wallet-dev soc=cortex-m4-generic "
            "profile=zmu/cortex-m4 instructions=1234 cycles=2468 stack_used=8192 "
            "stack_window=262144 stack_saturated=false initial_sp=0x20080000 "
            "pc=0x08001234 exit_code=0 strict=true reason=semihost-0"
        )
        self.assertEqual(probe.instructions, 1234)
        self.assertEqual(probe.cycles, 2468)
        self.assertEqual(probe.stack_used_bytes, 8192)
        self.assertEqual(probe.initial_sp, 0x20080000)
        self.assertTrue(probe.strict)

    def test_replaces_provisional_stack_with_measured_high_water(self) -> None:
        probe = firmverse_measurement.parse_probe_line(
            "PROBE status=ok board=hardware-wallet-dev soc=cortex-m4-generic "
            "profile=zmu/cortex-m4 instructions=1000 cycles=2000 stack_used=8192 "
            "stack_window=262144 stack_saturated=false initial_sp=0x20080000 "
            "pc=0x08001000 exit_code=0 strict=true reason=semihost-0"
        )
        measurement = firmverse_measurement.calculate(probe, config(), 0)
        self.assertEqual(measurement.measured_stack_allowance_bytes, 12 * 1024)
        self.assertEqual(measurement.ram_required_bytes, 57 * 1024)
        self.assertEqual(measurement.recommended_ram_kib, 64)
        self.assertEqual(measurement.errors, ())

    def test_fails_closed_for_saturated_or_oversized_stack(self) -> None:
        probe = firmverse_measurement.parse_probe_line(
            "PROBE status=ok board=hardware-wallet-dev soc=cortex-m4-generic "
            "profile=zmu/cortex-m4 instructions=1000 cycles=2000 stack_used=40000 "
            "stack_window=40000 stack_saturated=true initial_sp=0x20080000 "
            "pc=0x08001000 exit_code=0 strict=true reason=semihost-0"
        )
        measurement = firmverse_measurement.calculate(probe, config(), 0)
        self.assertTrue(any("bottom" in error for error in measurement.errors))
        self.assertTrue(any("provisional gate" in error for error in measurement.errors))


if __name__ == "__main__":
    unittest.main()

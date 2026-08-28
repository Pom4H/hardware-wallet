from __future__ import annotations

import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import hardware_budget
import mcu_candidate


def budget_config() -> dict:
    return {
        "schema": 1,
        "memory": {
            "flash_origin": 0x08000000,
            "flash_length": 2 * 1024 * 1024,
            "ram_origin": 0x20000000,
            "ram_length": 512 * 1024,
        },
        "limits": {
            "probe_flash_min_bytes": 64 * 1024,
            "probe_flash_max_bytes": 256 * 1024,
            "probe_static_ram_max_bytes": 16 * 1024,
        },
        "projection": {
            "flash_alignment_bytes": 4096,
            "ram_alignment_bytes": 1024,
            "flash_margin_percent": 25,
            "ram_margin_percent": 25,
            "bootloader_flash_bytes": 32 * 1024,
            "persistent_flash_bytes": 16 * 1024,
            "platform_flash_reserve_bytes": 64 * 1024,
            "future_flash_reserve_bytes": 64 * 1024,
            "firmware_slots": 2,
            "provisional_stack_bytes": 32 * 1024,
            "interrupt_stack_reserve_bytes": 4 * 1024,
            "platform_static_ram_reserve_bytes": 8 * 1024,
            "transport_buffers_bytes": 8 * 1024,
            "display_framebuffer_bytes": 1024,
            "storage_scratch_bytes": 4 * 1024,
            "future_ram_reserve_bytes": 8 * 1024,
        },
        "classes": {
            "flash_kib": [256, 512, 1024, 2048],
            "ram_kib": [32, 64, 96, 128, 256],
        },
        "latency_targets": {
            "boot_to_ready_ms": 250,
            "transaction_parse_ms": 100,
            "bip39_context_ms": 1500,
            "secp256k1_sign_ms": 500,
            "ed25519_sign_ms": 250,
        },
    }


class HardwareBudgetTests(unittest.TestCase):
    def test_parse_and_classify_sections(self) -> None:
        output = """
section             size       addr
.vector_table       1024       134217728
.text               169296     134218752
.rodata             61524      134388048
.data               128        536870912
.bss                256        536871040
.uninit             64         536871296
Total               232292
"""
        sections = hardware_budget.parse_llvm_size(output)
        flash, static_ram = hardware_budget.classify_sections(
            sections, budget_config()
        )
        self.assertEqual(flash, 1024 + 169296 + 61524 + 128)
        self.assertEqual(static_ram, 128 + 256 + 64)

    def test_projection_selects_expected_classes(self) -> None:
        sections = [
            hardware_budget.Section(".text", 170 * 1024, 0x08000400),
            hardware_budget.Section(".rodata", 58 * 1024, 0x0802AC00),
            hardware_budget.Section(".bss", 4 * 1024, 0x20000000),
        ]
        budget = hardware_budget.calculate("probe", sections, budget_config())
        self.assertEqual(budget.recommended_single_slot_flash_kib, 512)
        self.assertEqual(budget.recommended_ab_flash_kib, 1024)
        self.assertEqual(budget.recommended_ram_kib, 96)
        self.assertEqual(hardware_budget.validation_errors(budget), [])

    def test_zero_mapped_flash_is_rejected(self) -> None:
        sections = [hardware_budget.Section(".text", 1000, 0)]
        budget = hardware_budget.calculate("broken", sections, budget_config())
        errors = hardware_budget.validation_errors(budget)
        self.assertTrue(any("sanity floor" in error for error in errors))


class McuCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements = {
            "selection": {
                "flash_mode": "ab",
                "flash_floor_bytes": 1024 * 1024,
                "ram_floor_bytes": 128 * 1024,
                "min_clock_mhz": 0,
            },
            "required": {
                "architectures": [
                    "thumbv7em-none-eabi",
                    "thumbv8m.main-none-eabi",
                ],
                "boolean_capabilities": [
                    "usb_fs_device",
                    "device_entropy",
                    "independent_watchdog",
                    "brownout_reset",
                    "production_debug_lock",
                    "signed_boot_path",
                    "unique_device_identity_path",
                ],
                "minimum_counts": {
                    "spi_buses": 1,
                    "gpio_count": 8,
                },
            },
            "preferred": {
                "weights": {
                    "trustzone_m": 3,
                    "dual_bank_flash": 3,
                    "mpu": 2,
                }
            },
        }
        self.budget = {
            "single_slot_flash_required_bytes": 500 * 1024,
            "ab_flash_required_bytes": 944 * 1024,
            "ram_required_bytes": 82 * 1024,
        }

    def test_candidate_passes_hard_requirements(self) -> None:
        candidate = {
            "name": "example",
            "architecture": "thumbv8m.main-none-eabi",
            "flash_bytes": 1024 * 1024,
            "ram_bytes": 128 * 1024,
            "capabilities": {
                "usb_fs_device": True,
                "device_entropy": True,
                "independent_watchdog": True,
                "brownout_reset": True,
                "production_debug_lock": True,
                "signed_boot_path": True,
                "unique_device_identity_path": True,
                "spi_buses": 2,
                "gpio_count": 32,
                "trustzone_m": True,
                "dual_bank_flash": True,
                "mpu": True,
            },
        }
        checks, score, maximum = mcu_candidate.evaluate(
            self.requirements, self.budget, candidate
        )
        self.assertTrue(all(check.passed for check in checks))
        self.assertEqual((score, maximum), (8, 8))

    def test_candidate_fails_memory_and_entropy(self) -> None:
        candidate = {
            "name": "too-small",
            "architecture": "thumbv7em-none-eabi",
            "flash_bytes": 512 * 1024,
            "ram_bytes": 64 * 1024,
            "capabilities": {
                "usb_fs_device": True,
                "device_entropy": False,
                "independent_watchdog": True,
                "brownout_reset": True,
                "production_debug_lock": True,
                "signed_boot_path": True,
                "unique_device_identity_path": True,
                "spi_buses": 1,
                "gpio_count": 8,
            },
        }
        checks, _, _ = mcu_candidate.evaluate(
            self.requirements, self.budget, candidate
        )
        failed = {check.name for check in checks if not check.passed}
        self.assertEqual(failed, {"flash", "ram", "device_entropy"})


if __name__ == "__main__":
    unittest.main()

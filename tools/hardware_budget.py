#!/usr/bin/env python3
"""Turn a linked Cortex-M probe ELF into a conservative MCU memory budget."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Section:
    name: str
    size: int
    address: int


@dataclass(frozen=True)
class Budget:
    target: str
    probe_flash_bytes: int
    probe_static_ram_bytes: int
    probe_flash_limit_bytes: int
    probe_static_ram_limit_bytes: int
    firmware_slot_bytes: int
    single_slot_flash_required_bytes: int
    ab_flash_required_bytes: int
    ram_required_bytes: int
    recommended_single_slot_flash_kib: int
    recommended_ab_flash_kib: int
    recommended_ram_kib: int
    stack_bytes_status: str


def parse_number(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    if any(character in "abcdefABCDEF" for character in value):
        return int(value, 16)
    return int(value, 10)


def parse_llvm_size(output: str) -> list[Section]:
    sections: list[Section] = []
    for raw_line in output.splitlines():
        fields = raw_line.split()
        if len(fields) != 3 or fields[0] in {"section", "Total"}:
            continue
        try:
            size = parse_number(fields[1])
            address = parse_number(fields[2])
        except ValueError:
            continue
        sections.append(Section(fields[0], size, address))
    if not sections:
        raise ValueError("llvm-size produced no parseable sections")
    return sections


def in_range(address: int, origin: int, length: int) -> bool:
    return origin <= address < origin + length


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("alignment must be positive")
    return ((value + alignment - 1) // alignment) * alignment


def with_margin(value: int, percent: int) -> int:
    return math.ceil(value * (100 + percent) / 100)


def next_class(required_bytes: int, classes_kib: Iterable[int]) -> int:
    required_kib = math.ceil(required_bytes / 1024)
    for candidate in classes_kib:
        if candidate >= required_kib:
            return candidate
    return required_kib


def kib(value: int) -> str:
    return f"{value / 1024:.1f} KiB"


def classify_sections(sections: list[Section], config: dict) -> tuple[int, int]:
    memory = config["memory"]
    flash_origin = int(memory["flash_origin"])
    flash_length = int(memory["flash_length"])
    ram_origin = int(memory["ram_origin"])
    ram_length = int(memory["ram_length"])

    flash = 0
    static_ram = 0
    data_load_image = 0
    for section in sections:
        if in_range(section.address, flash_origin, flash_length):
            flash += section.size
        if in_range(section.address, ram_origin, ram_length):
            static_ram += section.size
            if section.name == ".data" or section.name.startswith(".data."):
                data_load_image += section.size

    # Initialized RAM is present both in RAM at runtime and in the flash load image.
    return flash + data_load_image, static_ram


def calculate(target: str, sections: list[Section], config: dict) -> Budget:
    probe_flash, probe_static_ram = classify_sections(sections, config)
    limits = config["limits"]
    projection = config["projection"]
    classes = config["classes"]

    slot_payload = (
        probe_flash
        + int(projection["platform_flash_reserve_bytes"])
        + int(projection["future_flash_reserve_bytes"])
    )
    firmware_slot = align_up(
        with_margin(slot_payload, int(projection["flash_margin_percent"])),
        int(projection["flash_alignment_bytes"]),
    )
    fixed_flash = int(projection["bootloader_flash_bytes"]) + int(
        projection["persistent_flash_bytes"]
    )
    single_slot_flash = align_up(
        fixed_flash + firmware_slot,
        int(projection["flash_alignment_bytes"]),
    )
    ab_flash = align_up(
        fixed_flash + firmware_slot * int(projection["firmware_slots"]),
        int(projection["flash_alignment_bytes"]),
    )

    ram_payload = (
        probe_static_ram
        + int(projection["provisional_stack_bytes"])
        + int(projection["interrupt_stack_reserve_bytes"])
        + int(projection["platform_static_ram_reserve_bytes"])
        + int(projection["transport_buffers_bytes"])
        + int(projection["display_framebuffer_bytes"])
        + int(projection["storage_scratch_bytes"])
        + int(projection["future_ram_reserve_bytes"])
    )
    required_ram = align_up(
        with_margin(ram_payload, int(projection["ram_margin_percent"])),
        int(projection["ram_alignment_bytes"]),
    )

    return Budget(
        target=target,
        probe_flash_bytes=probe_flash,
        probe_static_ram_bytes=probe_static_ram,
        probe_flash_limit_bytes=int(limits["probe_flash_max_bytes"]),
        probe_static_ram_limit_bytes=int(limits["probe_static_ram_max_bytes"]),
        firmware_slot_bytes=firmware_slot,
        single_slot_flash_required_bytes=single_slot_flash,
        ab_flash_required_bytes=ab_flash,
        ram_required_bytes=required_ram,
        recommended_single_slot_flash_kib=next_class(single_slot_flash, classes["flash_kib"]),
        recommended_ab_flash_kib=next_class(ab_flash, classes["flash_kib"]),
        recommended_ram_kib=next_class(required_ram, classes["ram_kib"]),
        stack_bytes_status=(
            f"provisional {projection['provisional_stack_bytes']} bytes; replace with "
            "Firmverse/HIL high-water measurement"
        ),
    )


def render_markdown(budget: Budget, config: dict, sections: list[Section]) -> str:
    latency = config["latency_targets"]
    memory = config["memory"]
    mapped = [
        section
        for section in sections
        if in_range(
            section.address,
            int(memory["flash_origin"]),
            int(memory["flash_length"]),
        )
        or in_range(
            section.address,
            int(memory["ram_origin"]),
            int(memory["ram_length"]),
        )
    ]
    largest = sorted(mapped, key=lambda section: section.size, reverse=True)[:10]
    lines = [
        f"# Hardware budget — `{budget.target}`",
        "",
        "## Measured linked probe",
        "",
        "| Metric | Value | CI ceiling |",
        "| --- | ---: | ---: |",
        f"| Flash image | {kib(budget.probe_flash_bytes)} | {kib(budget.probe_flash_limit_bytes)} |",
        f"| Static RAM (`.data + .bss + .uninit`) | {kib(budget.probe_static_ram_bytes)} | {kib(budget.probe_static_ram_limit_bytes)} |",
        "",
        "The probe links the domain, BIP-39 lifecycle, BIP-32/SLIP-0010, both signing backends, and all three chain adapters. It deliberately excludes the not-yet-written USB, display, bootloader, board HAL, secure-element driver, and production storage implementation.",
        "",
        "## Projected chip-selection floor",
        "",
        "| Configuration | Calculated requirement | Next normal MCU class |",
        "| --- | ---: | ---: |",
        f"| Single firmware slot | {kib(budget.single_slot_flash_required_bytes)} Flash | {budget.recommended_single_slot_flash_kib} KiB Flash |",
        f"| A/B rollback-safe update | {kib(budget.ab_flash_required_bytes)} Flash | {budget.recommended_ab_flash_kib} KiB Flash |",
        f"| Runtime memory | {kib(budget.ram_required_bytes)} RAM | {budget.recommended_ram_kib} KiB RAM |",
        "",
        f"Stack allowance: **{budget.stack_bytes_status}**.",
        "",
        "## Latency acceptance targets",
        "",
        f"- boot to ready: {latency['boot_to_ready_ms']} ms",
        f"- parse and prepare a transaction review: {latency['transaction_parse_ms']} ms",
        f"- open a BIP-39/passphrase context: {latency['bip39_context_ms']} ms",
        f"- derive and sign with secp256k1: {latency['secp256k1_sign_ms']} ms",
        f"- derive and sign with Ed25519: {latency['ed25519_sign_ms']} ms",
        "",
        "Clock frequency is not inferred from host timing. Firmverse or hardware must measure target cycles; required MHz is `ceil(worst_case_cycles / latency_budget_us)`.",
        "",
        "## Largest ELF sections",
        "",
        "| Section | Bytes | Address |",
        "| --- | ---: | ---: |",
    ]
    lines.extend(
        f"| `{section.name}` | {section.size} | `0x{section.address:08x}` |"
        for section in largest
    )
    lines.extend(
        [
            "",
            "## Confidence",
            "",
            "- linked Flash and static RAM: measured from the actual Cortex-M ELF;",
            "- platform reserves and future-feature margin: explicit policy inputs;",
            "- stack: provisional until scenario high-water tests exist;",
            "- execution speed and peak current: not measured by this report.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--llvm-size", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    with args.config.open("rb") as source:
        config = tomllib.load(source)
    if int(config.get("schema", 0)) != 1:
        raise ValueError("unsupported hardware budget schema")

    completed = subprocess.run(
        [str(args.llvm_size), "--format=sysv", str(args.elf)],
        check=True,
        capture_output=True,
        text=True,
    )
    sections = parse_llvm_size(completed.stdout)
    budget = calculate(args.target, sections, config)

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(asdict(budget), indent=2) + "\n", encoding="utf-8")
    report = render_markdown(budget, config, sections)
    args.markdown.write_text(report, encoding="utf-8")
    print(report)

    failed = False
    if budget.probe_flash_bytes > budget.probe_flash_limit_bytes:
        print("probe Flash exceeds CI ceiling", file=sys.stderr)
        failed = True
    if budget.probe_static_ram_bytes > budget.probe_static_ram_limit_bytes:
        print("probe static RAM exceeds CI ceiling", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate a Firmverse Cortex-M probe and project measured runtime RAM."""

from __future__ import annotations

import argparse
import json
import math
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Probe:
    status: str
    board: str
    soc: str
    profile: str
    instructions: int
    cycles: int
    stack_used_bytes: int
    stack_window_bytes: int
    stack_saturated: bool
    initial_sp: int
    pc: int
    exit_code: int
    strict: bool
    reason: str


@dataclass(frozen=True)
class Measurement:
    probe: Probe
    static_ram_bytes: int
    provisional_stack_gate_bytes: int
    measured_stack_allowance_bytes: int
    ram_required_bytes: int
    recommended_ram_kib: int
    cycles_per_instruction: float
    errors: tuple[str, ...]


def parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"invalid boolean {value!r}")


def parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def parse_probe_line(line: str) -> Probe:
    if not line.startswith("PROBE "):
        raise ValueError("Firmverse line must start with 'PROBE '")
    fields: dict[str, str] = {}
    for token in line.removeprefix("PROBE ").strip().split():
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError(f"invalid PROBE token {token!r}")
        fields[key] = value

    required = {
        "status",
        "board",
        "soc",
        "profile",
        "instructions",
        "cycles",
        "stack_used",
        "stack_window",
        "stack_saturated",
        "initial_sp",
        "pc",
        "exit_code",
        "strict",
        "reason",
    }
    missing = sorted(required - fields.keys())
    if missing:
        raise ValueError(f"missing PROBE fields: {', '.join(missing)}")

    return Probe(
        status=fields["status"],
        board=fields["board"],
        soc=fields["soc"],
        profile=fields["profile"],
        instructions=parse_int(fields["instructions"]),
        cycles=parse_int(fields["cycles"]),
        stack_used_bytes=parse_int(fields["stack_used"]),
        stack_window_bytes=parse_int(fields["stack_window"]),
        stack_saturated=parse_bool(fields["stack_saturated"]),
        initial_sp=parse_int(fields["initial_sp"]),
        pc=parse_int(fields["pc"]),
        exit_code=parse_int(fields["exit_code"]),
        strict=parse_bool(fields["strict"]),
        reason=fields["reason"],
    )


def read_probe(log: Path) -> Probe:
    lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("PROBE ")]
    if not lines:
        raise ValueError(f"{log} contains no Firmverse PROBE result")
    return parse_probe_line(lines[-1])


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("alignment must be positive")
    return ((value + alignment - 1) // alignment) * alignment


def with_margin(value: int, percent: int) -> int:
    if percent < 0:
        raise ValueError("margin cannot be negative")
    return math.ceil(value * (100 + percent) / 100)


def next_class(required_bytes: int, classes_kib: list[int]) -> int:
    required_kib = math.ceil(required_bytes / 1024)
    for candidate in classes_kib:
        if candidate >= required_kib:
            return candidate
    return required_kib


def calculate(probe: Probe, config: dict, static_ram_bytes: int) -> Measurement:
    projection = config["projection"]
    classes = config["classes"]
    stack_margin = int(projection.get("stack_high_water_margin_percent", 50))
    ram_alignment = int(projection["ram_alignment_bytes"])

    measured_stack_allowance = align_up(
        with_margin(probe.stack_used_bytes, stack_margin), ram_alignment
    )
    ram_payload = (
        static_ram_bytes
        + measured_stack_allowance
        + int(projection["interrupt_stack_reserve_bytes"])
        + int(projection["platform_static_ram_reserve_bytes"])
        + int(projection["transport_buffers_bytes"])
        + int(projection["display_framebuffer_bytes"])
        + int(projection["storage_scratch_bytes"])
        + int(projection["future_ram_reserve_bytes"])
    )
    ram_required = align_up(
        with_margin(ram_payload, int(projection["ram_margin_percent"])),
        ram_alignment,
    )

    errors: list[str] = []
    if probe.status != "ok":
        errors.append(f"Firmverse status is {probe.status!r}, expected 'ok'")
    if probe.board != "hardware-wallet-dev":
        errors.append(f"unexpected board {probe.board!r}")
    if probe.soc != "cortex-m4-generic":
        errors.append(f"unexpected SoC {probe.soc!r}")
    if probe.profile != "zmu/cortex-m4":
        errors.append(f"unexpected CPU profile {probe.profile!r}")
    if not probe.strict:
        errors.append("probe did not execute in strict mode")
    if probe.exit_code != 0:
        errors.append(f"guest exit code is {probe.exit_code}")
    if probe.instructions <= 0 or probe.cycles <= 0:
        errors.append("instruction and cycle counters must be positive")
    if probe.stack_used_bytes <= 0:
        errors.append("stack high-water is zero; the real guest scenario was probably not executed")
    if probe.stack_saturated:
        errors.append("stack touched the bottom of the scanned Firmverse window")
    if probe.stack_used_bytes > probe.stack_window_bytes:
        errors.append("stack high-water exceeds the scanned window")
    provisional_stack = int(projection["provisional_stack_bytes"])
    if probe.stack_used_bytes > provisional_stack:
        errors.append(
            f"measured stack {probe.stack_used_bytes} exceeds provisional gate {provisional_stack}"
        )

    return Measurement(
        probe=probe,
        static_ram_bytes=static_ram_bytes,
        provisional_stack_gate_bytes=provisional_stack,
        measured_stack_allowance_bytes=measured_stack_allowance,
        ram_required_bytes=ram_required,
        recommended_ram_kib=next_class(ram_required, list(classes["ram_kib"])),
        cycles_per_instruction=probe.cycles / probe.instructions,
        errors=tuple(errors),
    )


def kib(value: int) -> str:
    return f"{value / 1024:.1f} KiB"


def render_markdown(measurement: Measurement, config: dict) -> str:
    probe = measurement.probe
    stack_margin = int(config["projection"].get("stack_high_water_margin_percent", 50))
    result = "PASS" if not measurement.errors else "FAIL"
    lines = [
        "# Firmverse hardware execution",
        "",
        f"Runtime gate: **{result}**",
        "",
        "| Metric | Measured |",
        "| --- | ---: |",
        f"| Guest instructions | {probe.instructions:,} |",
        f"| Simulated cycles | {probe.cycles:,} |",
        f"| Cycles / instruction | {measurement.cycles_per_instruction:.3f} |",
        f"| Stack high-water | {kib(probe.stack_used_bytes)} |",
        f"| Scanned stack window | {kib(probe.stack_window_bytes)} |",
        f"| Stack window saturated | `{str(probe.stack_saturated).lower()}` |",
        f"| Measured stack allowance (+{stack_margin}%) | {kib(measurement.measured_stack_allowance_bytes)} |",
        f"| Recalculated runtime RAM | {kib(measurement.ram_required_bytes)} |",
        f"| Next normal RAM class | {measurement.recommended_ram_kib} KiB |",
        "",
        "The cycle count is an emulator regression baseline, not yet a clock-frequency claim. "
        "Frequency selection requires per-scenario cycle measurements and the latency budgets in "
        "`hardware-budget.toml`.",
        "",
        f"Guest result: `{probe.reason}`, PC `0x{probe.pc:08x}`, initial MSP `0x{probe.initial_sp:08x}`.",
    ]
    if measurement.errors:
        lines.extend(["", "## Gate failures", ""])
        lines.extend(f"- {error}" for error in measurement.errors)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--budget", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    with args.config.open("rb") as source:
        config = tomllib.load(source)
    budget = json.loads(args.budget.read_text(encoding="utf-8"))
    probe = read_probe(args.log)
    measurement = calculate(probe, config, int(budget["probe_static_ram_bytes"]))

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(asdict(measurement), indent=2) + "\n", encoding="utf-8")
    report = render_markdown(measurement, config)
    args.markdown.write_text(report, encoding="utf-8")
    print(report)
    return 1 if measurement.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

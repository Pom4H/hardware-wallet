#!/usr/bin/env python3
"""Check a manually verified MCU description against the wallet requirements."""

from __future__ import annotations

import argparse
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Check:
    name: str
    required: str
    actual: str
    passed: bool


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        value = tomllib.load(source)
    if int(value.get("schema", 0)) != 1:
        raise ValueError(f"unsupported schema in {path}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def human_bytes(value: int) -> str:
    return f"{value / 1024:.1f} KiB"


def required_flash_bytes(requirements: dict[str, Any], budget: dict[str, Any]) -> int:
    selection = requirements["selection"]
    mode = selection["flash_mode"]
    if mode == "ab":
        measured = int(budget["ab_flash_required_bytes"])
    elif mode == "single":
        measured = int(budget["single_slot_flash_required_bytes"])
    else:
        raise ValueError(f"unsupported flash mode: {mode}")
    return max(measured, int(selection["flash_floor_bytes"]))


def required_ram_bytes(requirements: dict[str, Any], budget: dict[str, Any]) -> int:
    return max(
        int(budget["ram_required_bytes"]),
        int(requirements["selection"]["ram_floor_bytes"]),
    )


def capability(
    checks: list[Check],
    candidate_caps: dict[str, Any],
    name: str,
    expected: bool,
) -> None:
    actual = bool(candidate_caps.get(name, False))
    checks.append(
        Check(
            name=name,
            required=str(expected).lower(),
            actual=str(actual).lower(),
            passed=actual is expected,
        )
    )


def minimum_count(
    checks: list[Check],
    candidate_caps: dict[str, Any],
    name: str,
    expected: int,
) -> None:
    actual = int(candidate_caps.get(name, 0))
    checks.append(
        Check(
            name=name,
            required=f">= {expected}",
            actual=str(actual),
            passed=actual >= expected,
        )
    )


def evaluate(
    requirements: dict[str, Any],
    budget: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[list[Check], int, int]:
    checks: list[Check] = []
    required = requirements["required"]
    candidate_caps = candidate.get("capabilities", {})

    architectures = [str(value) for value in required["architectures"]]
    architecture = str(candidate.get("architecture", ""))
    checks.append(
        Check(
            name="architecture",
            required=" or ".join(architectures),
            actual=architecture or "<missing>",
            passed=architecture in architectures,
        )
    )

    flash_required = required_flash_bytes(requirements, budget)
    flash_actual = int(candidate.get("flash_bytes", 0))
    checks.append(
        Check(
            name="flash",
            required=f">= {human_bytes(flash_required)}",
            actual=human_bytes(flash_actual),
            passed=flash_actual >= flash_required,
        )
    )

    ram_required = required_ram_bytes(requirements, budget)
    ram_actual = int(candidate.get("ram_bytes", 0))
    checks.append(
        Check(
            name="ram",
            required=f">= {human_bytes(ram_required)}",
            actual=human_bytes(ram_actual),
            passed=ram_actual >= ram_required,
        )
    )

    minimum_clock = int(requirements["selection"].get("min_clock_mhz", 0))
    if minimum_clock > 0:
        clock_actual = int(candidate.get("max_clock_mhz", 0))
        checks.append(
            Check(
                name="max_clock_mhz",
                required=f">= {minimum_clock}",
                actual=str(clock_actual),
                passed=clock_actual >= minimum_clock,
            )
        )

    for name in required.get("boolean_capabilities", []):
        capability(checks, candidate_caps, str(name), True)

    for name, value in required.get("minimum_counts", {}).items():
        minimum_count(checks, candidate_caps, str(name), int(value))

    weights = {
        str(name): int(weight)
        for name, weight in requirements.get("preferred", {})
        .get("weights", {})
        .items()
    }
    score = sum(
        weight for name, weight in weights.items() if bool(candidate_caps.get(name, False))
    )
    maximum_score = sum(weights.values())
    return checks, score, maximum_score


def render_markdown(
    candidate: dict[str, Any],
    checks: list[Check],
    score: int,
    maximum_score: int,
) -> str:
    passed = all(check.passed for check in checks)
    lines = [
        f"# MCU candidate — {candidate.get('name', '<unnamed>')}",
        "",
        f"Hard requirements: **{'PASS' if passed else 'FAIL'}**",
        "",
        "| Requirement | Required | Actual | Result |",
        "| --- | --- | --- | --- |",
    ]
    for check in checks:
        lines.append(
            f"| `{check.name}` | {check.required} | {check.actual} | "
            f"{'PASS' if check.passed else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            f"Preferred-feature score: **{score}/{maximum_score}**.",
            "",
            (
                "Candidate capability fields are manually verified evidence. Passing this "
                "tool does not replace checking the exact ordering code, package, errata, "
                "temperature range, lifecycle status, availability and unit price."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--budget", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    requirements = load_toml(args.requirements)
    budget = load_json(args.budget)
    candidate = load_toml(args.candidate)
    checks, score, maximum_score = evaluate(requirements, budget, candidate)
    report = render_markdown(candidate, checks, score, maximum_score)
    print(report)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "candidate": candidate.get("name", "<unnamed>"),
                    "passed": all(check.passed for check in checks),
                    "score": score,
                    "maximum_score": maximum_score,
                    "checks": [check.__dict__ for check in checks],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(report, encoding="utf-8")

    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())

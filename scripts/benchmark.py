"""Synthetic benchmark runner for Preflight.

Evaluates detection rates, false positive rates, runtime performance,
and determinism against synthetic Terraform plan fixtures.
"""

import time
from pathlib import Path
from typing import TypedDict

from preflight.engine import PreflightEngine
from preflight.models import Environment


class BenchmarkCase(TypedDict):
    name: str
    path: str
    expected_safe: bool
    expected_rules: list[str]


BENCHMARK_CASES: list[BenchmarkCase] = [
    {
        "name": "safe-plan",
        "path": "examples/safe-plan.json",
        "expected_safe": True,
        "expected_rules": [],
    },
    {
        "name": "empty-plan",
        "path": "tests/fixtures/plans/empty-plan.json",
        "expected_safe": True,
        "expected_rules": [],
    },
    {
        "name": "risky-plan",
        "path": "examples/risky-plan.json",
        "expected_safe": False,
        "expected_rules": [
            "AWS-NET-001",
            "AWS-S3-001",
            "AWS-IAM-001",
            "AWS-DB-001",
            "GEN-DEL-001",
            "GEN-DST-001",
        ],
    },
    {
        "name": "replacement-db",
        "path": "tests/fixtures/plans/replacement-db.json",
        "expected_safe": False,
        "expected_rules": ["AWS-DB-001", "GEN-REP-001", "GEN-DST-001"],
    },
    {
        "name": "unknown-action",
        "path": "tests/fixtures/plans/unknown-action.json",
        "expected_safe": False,
        "expected_rules": ["GEN-ACT-001"],
    },
    {
        "name": "unknown-values",
        "path": "tests/fixtures/plans/unknown-values.json",
        "expected_safe": False,
        "expected_rules": ["GEN-UNK-001"],
    },
]


def run_benchmark() -> None:
    engine = PreflightEngine()
    total_cases = len(BENCHMARK_CASES)
    expected_findings_total = 0
    actual_detected_findings = 0
    false_positives = 0
    run_times: list[float] = []

    print(f"Running synthetic benchmark across {total_cases} plan fixtures...\n")
    print(f"{'Fixture':<22} | {'Status':<10} | {'Score':<8} | {'Findings':<10} | {'Time (ms)':<10}")
    print("-" * 72)

    for case in BENCHMARK_CASES:
        plan_file = Path(case["path"])
        if not plan_file.exists():
            print(f"ERROR: Missing fixture: {case['path']}")
            continue

        start_time = time.perf_counter()
        result = engine.analyze_file(plan_file, Environment.PRODUCTION)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        run_times.append(elapsed_ms)

        detected_rule_ids = {f.rule_id for f in result.findings}

        if case["expected_safe"]:
            if len(result.findings) > 0:
                false_positives += len(result.findings)
                status = "FP_FAIL"
            else:
                status = "PASS (SAFE)"
        else:
            expected_rules = set(case["expected_rules"])
            expected_findings_total += len(expected_rules)
            matched = detected_rule_ids.intersection(expected_rules)
            actual_detected_findings += len(matched)
            status = "PASS (RISK)" if matched else "FN_FAIL"

        print(
            f"{case['name']:<22} | {status:<10} | {result.overall_risk_score:<8.1f} | "
            f"{len(result.findings):<10} | {elapsed_ms:<10.2f}"
        )

    print("-" * 72)
    detection_rate = (
        (actual_detected_findings / expected_findings_total * 100)
        if expected_findings_total > 0
        else 100.0
    )
    avg_runtime_ms = sum(run_times) / len(run_times) if run_times else 0.0

    print("\nSynthetic Benchmark Summary:")
    print(f"  Total Fixtures:          {total_cases}")
    print(
        f"  Target Rule Detection:   {detection_rate:.1f}% ({actual_detected_findings}/{expected_findings_total})"
    )
    print(f"  False Positives:         {false_positives}")
    print(f"  Average Analysis Time:   {avg_runtime_ms:.2f} ms")


if __name__ == "__main__":
    run_benchmark()

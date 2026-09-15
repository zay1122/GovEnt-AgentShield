#!/usr/bin/env python3
"""Run exact-action regression checks on the curated Skill package cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from supply_chain_guard import SupplyChainGuard  # noqa: E402


def main() -> int:
    expected_path = ROOT / "data" / "evaluation" / "supply_chain_expected.json"
    expected_doc = json.loads(expected_path.read_text(encoding="utf-8"))
    cases = expected_doc["cases"]
    case_dir = ROOT / "data" / "skill_cases" / "curated"
    guard = SupplyChainGuard()
    rows = []
    exact = 0
    risky_tp = risky_tn = risky_fp = risky_fn = 0
    for filename, expected in cases.items():
        result = guard.scan(case_dir / filename)
        actual = result["decision"]
        exact += actual == expected
        expected_risky = expected != "allow"
        actual_risky = actual != "allow"
        if expected_risky and actual_risky:
            risky_tp += 1
        elif expected_risky:
            risky_fn += 1
        elif actual_risky:
            risky_fp += 1
        else:
            risky_tn += 1
        rows.append({
            "case": filename,
            "expected": expected,
            "actual": actual,
            "correct": expected == actual,
            "rules": result["matched_rules"],
        })
    total = len(cases)
    summary = {
        "dataset": expected_path.relative_to(ROOT).as_posix(),
        "dataset_scope": "human-authored engineering regression set, not an external blind test",
        "case_count": total,
        "exact_action_accuracy": round(exact / max(total, 1), 4),
        "risky_case_recall": round(risky_tp / max(risky_tp + risky_fn, 1), 4),
        "safe_case_specificity": round(risky_tn / max(risky_tn + risky_fp, 1), 4),
        "rows": rows,
    }
    output = ROOT / "output" / "evaluation" / "supply_chain_benchmark_summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


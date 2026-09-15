#!/usr/bin/env python3
"""Expand the 15 canonical Tool Guard cases into 120 robustness variants."""

from __future__ import annotations

import base64
import csv
import json
import statistics
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from tool_guard import ToolGuard  # noqa: E402


def variants(case: dict) -> list[tuple[str, dict]]:
    values = []
    for name in ("plain", "upper_tool", "target_noise", "argument_noise", "url_target", "base64_target", "nested_args", "reordered"):
        row = json.loads(json.dumps(case, ensure_ascii=False))
        if name == "upper_tool":
            row["tool_name"] = str(row["tool_name"]).upper()
        elif name == "target_noise":
            row["target"] = f"{row.get('target', '')} "
        elif name == "argument_noise":
            row.setdefault("arguments", {})["request_note"] = "normal workflow context"
        elif name == "url_target":
            row["target"] = urllib.parse.quote(str(row.get("target", "")), safe="")
        elif name == "base64_target":
            row["target"] = base64.b64encode(str(row.get("target", "")).encode("utf-8")).decode("ascii")
        elif name == "nested_args":
            row["arguments"] = {"payload": row.get("arguments") or {}, "target_copy": row.get("target", "")}
        elif name == "reordered":
            row["arguments"] = dict(reversed(list((row.get("arguments") or {}).items())))
        values.append((name, row))
    return values


def main() -> int:
    source = json.loads((ROOT / "data" / "tool_guard_cases.json").read_text(encoding="utf-8"))["cases"]
    guard = ToolGuard(ROOT)
    records = []
    for base in source:
        for index, (variant, case) in enumerate(variants(base), 1):
            started = time.perf_counter()
            result = guard.detect(
                case["tool_name"], operation=case.get("operation", ""), target=case.get("target", ""),
                arguments=case.get("arguments") or {}, event_id=f"EVT-20991130-{len(records)+1:04d}",
            )
            records.append({
                "case_id": base["case_id"], "variant": variant,
                "expected_action": base["expected_action"], "actual_action": result["actual_action"],
                "correct": base["expected_action"] == result["actual_action"],
                "latency_ms": round((time.perf_counter() - started) * 1000, 4),
                "matched_rules": ";".join(result["matched_rules"]),
            })
    correct = sum(row["correct"] for row in records)
    by_variant = Counter()
    variant_total = Counter()
    for row in records:
        variant_total[row["variant"]] += 1
        by_variant[row["variant"]] += int(row["correct"])
    summary = {
        "cases": len(records), "canonical_cases": len(source),
        "action_accuracy": round(correct / len(records), 4),
        "avg_latency_ms": round(statistics.fmean(row["latency_ms"] for row in records), 4),
        "variant_accuracy": {key: round(by_variant[key] / value, 4) for key, value in sorted(variant_total.items())},
        "failed_expectations": [row for row in records if not row["correct"]],
        "limitation": "Template-derived robustness set; not an independent blind benchmark.",
    }
    out = ROOT / "output" / "evaluation"
    out.mkdir(parents=True, exist_ok=True)
    (out / "tool_benchmark_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    with (out / "tool_benchmark_records.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader(); writer.writerows(records)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


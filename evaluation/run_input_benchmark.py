#!/usr/bin/env python3
"""Reproducible baseline, ablation, robustness and latency evaluation."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from input_guard import InputGuard  # noqa: E402


KEYWORDS = re.compile(
    r"(忽略.{0,8}规则|系统提示词|无限制模式|api\s*key|token|私钥|rm\s+-rf|drop\s+database|"
    r"跳过.{0,8}审批|删除.{0,8}日志|上传.{0,12}外部|最高权限|777|webhook)",
    re.I,
)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def metrics(rows: list[dict]) -> dict:
    tp = sum(r["expected_attack"] and r["predicted_attack"] for r in rows)
    tn = sum(not r["expected_attack"] and not r["predicted_attack"] for r in rows)
    fp = sum(not r["expected_attack"] and r["predicted_attack"] for r in rows)
    fn = sum(r["expected_attack"] and not r["predicted_attack"] for r in rows)
    total = len(rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "cases": total, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "avg_latency_ms": round(statistics.fmean(r["latency_ms"] for r in rows), 4) if rows else 0.0,
        "p95_latency_ms": round(percentile([r["latency_ms"] for r in rows], 0.95), 4),
    }


def keyword_ablation(text: str, _sample_id: str) -> tuple[bool, str]:
    hit = bool(KEYWORDS.search(text))
    return hit, "warn" if hit else "allow"


def full_detector(guard: InputGuard) -> Callable[[str, str], tuple[bool, str]]:
    def detect(text: str, sample_id: str) -> tuple[bool, str]:
        result = guard.detect(text, event_id=f"EVT-20991231-{int(sample_id.split('-')[1]):04d}", sample_id=sample_id)
        action = str(result.get("actual_action", "allow"))
        return action != "allow", action
    return detect


def evaluate(rows: list[dict], name: str,
             detector: Callable[[str, str], tuple[bool, str]]) -> list[dict]:
    results: list[dict] = []
    for row in rows:
        started = time.perf_counter()
        predicted, action = detector(row["input_text"], row["sample_id"])
        elapsed = (time.perf_counter() - started) * 1000
        results.append({
            **row,
            "system": name,
            "expected_attack": row["label"] == "attack",
            "predicted_attack": predicted,
            "predicted_action": action,
            "correct": predicted == (row["label"] == "attack"),
            "latency_ms": round(elapsed, 4),
        })
    return results


def robustness(results: list[dict]) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in results:
        if row["expected_attack"]:
            groups[row["parent_id"]].append(row)
    detected = [sum(item["predicted_attack"] for item in group) / len(group) for group in groups.values() if group]
    by_variant: dict[str, list[bool]] = defaultdict(list)
    for row in results:
        if row["expected_attack"]:
            by_variant[row["variant"]].append(row["predicted_attack"])
    return {
        "attack_family_count": len(groups),
        "mean_variant_detection_rate": round(statistics.fmean(detected), 4) if detected else 0.0,
        "variant_detection_rate": {
            key: round(sum(values) / len(values), 4) for key, values in sorted(by_variant.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=ROOT / "data" / "evaluation" / "input_benchmark.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output" / "evaluation")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    guard = InputGuard(ROOT)
    all_results: list[dict] = []
    systems = {
        "keyword_only_ablation": keyword_ablation,
        "input_guard_full": full_detector(guard),
    }
    summary = {"dataset": str(args.dataset), "cases": len(rows), "systems": {}}
    for name, detector in systems.items():
        result = evaluate(rows, name, detector)
        all_results.extend(result)
        split_summary = {}
        for split in ("development", "validation", "holdout", "overall"):
            selected = result if split == "overall" else [r for r in result if r["split"] == split]
            split_summary[split] = metrics(selected)
        summary["systems"][name] = {
            "metrics": split_summary,
            "robustness": robustness(result),
        }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "input_benchmark_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    fields = [
        "sample_id", "parent_id", "split", "label", "category", "variant", "system",
        "expected_attack", "predicted_attack", "predicted_action", "correct", "latency_ms",
    ]
    with (args.output_dir / "input_benchmark_records.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in fields} for row in all_results)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


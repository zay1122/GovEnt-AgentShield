#!/usr/bin/env python3
"""Evaluate provenance-aware multi-source detection on the frozen regression set."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from multisource_guard import MultiSourceGuard  # noqa: E402


def metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float | int]:
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main() -> int:
    dataset = ROOT / "data" / "evaluation" / "multisource_benchmark.jsonl"
    cases = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    guard = MultiSourceGuard(project_root=ROOT)
    rows = []
    tp = tn = fp = fn = block_count = 0
    for index, case in enumerate(cases, 1):
        result = guard.detect(
            case["sources"],
            event_id=f"EVT-20991231-{index:03d}",
            tool_name=case.get("tool_name"),
            operation=case.get("operation", "read"),
            destination=case.get("destination"),
        )
        expected_attack = case["label"] == "attack"
        predicted_attack = result["decision"] != "allow"
        if expected_attack and predicted_attack:
            tp += 1
        elif expected_attack:
            fn += 1
        elif predicted_attack:
            fp += 1
        else:
            tn += 1
        block_count += result["decision"] == "block"
        rows.append({
            "case_id": case["case_id"],
            "label": case["label"],
            "decision": result["decision"],
            "correct": expected_attack == predicted_attack,
            "matched_rules": result["matched_rules"],
        })
    summary = {
        "dataset": dataset.relative_to(ROOT).as_posix(),
        "dataset_scope": "frozen engineering regression set, not an external blind test",
        "case_count": len(cases),
        "metrics": metrics(tp, tn, fp, fn),
        "block_rate": round(block_count / max(len(cases), 1), 4),
        "rows": rows,
    }
    output = ROOT / "output" / "evaluation" / "multisource_benchmark_summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


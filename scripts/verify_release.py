#!/usr/bin/env python3
"""One-command release verification for a clean environment."""

from __future__ import annotations

import argparse
import json
import os
import py_compile
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def run_step(name: str, command: list[str], timeout: int = 120) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )
    result = {
        "name": name,
        "command": command,
        "returncode": completed.returncode,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "stdout_tail": completed.stdout[-3000:],
        "stderr_tail": completed.stderr[-3000:],
        "passed": completed.returncode == 0,
    }
    if completed.returncode != 0:
        raise RuntimeError(f"{name} failed\n{completed.stdout}\n{completed.stderr}")
    return result


def dashboard_apptest() -> dict[str, Any]:
    started = time.perf_counter()
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=30)
    app.run()
    exceptions = [str(item.value) for item in app.exception]
    result = {
        "name": "dashboard_apptest",
        "duration_seconds": round(time.perf_counter() - started, 3),
        "exceptions": exceptions,
        "passed": not exceptions,
    }
    if exceptions:
        raise RuntimeError(f"dashboard AppTest failed: {exceptions}")
    return result


def api_process_smoke() -> dict[str, Any]:
    started = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    environment = dict(os.environ)
    environment.update({"AGENTSHIELD_HOST": "127.0.0.1", "AGENTSHIELD_PORT": str(port)})
    process = subprocess.Popen(
        [sys.executable, "src/api.py"], cwd=ROOT, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        last_error = ""
        for _ in range(50):
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=2)
                raise RuntimeError(f"API exited early\n{stdout}\n{stderr}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    if response.status == 200 and payload.get("status") == "ok":
                        return {
                            "name": "api_process_smoke",
                            "duration_seconds": round(time.perf_counter() - started, 3),
                            "health": payload,
                            "passed": True,
                        }
            except Exception as exc:
                last_error = str(exc)
                time.sleep(0.1)
        raise RuntimeError(f"API health timeout: {last_error}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def artifact_quality_gates() -> dict[str, Any]:
    benchmark = json.loads(
        (ROOT / "output" / "evaluation" / "input_benchmark_summary.json").read_text(encoding="utf-8")
    )
    full = benchmark["systems"]["input_guard_full"]
    tool_benchmark = json.loads(
        (ROOT / "output" / "evaluation" / "tool_benchmark_summary.json").read_text(encoding="utf-8")
    )
    skill_benchmark = json.loads(
        (ROOT / "output" / "evaluation" / "skill_benchmark_summary.json").read_text(encoding="utf-8")
    )
    multisource_benchmark = json.loads(
        (ROOT / "output" / "evaluation" / "multisource_benchmark_summary.json").read_text(encoding="utf-8")
    )
    supply_chain_benchmark = json.loads(
        (ROOT / "output" / "evaluation" / "supply_chain_benchmark_summary.json").read_text(encoding="utf-8")
    )
    overall_f1 = float(full["metrics"]["overall"]["f1"])
    holdout_f1 = float(full["metrics"]["holdout"]["f1"])
    base64_rate = float(full["robustness"]["variant_detection_rate"]["base64"])
    quality_paths = sorted((ROOT / "output" / "statistics" / "aggregated").glob("data_quality_*.json"))
    if not quality_paths:
        raise RuntimeError("result aggregator did not produce a data-quality report")
    quality = json.loads(quality_paths[-1].read_text(encoding="utf-8"))
    demo = json.loads((ROOT / "output" / "control_demo.json").read_text(encoding="utf-8"))
    demo_statuses = [item.get("status") for item in demo]
    one_click_demo = json.loads(
        (ROOT / "output" / "evaluation" / "one_click_demo_summary.json").read_text(encoding="utf-8")
    )
    short_circuit_records = [
        item for item in one_click_demo.get("records", [])
        if (item.get("case", {}).get("expected") or {}).get("input_gate_passed") is False
    ]
    checks = {
        "overall_f1_at_least_0_85": overall_f1 >= 0.85,
        "holdout_f1_at_least_0_75": holdout_f1 >= 0.75,
        "base64_detection_at_least_0_70": base64_rate >= 0.70,
        "tool_action_accuracy_at_least_0_95": float(tool_benchmark["action_accuracy"]) >= 0.95,
        "skill_accuracy_at_least_0_95": float(skill_benchmark["accuracy"]) >= 0.95,
        "multisource_f1_at_least_0_90": float(multisource_benchmark["metrics"]["f1"]) >= 0.90,
        "multisource_false_positives_at_most_1": int(multisource_benchmark["metrics"]["fp"]) <= 1,
        "supply_chain_exact_action_at_least_0_90": float(supply_chain_benchmark["exact_action_accuracy"]) >= 0.90,
        "aggregated_data_quality_zero": int(quality.get("issue_count", -1)) == 0,
        "demo_control_states": demo_statuses == [
            "executed", "pending_approval", "input_blocked", "executed"
        ],
        "one_click_demo_all_passed": bool(one_click_demo.get("passed")),
        "one_click_input_short_circuit": bool(short_circuit_records) and all(
            item.get("verification", {}).get("checks", {}).get("input_gate_short_circuit") is True
            for item in short_circuit_records
        ),
    }
    result = {
        "name": "artifact_quality_gates",
        "metrics": {"overall_f1": overall_f1, "holdout_f1": holdout_f1,
                    "base64_detection_rate": base64_rate,
                    "tool_action_accuracy": tool_benchmark["action_accuracy"],
                    "skill_accuracy": skill_benchmark["accuracy"],
                    "multisource_f1": multisource_benchmark["metrics"]["f1"],
                    "multisource_false_positives": multisource_benchmark["metrics"]["fp"],
                    "supply_chain_exact_action_accuracy": supply_chain_benchmark["exact_action_accuracy"],
                    "data_quality_issues": quality.get("issue_count"),
                    "demo_statuses": demo_statuses,
                    "one_click_demo_passed": one_click_demo.get("passed"),
                    "one_click_demo_cases": one_click_demo.get("case_count"),
                    "one_click_short_circuit_cases": len(short_circuit_records)},
        "checks": checks,
        "passed": all(checks.values()),
    }
    if not result["passed"]:
        raise RuntimeError(f"artifact quality gate failed: {result}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-ui", action="store_true", help="skip Streamlit AppTest")
    parser.add_argument("--output", type=Path, default=ROOT / "output" / "verification_report.json")
    args = parser.parse_args()
    steps: list[dict[str, Any]] = []
    try:
        for path in sorted(list((ROOT / "src").glob("*.py")) + list((ROOT / "dashboard").glob("*.py"))):
            py_compile.compile(str(path), doraise=True)
        steps.append({"name": "python_compile", "passed": True})
        steps.append(run_step("unit_and_integration_tests", [
            sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"
        ]))
        steps.append(run_step("generate_benchmark", [sys.executable, "evaluation/generate_benchmark.py"]))
        steps.append(run_step("input_benchmark", [sys.executable, "evaluation/run_input_benchmark.py"]))
        steps.append(run_step("tool_benchmark", [sys.executable, "evaluation/run_tool_benchmark.py"]))
        steps.append(run_step("skill_benchmark", [sys.executable, "evaluation/run_skill_benchmark.py"]))
        steps.append(run_step("multisource_benchmark", [sys.executable, "evaluation/run_multisource_benchmark.py"]))
        steps.append(run_step("supply_chain_benchmark", [sys.executable, "evaluation/run_supply_chain_benchmark.py"]))
        steps.append(run_step("one_click_demo", [sys.executable, "src/demo_runner.py"]))
        steps.append(run_step("controlled_runtime_demo", [sys.executable, "src/runtime_controller.py", "--demo"]))
        steps.append(run_step("pipeline_demo", [sys.executable, "src/security_pipeline.py", "--demo"]))
        steps.append(run_step("result_aggregation", [sys.executable, "src/result_aggregator.py"]))
        steps.append(run_step("control_aggregation", [sys.executable, "src/control_aggregator.py"]))
        steps.append(artifact_quality_gates())
        steps.append(api_process_smoke())
        if not args.skip_ui:
            steps.append(dashboard_apptest())
        status = "passed"
        error = None
    except Exception as exc:
        status = "failed"
        error = str(exc)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version,
        "status": status,
        "steps": steps,
        "error": error,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

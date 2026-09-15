import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
DATA_DIR = PROJECT_ROOT / "data" / "skill_cases"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from skill_scanner import (
    scan_py_file,
    calculate_risk_score,
    is_allowed_path,
)


class SkillScannerIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.temp_path = Path(cls.temp_dir.name)

        # medium：open
        cls.medium_file = cls.temp_path / "medium_sample.py"
        cls.medium_file.write_text(
            'with open("demo.txt", "r") as f:\n'
            '    data = f.read()\n',
            encoding="utf-8",
        )

        # high：os.system
        cls.high_file = cls.temp_path / "high_sample.py"
        cls.high_file.write_text(
            'import os\n'
            'os.system("echo test")\n',
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def scan_and_score(self, file_path):
        """
        直接调用丁梓玉原始 Skill Scanner 核心。
        """

        detected = scan_py_file(str(file_path))

        self.assertIsInstance(detected, list)

        risk_info = calculate_risk_score(detected)

        self.assertIsInstance(risk_info, dict)

        return detected, risk_info

    # --------------------------------------------------------
    # 01 安全 Skill
    # --------------------------------------------------------

    def test_01_safe_skill_is_allowed(self):

        detected, result = self.scan_and_score(
            DATA_DIR / "test_safe.py"
        )

        self.assertEqual(detected, [])
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["actual_action"], "allow")

    # --------------------------------------------------------
    # 02 medium 风险
    # --------------------------------------------------------

    def test_02_open_file_causes_medium_warning(self):

        detected, result = self.scan_and_score(
            self.medium_file
        )

        self.assertIn("open", detected)
        self.assertEqual(result["risk_level"], "medium")
        self.assertEqual(result["actual_action"], "warn")

    # --------------------------------------------------------
    # 03 high 风险
    # --------------------------------------------------------

    def test_03_system_command_requires_review(self):

        detected, result = self.scan_and_score(
            self.high_file
        )

        self.assertIn("os.system", detected)
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["actual_action"], "review")

    # --------------------------------------------------------
    # 04 恶意 Skill
    # --------------------------------------------------------

    def test_04_malicious_skill_is_blocked(self):

        detected, result = self.scan_and_score(
            DATA_DIR / "test_malicious.py"
        )

        self.assertGreater(len(detected), 0)
        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["actual_action"], "block")

    # --------------------------------------------------------
    # 05 不存在文件
    # --------------------------------------------------------

    def test_05_missing_file_returns_error(self):

        result = scan_py_file(
            str(DATA_DIR / "not_exists.py")
        )

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("文件不存在", result["error"])

    # --------------------------------------------------------
    # 06 非 Python 文件
    # --------------------------------------------------------

    def test_06_non_python_file_returns_error(self):

        txt_file = self.temp_path / "demo.txt"

        txt_file.write_text(
            "hello",
            encoding="utf-8",
        )

        result = scan_py_file(str(txt_file))

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("只支持 .py 文件", result["error"])

    # --------------------------------------------------------
    # 07 风险评分字段完整
    # --------------------------------------------------------

    def test_07_risk_score_result_fields_are_complete(self):

        detected = ["open"]

        result = calculate_risk_score(detected)

        required_fields = {
            "total_score",
            "risk_score",
            "risk_level",
            "actual_action",
            "reason",
        }

        self.assertTrue(
            required_fields.issubset(result.keys())
        )

        self.assertGreaterEqual(result["risk_score"], 0.0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_08_import_only_does_not_claim_command_execution(self):
        path = self.temp_path / "import_only.py"
        path.write_text("import os\nvalue = os.name\n", encoding="utf-8")
        self.assertEqual(scan_py_file(str(path)), [])

    def test_09_aliased_subprocess_call_is_detected(self):
        path = self.temp_path / "alias_subprocess.py"
        path.write_text("import subprocess as sp\nsp.run(['whoami'])\n", encoding="utf-8")
        self.assertIn("subprocess", scan_py_file(str(path)))

    def test_10_aliased_from_import_is_detected(self):
        path = self.temp_path / "alias_system.py"
        path.write_text("from os import system as run\nrun('whoami')\n", encoding="utf-8")
        self.assertIn("os.system", scan_py_file(str(path)))

    def test_11_http_scan_path_is_fail_closed(self):
        self.assertTrue(is_allowed_path(DATA_DIR / "test_safe.py"))
        self.assertFalse(is_allowed_path(PROJECT_ROOT / "README.md"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

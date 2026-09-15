#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skill/插件安全检测模块 - 竞赛融合增强版
原始作者：丁梓玉；融合维护：项目组
功能：
  1. 危险API权重评分 + 组合规则（替代简单计数）
  2. AST扫描、别名解析、shell=True 与敏感文件上下文识别
  3. 区分普通文件、敏感文件和合法日志追加写入，降低误报
  4. 单文件扫描 + 批量目录扫描（AST失败时降级到字符串扫描）
  5. 标准 skill_result.json 输出、目录限制与可控HTTP服务
"""

import os
import sys
import re
import json
import ast
from pathlib import Path
from datetime import datetime
try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ModuleNotFoundError:
    # Core static scanning and its tests do not require an HTTP server.  Keeping
    # Flask optional here lets a clean checkout run core tests before optional
    # web dependencies are installed; starting this module as a service still
    # fails with a clear message below.
    FLASK_AVAILABLE = False
    request = None

    class Flask:  # type: ignore[no-redef]
        def __init__(self, *_args, **_kwargs):
            pass

        def route(self, *_args, **_kwargs):
            def decorator(function):
                return function
            return decorator

        def run(self, *_args, **_kwargs):
            raise RuntimeError("Flask is required for the Skill Scanner HTTP service")

    def jsonify(*_args, **_kwargs):  # type: ignore[no-redef]
        raise RuntimeError("Flask is required for HTTP responses")

# ============================================================
# 1. 配置区（可在此调整参数）
# ============================================================

# HTTP API 允许扫描的根目录。默认仅允许仓库内的示例目录；可使用
# SKILL_SCAN_ROOTS（按系统 path separator 分隔）显式扩展。核心函数仍可由
# 可信的本地 Pipeline 直接调用，API 层则必须拒绝任意服务器文件读取。
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_configured_roots = [item for item in os.environ.get("SKILL_SCAN_ROOTS", "").split(os.pathsep) if item]
ALLOWED_ROOT_DIRECTORIES = _configured_roots or [str(_PROJECT_ROOT / "data" / "skill_cases")]

# Flask Debug 模式（通过环境变量控制，默认关闭）
DEBUG_MODE = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

# 输出文件名
OUTPUT_JSON_FILE = "skill_result.json"

# 扫描文件大小上限（10MB）
MAX_FILE_SIZE = 10 * 1024 * 1024


# ============================================================
# 2. 危险API定义 & 权重配置
# ============================================================

# 危险 API 清单。名称是审计用规范名，不代表仅 import 对应模块就有风险；
# AST 扫描器只在真正调用危险函数时记录。
DANGEROUS_APIS = [
    "os.system",
    "os.popen",
    "os.remove",
    "os.chmod",
    "subprocess",
    "subprocess_shell",
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "open_sensitive",
    "requests.post",
    "requests.get",
    "socket",
    "shutil.rmtree",
    "pickle.load",
    "yaml.load",
    "importlib.import_module",
    "ctypes.CDLL",
]

# 每个API的权重分（体现危险程度差异）
API_WEIGHTS = {
    "os.system": 8,
    "os.popen": 7,
    "os.remove": 5,
    "os.chmod": 5,
    "subprocess": 8,
    "subprocess_shell": 12,
    "eval": 9,
    "exec": 9,
    "compile": 6,
    "__import__": 6,
    "open": 3,
    "open_sensitive": 7,
    "requests.post": 4,
    "requests.get": 2,
    "socket": 5,
    "shutil.rmtree": 6,
    "pickle.load": 8,
    "yaml.load": 6,
    "importlib.import_module": 5,
    "ctypes.CDLL": 8,
}

_SENSITIVE_FILE_PATTERNS = (
    r"(^|[/\\\\])\.env($|[._-])",
    r"(^|[/\\\\])id_(rsa|dsa|ed25519)($|[._-])",
    r"(^|[/\\\\])(secret|secrets|password|passwd|credential)(s)?($|[._-])",
    r"private[_-]?key",
    r"api[_-]?key",
    r"access[_-]?token",
    r"credentials?\.(json|ya?ml|txt|ini)$",
    r"\.(pem|key)$",
    r"/etc/(passwd|shadow)$",
)


def _is_log_file(file_path):
    """Return True only for explicit log filenames, not arbitrary 'log' substrings."""
    name = os.path.basename(str(file_path)).lower()
    if name.endswith(".log"):
        return True
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return stem in {"log", "logging", "logger"}


def _is_sensitive_file(file_path):
    normalized = str(file_path).replace("\\\\", "/")
    return any(re.search(pattern, normalized, re.I) for pattern in _SENSITIVE_FILE_PATTERNS)


def _literal_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword_is_true(node, name):
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


# ============================================================
# 3. 扫描引擎（字符串匹配 + AST降级）
# ============================================================

# ---------- 3.1 字符串扫描（保底方案） ----------
def scan_py_file_string(file_path):
    """
    字符串匹配扫描（第0周实现，作为保底方案）
    返回：命中的危险API列表
    """
    if not os.path.exists(file_path):
        return {"error": f"文件不存在: {file_path}"}
    if not file_path.endswith(".py"):
        return {"error": "请传入 .py 文件"}

    # 文件大小检查
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        return {"error": f"文件过大: {os.path.getsize(file_path)} 字节（上限 {MAX_FILE_SIZE} 字节）"}

    detected_apis = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            open_match = re.search(r"\bopen\s*\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]*)['\"])?", line)
            if open_match:
                path, mode = open_match.group(1), (open_match.group(2) or "r")
                if _is_log_file(path) and any(flag in mode for flag in ("a", "w")):
                    continue
                api = "open_sensitive" if _is_sensitive_file(path) else "open"
                if api not in detected_apis:
                    detected_apis.append(api)
            if re.search(r"\bsubprocess\.(Popen|run|call|check_output|check_call)\s*\(", line) and re.search(r"\bshell\s*=\s*True\b", line):
                if "subprocess_shell" not in detected_apis:
                    detected_apis.append("subprocess_shell")
            for api in DANGEROUS_APIS:
                if api in {"open", "open_sensitive", "subprocess_shell"}:
                    continue
                pattern = r'\b' + re.escape(api) + r'\b'
                if re.search(pattern, line):
                    if api not in detected_apis:
                        detected_apis.append(api)
    except Exception as e:
        return {"error": f"读取文件失败: {str(e)}"}

    return detected_apis


# ---------- 3.2 AST扫描(若失败则自动降级进行字符串匹配扫描) ----------
class DangerousCallChecker(ast.NodeVisitor):
    """AST visitor that resolves common import aliases and records calls."""

    CALL_ALIASES = {
        "os.system": "os.system",
        "os.popen": "os.popen",
        "os.remove": "os.remove",
        "os.unlink": "os.remove",
        "os.chmod": "os.chmod",
        "subprocess.run": "subprocess",
        "subprocess.Popen": "subprocess",
        "subprocess.call": "subprocess",
        "subprocess.check_call": "subprocess",
        "subprocess.check_output": "subprocess",
        "eval": "eval",
        "exec": "exec",
        "compile": "compile",
        "__import__": "__import__",
        "open": "open",
        "requests.post": "requests.post",
        "requests.put": "requests.post",
        "requests.patch": "requests.post",
        "requests.delete": "requests.post",
        "requests.get": "requests.get",
        "socket.socket": "socket",
        "shutil.rmtree": "shutil.rmtree",
        "pickle.load": "pickle.load",
        "pickle.loads": "pickle.load",
        "yaml.load": "yaml.load",
        "importlib.import_module": "importlib.import_module",
        "ctypes.CDLL": "ctypes.CDLL",
        "ctypes.PyDLL": "ctypes.CDLL",
    }

    def __init__(self):
        self.detected_apis: list[str] = []
        self.aliases: dict[str, str] = {}

    def _record(self, api: str) -> None:
        if api not in self.detected_apis:
            self.detected_apis.append(api)

    def _qualified_name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._qualified_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def visit_Call(self, node):
        """检测函数调用节点，如 eval(), os.system()"""
        qualified = self._qualified_name(node.func)
        if qualified == "open":
            file_path = _literal_string(node.args[0]) if node.args else None
            mode = _literal_string(node.args[1]) if len(node.args) > 1 else "r"
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = _literal_string(keyword.value) or mode
            if file_path and _is_log_file(file_path) and any(flag in str(mode) for flag in ("a", "w")):
                self.generic_visit(node)
                return
            self._record("open_sensitive" if file_path and _is_sensitive_file(file_path) else "open")
            self.generic_visit(node)
            return
        canonical = self.CALL_ALIASES.get(qualified)
        if canonical:
            self._record(canonical)
            if canonical == "subprocess" and _keyword_is_true(node, "shell"):
                self._record("subprocess_shell")
        self.generic_visit(node)

    def visit_Import(self, node):
        """检测 import 语句，如 import os"""
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """检测 from ... import ... 语句"""
        if node.module:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)


def scan_py_file_ast(file_path):
    """
    AST扫描（优先方案）
    返回：命中的危险API列表
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        tree = ast.parse(content)
        checker = DangerousCallChecker()
        checker.visit(tree)
        return [api for api in checker.detected_apis if api in DANGEROUS_APIS]
    except Exception as e:
        # AST解析失败，返回错误信息
        return {"error": f"AST扫描失败: {str(e)}"}


def scan_py_file(file_path):
    """
    增强扫描：优先使用AST，失败时降级到字符串扫描
    """
    # 前置检查
    if not os.path.exists(file_path):
        return {"error": f"文件不存在: {file_path}"}
    if not file_path.endswith(".py"):
        return {"error": "只支持 .py 文件"}
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        return {"error": f"文件过大: {os.path.getsize(file_path)} 字节（上限 {MAX_FILE_SIZE} 字节）"}

    # 优先使用AST
    result = scan_py_file_ast(file_path)
    if isinstance(result, dict) and "error" in result:
        # AST失败，降级到字符串扫描
        print(f"⚠️ AST扫描失败，降级到字符串扫描: {result['error']}")
        return scan_py_file_string(file_path)

    # AST成功，但可能返回空列表
    return result


# ============================================================
# 4. 风险评分引擎（权重 + 组合规则）
# ============================================================

def calculate_combo_bonus(detected_apis):
    """
    检测API组合，返回额外加权分
    """
    if not detected_apis:
        return 0

    bonus = 0
    api_set = set(detected_apis)

    # 规则1：数据泄露链 open + requests.post
    has_open = bool({"open", "open_sensitive"} & api_set)

    if has_open and "requests.post" in api_set:
        bonus += 5

    # 规则2：数据外发 open + socket
    if has_open and "socket" in api_set:
        bonus += 4

    if "open_sensitive" in api_set:
        bonus += 2

    if "subprocess_shell" in api_set:
        bonus += 4

    # 规则3：动态代码执行 eval 或 exec
    if "eval" in api_set or "exec" in api_set:
        bonus += 3

    # 规则4：3个以上危险API
    if len(api_set) >= 3:
        bonus += 3

    return bonus


def calculate_risk_score(detected_apis):
    """
    计算总分 → risk_score (0~1) → risk_level → actual_action
    """
    if not detected_apis:
        return {
            "total_score": 0,
            "risk_score": 0.0,
            "risk_level": "low",
            "actual_action": "allow",
            "reason": "未检测到危险API，风险可控"
        }

    # 基础分
    base_score = sum(API_WEIGHTS.get(api, 0) for api in detected_apis)

    # 组合加分
    combo_bonus = calculate_combo_bonus(detected_apis)

    # 总分
    total_score = base_score + combo_bonus

    # 映射
    if total_score <= 0:
        risk_score = 0.0
        risk_level = "low"
        action = "allow"
        reason = "未检测到危险API，风险可控"
    elif total_score <= 4:
        risk_score = 0.30
        risk_level = "medium"
        action = "warn"
        reason = f"检测到 {len(detected_apis)} 个危险API，权重分 {total_score}，建议关注"
    elif total_score <= 9:
        risk_score = 0.65
        risk_level = "high"
        action = "review"
        reason = f"检测到 {len(detected_apis)} 个危险API，权重分 {total_score}，建议人工复核"
    elif total_score <= 14:
        risk_score = 0.85
        risk_level = "critical"
        action = "block"
        reason = f"检测到 {len(detected_apis)} 个危险API，权重分 {total_score}，存在高危攻击链"
    else:
        risk_score = 1.0
        risk_level = "critical"
        action = "block"
        reason = f"检测到 {len(detected_apis)} 个危险API，权重分 {total_score}，存在严重供应链攻击风险"

    return {
        "total_score": total_score,
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "actual_action": action,
        "reason": reason
    }


# ============================================================
# 5. 安全限制
# ============================================================

def is_allowed_path(file_path):
    """检查文件路径是否在允许的目录内"""
    try:
        candidate = Path(file_path).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return False
    for allowed_dir in ALLOWED_ROOT_DIRECTORIES:
        try:
            candidate.relative_to(Path(allowed_dir).resolve(strict=False))
            return True
        except (OSError, ValueError):
            continue
    return False


def scan_directory(directory_path):
    """
    批量扫描目录下所有 .py 文件
    返回: 汇总结果 + 每个文件的详细报告
    """
    directory = Path(directory_path)
    if not directory.exists():
        return {"error": f"目录不存在: {directory_path}"}

    if not directory.is_dir():
        return {"error": f"路径不是目录: {directory_path}"}

    # 收集所有 .py 文件
    py_files = list(directory.glob("**/*.py"))

    if not py_files:
        return {"error": f"目录下没有 .py 文件: {directory_path}"}

    # 限制文件数量（防止扫描过多文件）
    if len(py_files) > 100:
        return {"error": f"文件数量过多: {len(py_files)}（上限100个）"}

    results = []
    high_risk_count = 0
    critical_count = 0
    high_risk_samples = []
    critical_samples = []
    error_count = 0

    for file_path in py_files:
        file_path_str = str(file_path)

        # 安全限制检查
        if not is_allowed_path(file_path_str):
            continue

        # 扫描
        detected = scan_py_file(file_path_str)

        if isinstance(detected, dict) and "error" in detected:
            error_count += 1
            results.append({
                "skill_name": file_path.name,
                "file_path": file_path_str,
                "error": detected["error"]
            })
            continue

        # 评分
        risk_info = calculate_risk_score(detected)

        report = {
            "skill_name": file_path.name,
            "file_path": file_path_str,
            "dangerous_api": detected,
            **risk_info
        }
        results.append(report)

        # 统计高危
        if risk_info["risk_level"] in ["high", "critical"]:
            high_risk_count += 1
            high_risk_samples.append(file_path.name)

        if risk_info["risk_level"] == "critical":
            critical_count += 1
            critical_samples.append(file_path.name)

    summary = {
        "total_files_scanned": len(py_files),
        "success_count": len([r for r in results if "error" not in r]),
        "error_count": error_count,
        "high_risk_count": high_risk_count,
        "critical_count": critical_count,
        "high_risk_samples": high_risk_samples,
        "critical_samples": critical_samples
    }

    return {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_directory": directory_path,
        "summary": summary,
        "results": results
    }


# ============================================================
# 6. 保存结果
# ============================================================

def save_scan_result(result, output_path=OUTPUT_JSON_FILE):
    """保存扫描结果到JSON文件"""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        return {"error": f"保存失败: {str(e)}"}


# ============================================================
# 7. Flask HTTP API 服务
# ============================================================

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    """健康检查"""
    return jsonify({
        "service": "skill_scanner",
        "version": "v2.0",
        "status": "running",
        "debug": DEBUG_MODE
    })


@app.route('/scan', methods=['POST'])
def scan_single_file():
    """单文件扫描接口"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供 JSON 请求体"}), 400

    file_path = data.get('file_path')
    if not file_path:
        return jsonify({"error": "缺少 file_path 参数"}), 400

    # 安全限制
    if not is_allowed_path(file_path):
        return jsonify({"error": f"文件路径不在允许目录内: {file_path}"}), 403

    # 扫描
    detected = scan_py_file(file_path)
    if isinstance(detected, dict) and "error" in detected:
        return jsonify(detected), 500

    risk_info = calculate_risk_score(detected)

    result = {
        "module": "skill_scanner",
        "skill_name": os.path.basename(file_path),
        "file_path": file_path,
        "dangerous_api": detected,
        **risk_info
    }

    return jsonify(result)


@app.route('/scan_directory', methods=['POST'])
def scan_directory_api():
    """批量扫描目录接口"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供 JSON 请求体"}), 400

    directory_path = data.get('directory_path')
    if not directory_path:
        return jsonify({"error": "缺少 directory_path 参数"}), 400

    # 安全限制
    if not is_allowed_path(directory_path):
        return jsonify({"error": f"目录路径不在允许目录内: {directory_path}"}), 403

    # 是否保存结果
    save_to_file = data.get('save_to_file', True)

    result = scan_directory(directory_path)
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 500

    # 保存到文件
    if save_to_file:
        save_result = save_scan_result(result)
        if isinstance(save_result, dict) and "error" in save_result:
            return jsonify({"error": save_result["error"]}), 500

    # 包装返回
    response = {
        "module": "skill_scanner",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "saved_to_file": OUTPUT_JSON_FILE if save_to_file else None,
        **result
    }

    return jsonify(response)


@app.route('/batch_scan', methods=['POST'])
def batch_scan():
    """批量扫描多个文件（前端接入用）"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供 JSON 请求体"}), 400

    file_paths = data.get('file_paths', [])
    if not file_paths or not isinstance(file_paths, list):
        return jsonify({"error": "请提供 file_paths 列表"}), 400

    if len(file_paths) > 50:
        return jsonify({"error": f"文件数量过多: {len(file_paths)}（上限50个）"}), 400

    results = []
    for file_path in file_paths:
        if not is_allowed_path(file_path):
            results.append({
                "skill_name": os.path.basename(file_path),
                "file_path": file_path,
                "error": "文件路径不在允许目录内"
            })
            continue

        detected = scan_py_file(file_path)
        if isinstance(detected, dict) and "error" in detected:
            results.append({
                "skill_name": os.path.basename(file_path),
                "file_path": file_path,
                "error": detected["error"]
            })
            continue

        risk_info = calculate_risk_score(detected)
        results.append({
            "module": "skill_scanner",
            "skill_name": os.path.basename(file_path),
            "file_path": file_path,
            "dangerous_api": detected,
            **risk_info
        })

    # 统计
    critical_count = len([r for r in results if r.get("risk_level") == "critical"])
    high_count = len([r for r in results if r.get("risk_level") == "high"])

    return jsonify({
        "module": "skill_scanner",
        "total": len(results),
        "critical_count": critical_count,
        "high_count": high_count,
        "results": results
    })


# ============================================================
# 8. 启动服务
# ============================================================
if __name__ == '__main__':
    if not FLASK_AVAILABLE:
        raise SystemExit("请先安装项目依赖：python -m pip install -r requirements.txt")
    print("=" * 50)
    print("🚀 Skill 扫描服务 v2.0 启动")
    print(f"   Debug 模式: {DEBUG_MODE}")
    print(f"   文件大小限制: {MAX_FILE_SIZE // 1024 // 1024}MB")
    print(f"   目录限制: {'已启用' if ALLOWED_ROOT_DIRECTORIES else '未限制'}")
    print("=" * 50)

    app.run(host='0.0.0.0', port=5000, debug=DEBUG_MODE)

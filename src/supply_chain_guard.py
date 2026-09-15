#!/usr/bin/env python3
"""Package-level supply-chain scanner for Agent plugins, Skills and scripts.

The scanner never imports or executes the target package.  It inspects Python
ASTs, dependency declarations, archive structure, embedded secret filenames,
binary payloads and file hashes.  ZIP files are read in place and are never
extracted, which keeps traversal and zip-bomb checks enforceable.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from redaction import redact_text
from skill_scanner import DangerousCallChecker, calculate_risk_score


SEVERITY_PRIORITY = {"info": 0, "medium": 1, "high": 2, "critical": 3}
DECISION_BY_SEVERITY = {
    "info": ("allow", "low", 0.0),
    "medium": ("warn", "medium", 0.35),
    "high": ("review", "high", 0.65),
    "critical": ("block", "critical", 0.90),
}
IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {
    ".py", ".txt", ".toml", ".json", ".yaml", ".yml", ".cfg", ".ini", ".md", ".lock"
}
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".pyd", ".bat", ".cmd", ".ps1", ".sh"}
SECRET_PATH = re.compile(
    r"(^|/)(\.env($|\.)|id_(rsa|dsa|ed25519)|credentials?\.(json|ya?ml|txt)|"
    r"secrets?\.(json|ya?ml|txt)|[^/]+\.(pem|key))$",
    re.I,
)
DIRECT_URL = re.compile(r"(@\s*(https?|git\+|file:)|^(https?|git\+|file:))", re.I)
DEPENDENCY_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


class SupplyChainError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _finding(rule_id: str, severity: str, file_path: str, evidence: str) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file_path,
        "evidence": redact_text(str(evidence))[:300],
    }


def _safe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(normalized)
        and not path.is_absolute()
        and ".." not in path.parts
        and not re.match(r"^[A-Za-z]:", normalized)
        and "\x00" not in normalized
    )


def _decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _parse_requirement(raw: str, file_path: str, findings: list[dict[str, str]]) -> dict[str, Any] | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-r", "--requirement")):
        return {"name": line, "specifier": "included-file", "source": file_path}
    if line.startswith(("--extra-index-url", "--index-url", "--find-links", "-e", "--editable")):
        findings.append(_finding(
            "dependency_source_override", "high", file_path,
            "dependency resolver source or editable install changes the trusted supply path",
        ))
        return {"name": line.split()[0], "specifier": "resolver-option", "source": file_path}
    name_match = DEPENDENCY_NAME.search(line)
    name = name_match.group(1) if name_match else line[:80]
    direct = bool(DIRECT_URL.search(line))
    if direct:
        findings.append(_finding(
            "direct_url_dependency", "high", file_path,
            f"direct URL or VCS dependency: {name}",
        ))
    exact_pin = bool(re.search(r"===?\s*[^,;\s*]+", line)) and "*" not in line
    if not exact_pin and not direct:
        findings.append(_finding(
            "dependency_not_exactly_pinned", "medium", file_path,
            f"dependency is not exactly pinned: {name}",
        ))
    return {
        "name": name,
        "specifier": line,
        "source": file_path,
        "exact_pin": exact_pin,
        "direct_url": direct,
    }


def _python_findings(text: str, file_path: str) -> tuple[list[dict[str, str]], list[str]]:
    try:
        tree = ast.parse(text, filename=file_path)
    except SyntaxError as exc:
        return [
            _finding("python_ast_parse_failure", "high", file_path, f"line {exc.lineno}: {exc.msg}")
        ], []
    checker = DangerousCallChecker()
    checker.visit(tree)
    apis = list(checker.detected_apis)
    if not apis:
        return [], []
    risk = calculate_risk_score(apis)
    severity = {
        "low": "info",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }.get(str(risk.get("risk_level")), "critical")
    return [
        _finding("dangerous_python_behavior", severity, file_path, ", ".join(apis))
    ], apis


class SupplyChainGuard:
    def __init__(
        self,
        *,
        max_files: int = 1_000,
        max_file_bytes: int = 2 * 1024 * 1024,
        max_total_bytes: int = 50 * 1024 * 1024,
        max_archive_ratio: float = 100.0,
    ) -> None:
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_archive_ratio = max_archive_ratio

    def _directory_files(
        self, root: Path, findings: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for directory in sorted(directories):
                candidate = current_path / directory
                relative = candidate.relative_to(root).as_posix()
                if directory in IGNORED_DIRECTORIES:
                    continue
                if candidate.is_symlink():
                    findings.append(_finding("package_symlink", "high", relative, "directory symlink"))
                    continue
                kept.append(directory)
            directories[:] = kept
            for filename in sorted(filenames):
                path = current_path / filename
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    findings.append(_finding("package_symlink", "high", relative, "file symlink"))
                    continue
                try:
                    size = path.stat().st_size
                except OSError as exc:
                    findings.append(_finding("file_stat_failure", "high", relative, str(exc)))
                    continue
                if size > self.max_file_bytes:
                    findings.append(_finding(
                        "oversized_package_file", "high", relative,
                        f"{size} bytes exceeds analysis limit {self.max_file_bytes}",
                    ))
                    digest = hashlib.sha256()
                    try:
                        with path.open("rb") as stream:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                digest.update(chunk)
                        records.append({"path": relative, "size": size, "sha256": digest.hexdigest(), "data": None})
                    except OSError as exc:
                        findings.append(_finding("file_read_failure", "high", relative, str(exc)))
                    continue
                try:
                    data = path.read_bytes()
                except OSError as exc:
                    findings.append(_finding("file_read_failure", "high", relative, str(exc)))
                    continue
                records.append({"path": relative, "size": size, "sha256": _sha256(data), "data": data})
        return records

    def _archive_files(
        self, archive: Path, findings: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            stream = zipfile.ZipFile(archive)
        except (OSError, zipfile.BadZipFile) as exc:
            raise SupplyChainError(f"invalid ZIP archive: {exc}") from exc
        with stream:
            infos = stream.infolist()
            if len(infos) > self.max_files:
                findings.append(_finding(
                    "archive_entry_limit", "critical", archive.name,
                    f"{len(infos)} entries exceeds limit {self.max_files}",
                ))
            total_uncompressed = sum(item.file_size for item in infos)
            total_compressed = sum(item.compress_size for item in infos)
            if total_uncompressed > self.max_total_bytes:
                findings.append(_finding(
                    "archive_uncompressed_size_limit", "critical", archive.name,
                    f"{total_uncompressed} bytes exceeds limit {self.max_total_bytes}",
                ))
            overall_ratio = total_uncompressed / max(total_compressed, 1)
            if total_uncompressed > 1024 * 1024 and overall_ratio > self.max_archive_ratio:
                findings.append(_finding(
                    "archive_compression_bomb", "critical", archive.name,
                    f"compression ratio {overall_ratio:.1f}:1",
                ))
            seen: set[str] = set()
            for info in infos[: self.max_files]:
                name = info.filename.replace("\\", "/")
                if info.is_dir():
                    continue
                if not _safe_archive_name(name):
                    findings.append(_finding("archive_path_traversal", "critical", name, "unsafe archive path"))
                    continue
                normalized = str(PurePosixPath(name))
                key = normalized.casefold()
                if key in seen:
                    findings.append(_finding("archive_duplicate_path", "high", normalized, "duplicate path"))
                    continue
                seen.add(key)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    findings.append(_finding("package_symlink", "high", normalized, "archive symlink"))
                    continue
                if info.flag_bits & 0x1:
                    findings.append(_finding("encrypted_archive_entry", "high", normalized, "encrypted file"))
                    continue
                ratio = info.file_size / max(info.compress_size, 1)
                if info.file_size > 1024 * 1024 and ratio > self.max_archive_ratio:
                    findings.append(_finding(
                        "archive_entry_compression_bomb", "critical", normalized,
                        f"compression ratio {ratio:.1f}:1",
                    ))
                    continue
                if info.file_size > self.max_file_bytes:
                    findings.append(_finding(
                        "oversized_package_file", "high", normalized,
                        f"{info.file_size} bytes exceeds analysis limit {self.max_file_bytes}",
                    ))
                    continue
                try:
                    data = stream.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    findings.append(_finding("file_read_failure", "high", normalized, str(exc)))
                    continue
                records.append({
                    "path": normalized,
                    "size": info.file_size,
                    "sha256": _sha256(data),
                    "data": data,
                })
        return records

    def _single_file(self, path: Path) -> list[dict[str, Any]]:
        data = path.read_bytes()
        if len(data) > self.max_file_bytes:
            raise SupplyChainError(f"file exceeds {self.max_file_bytes} byte limit")
        return [{"path": path.name, "size": len(data), "sha256": _sha256(data), "data": data}]

    def scan(self, package_path: str | Path) -> dict[str, Any]:
        target = Path(package_path).resolve()
        if not target.exists():
            raise SupplyChainError(f"package does not exist: {target}")
        findings: list[dict[str, str]] = []
        if target.is_dir():
            artifact_type = "directory"
            records = self._directory_files(target, findings)
        elif target.suffix.lower() == ".zip":
            artifact_type = "zip"
            records = self._archive_files(target, findings)
        elif target.is_file():
            artifact_type = "file"
            records = self._single_file(target)
        else:
            raise SupplyChainError("package path must be a directory, ZIP or regular file")

        if len(records) > self.max_files:
            findings.append(_finding(
                "package_file_limit", "critical", target.name,
                f"{len(records)} files exceeds limit {self.max_files}",
            ))
            records = records[: self.max_files]
        total_bytes = sum(int(item["size"]) for item in records)
        if total_bytes > self.max_total_bytes:
            findings.append(_finding(
                "package_total_size_limit", "critical", target.name,
                f"{total_bytes} bytes exceeds limit {self.max_total_bytes}",
            ))

        dependencies: list[dict[str, Any]] = []
        python_behaviors: list[dict[str, Any]] = []
        for record in records:
            relative = str(record["path"])
            lower = relative.lower()
            suffix = Path(lower).suffix
            if SECRET_PATH.search(lower):
                severity = "critical" if suffix in {".pem", ".key"} else "high"
                findings.append(_finding("embedded_secret_material", severity, relative, "sensitive filename"))
            if suffix in EXECUTABLE_SUFFIXES:
                findings.append(_finding(
                    "executable_or_native_payload", "high", relative,
                    f"executable/native suffix {suffix}",
                ))
            data = record.get("data")
            if not isinstance(data, bytes) or suffix not in TEXT_SUFFIXES:
                continue
            text = _decode_text(data)
            if text is None:
                findings.append(_finding("unexpected_binary_text_file", "high", relative, "contains binary data"))
                continue
            if suffix == ".py":
                py_findings, apis = _python_findings(text, relative)
                findings.extend(py_findings)
                if apis:
                    python_behaviors.append({"file": relative, "dangerous_apis": apis})
            name = Path(lower).name
            if name.startswith("requirements") and suffix == ".txt":
                for line in text.splitlines():
                    dependency = _parse_requirement(line, relative, findings)
                    if dependency:
                        dependencies.append(dependency)
            elif name == "pyproject.toml":
                try:
                    document = tomllib.loads(text)
                    project_dependencies = document.get("project", {}).get("dependencies", [])
                    if isinstance(project_dependencies, list):
                        for value in project_dependencies:
                            dependency = _parse_requirement(str(value), relative, findings)
                            if dependency:
                                dependencies.append(dependency)
                except (tomllib.TOMLDecodeError, AttributeError) as exc:
                    findings.append(_finding("manifest_parse_failure", "high", relative, str(exc)))

        unique_findings: list[dict[str, str]] = []
        seen_findings: set[tuple[str, str, str]] = set()
        for item in findings:
            key = (item["rule_id"], item["severity"], item["file"])
            if key not in seen_findings:
                unique_findings.append(item)
                seen_findings.add(key)
        findings = unique_findings

        severity = max(
            (item["severity"] for item in findings),
            default="info",
            key=SEVERITY_PRIORITY.__getitem__,
        )
        decision, risk_level, floor = DECISION_BY_SEVERITY[severity]
        severity_counts = {
            key: sum(item["severity"] == key for item in findings)
            for key in SEVERITY_PRIORITY
        }
        risk_score = round(min(1.0, floor + 0.02 * max(0, len(findings) - 1)), 2)
        file_manifest = [
            {"path": item["path"], "size": item["size"], "sha256": item["sha256"]}
            for item in records
        ]
        manifest_sha256 = hashlib.sha256(
            json.dumps(file_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "module": "supply_chain_guard",
            "scanner_version": "package_guard_v1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "artifact_name": target.name,
            "artifact_type": artifact_type,
            "decision": decision,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "reason": "no package-level risk found" if not findings else f"highest finding severity: {severity}",
            "matched_rules": list(dict.fromkeys(item["rule_id"] for item in findings)),
            "evidence": findings,
            "summary": {
                "files_scanned": len(records),
                "bytes_scanned": total_bytes,
                "dependencies_declared": len(dependencies),
                "python_files_with_dangerous_behavior": len(python_behaviors),
                "severity_counts": severity_counts,
            },
            "manifest_sha256": manifest_sha256,
            "file_manifest": file_manifest,
            "dependency_inventory": dependencies,
            "python_behaviors": python_behaviors,
            "vulnerability_database_checked": False,
            "limitations": [
                "Static analysis does not prove absence of malicious behavior.",
                "Dependency inventory is not an online vulnerability database lookup.",
                "Production admission should additionally verify signatures and trusted publishers.",
            ],
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan an Agent Skill/plugin package without executing it")
    parser.add_argument("package", type=Path, help="directory, ZIP archive or source file")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = SupplyChainGuard().scan(args.package)
    except (OSError, SupplyChainError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["decision"] != "block" else 2


if __name__ == "__main__":
    raise SystemExit(main())


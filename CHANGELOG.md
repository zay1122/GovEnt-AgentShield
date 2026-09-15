# Changelog

## 3.0.0 - 2026-09-04

### Windows compatibility fix

- PowerShell setup and combined-start scripts now use ASCII-only console messages, preventing Windows PowerShell 5.1 from misparsing UTF-8 Chinese text without a BOM.
- Windows setup restores the Python-bundled pip with `ensurepip` and no longer forces a pip self-upgrade before installing project dependencies.
- The security pipeline, rules, cases, metrics, and API contract are unchanged.

### Added

- 默认“一键安全检测”页面和 16 条页面/CLI 共用验收案例。
- 跨来源共享实体图、拆分语义关联和受限 Base64 分片重组。
- 双层 URL 编码与 HTML 实体检测视图。
- 运行时可选 Skill 供应链准入，以及逐阶段 `stage_status` 证据。
- Windows 首次配置与日常双服务启动脚本。
- 相对简单版改进说明、困难攻击矩阵和详细交付说明。

### Changed

- 执行顺序调整为单源输入、多源输入、输入总门禁、Skill、Tool、策略与执行。
- `review` 与 `block` 均不视为输入门禁通过；输入未通过时所有下游阶段立即短路。
- 多源工程回归集从 20 条扩展到 30 条，加入拆分引用、拆分语义、编码分片和低误报边界。
- README、架构、字段契约、技术报告和任务书矩阵统一升级到 v3.0。

### Security

- 修复原链路中 Tool Guard 可能先于 MultiSource Guard 运行的问题。
- 增加测试，确保输入阻断后 Skill、Tool、Policy、Task Chain、Registry 与 Execution 均未执行。
- Skill 准入阻断后 Tool Guard 与执行面均未执行。

## 2.0.0 - 2026-08-28

### Added

- RBAC/ABAC policy engine with roles, data classifications, environments and destination controls.
- Session-level Task Chain Guard for split-step data-exfiltration detection.
- Request-fingerprinted approval state machine with no self-approval and one-time consumption.
- Deny-by-default tool registry and safe local execution sandbox.
- SHA-256 hash-chained audit log with credential redaction and integrity verification.
- Bearer-token API authentication with server-side identity resolution.
- Runtime, approval and audit HTTP endpoints.
- Dashboard control center for submitting, approving, blocking and auditing real tasks.
- 320-case Input, 120-case Tool and 100-case Skill reproducible engineering benchmarks.
- Docker, Compose, Windows launch scripts and one-command release verification.
- Architecture, API, deployment, evaluation and 10-minute demo documentation.

### Fixed

- Base64 payloads were previously lower-cased before decoding, silently causing encoded attack misses.
- Skill Scanner previously treated importing `os` as if `os.system` had executed.
- Skill Scanner now resolves common import aliases and restricts HTTP scan paths by default.
- Missing root dependency declaration prevented a clean checkout from running the full test suite.
- Security Pipeline tests now isolate output and no longer contaminate formal aggregation data.
- README and Dashboard status descriptions now match the implemented code.

### Preserved

- Existing Input Guard, Tool Guard, Skill Scanner and Security Pipeline unified fields.
- Existing event and scan identifier formats.
- Existing rule files, canonical test libraries and result aggregation contract.

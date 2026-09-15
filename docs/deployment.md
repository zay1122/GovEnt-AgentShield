# 部署与复现说明

## 本机竞赛演示

1. 安装Python 3.12。
2. 创建虚拟环境并安装`requirements.txt`。
3. 执行`python scripts/verify_release.py`。
4. 分别启动`python src/api.py`与Streamlit Dashboard。
5. 浏览器只访问本机回环地址。

Windows用户也可以使用`scripts/*.bat`。

## Docker

```bash
docker compose build
docker compose up
```

Compose中的端口绑定为`127.0.0.1`，避免原型直接暴露在公网。容器以非root用户运行，根文件系统只读，丢弃全部Linux capabilities，并使用命名卷`agentshield_output`共享运行证据。

导出容器内证据：

```bash
docker compose cp api:/app/output ./output_export
```

## 配置

| 配置 | 位置 |
|---|---|
| 输入检测规则 | `config/input_rules.json` |
| 工具检测规则 | `config/tool_rules.json` |
| 权限与数据分级 | `config/access_policy.json` |
| 本机演示身份摘要 | `config/identities.json` |
| Skill API扫描根目录 | 环境变量`SKILL_SCAN_ROOTS` |
| API监听地址 | `AGENTSHIELD_HOST`、`AGENTSHIELD_PORT` |
| API请求体上限 | `AGENTSHIELD_MAX_REQUEST_BYTES`，默认262144字节 |
| 外部身份文件 | `AGENTSHIELD_AUTH_FILE` |

## 非本机部署前的强制替换项

1. 用OIDC/OAuth2、单位IAM或独立密钥文件替换演示Token。
2. 使用TLS反向代理，不允许明文跨主机传输Token。
3. 将审批文件存储替换为事务数据库。
4. 将审计日志同步到远程SIEM/WORM存储。
5. 工具执行放入容器/微虚机，分别设置网络、文件和系统调用权限。
6. 使用只读镜像，输出目录使用独立最小权限卷。
7. 配置限流、告警、备份和灾难恢复。
8. 将供应链准入接入企业制品库、发布者签名和CVE服务；当前离线扫描不声称完成漏洞库核验。

## 数据清理

`output/`包含任务文本、审批信息和审计证据，可能涉及敏感信息。正式环境需要保留周期、脱敏、访问控制和安全删除策略。不要把开发期完整`output/`推送到公开仓库。

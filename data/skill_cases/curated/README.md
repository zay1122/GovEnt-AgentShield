# Curated Skill Cases

本目录保留自简单版工程的10个人工Skill样例，用于验证细粒度供应链动作。样例中的`ENABLE_REAL_EXEC=False`只是注释性安全标记；扫描器从不导入或运行这些文件。

| 样例 | 场景 | 预期动作 |
|---|---|---|
| skill_01 | 公开政策检索 | allow |
| skill_02 | 普通文件读取 | warn |
| skill_03 | 内部数据写本地文件 | warn |
| skill_04 | 读文件后外传 | block |
| skill_05 | subprocess + shell=True | block |
| skill_06 | 用户输入拼接Shell | block |
| skill_07 | 删除本地文件 | review |
| skill_08 | 读取敏感配置 | review |
| skill_09 | 仅返回命令字符串 | allow |
| skill_10 | 合法日志追加 | allow |

这些结果是工程回归期望，不是第三方独立盲测标签。


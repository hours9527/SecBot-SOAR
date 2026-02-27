# 🛡️ SecBot-SOAR: 轻量级安全编排与 ChatOps 防御矩阵

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production_Ready-orange.svg)

SecBot-SOAR 是一个专为中小企业和个人安全研究者打造的 **轻量级、零信任邮件安全监控与 ChatOps 自动化响应引擎**。它通过 IMAP 协议 7x24 小时静默接管企业邮局，结合深度正则榨汁、本地 YARA-lite 静态规则、附件内存级不落地查杀，以及 VirusTotal 威胁情报网络，实现毫秒级的钓鱼邮件拦截与 Telegram 实时移动端告警。

---

## 🧩 武器库组件说明 (Arsenal Components)

本仓库完整保留了该防御系统从基础分析脚本到双核 SOAR 引擎的演进过程，旨在提供覆盖多种场景的安全自动化工具链：

* **`soar_bot_pro.py` (🔥 核心主程序)**
  融合了多线程并发、邮箱实时监听与 Telegram ChatOps 交互的生产级 SOAR 引擎。支持双链路同时工作（被动防御告警 + 主动研判查询）。
* **`standalone_tools/phishing_analyzer.py` (离线解析器)**
  可独立运行的本地离线邮件分析器，支持对 `.eml` 文件的静态特征深度提取，适合集成到传统的 SOC 工单流水线或沙箱预处理环节中。
* **`standalone_tools/tg_secbot_v1.py` (轻量级探测器)**
  单线程交互式威胁情报查询机器人，剥离了邮件监听模块，极度轻量，适合部署在资源受限的云函数（Serverless）或内网跳板机环境中。

---

## ✨ 核心大厂级特性

* **✉️ 深度邮件拆解与降维去重**：自动剥离伪造发件人头，精准提取正文所有长短链接并降维至主域名，配合“国民级域名白名单”实现极速降噪。
* **🌍 IP 物理溯源穿透雷达**：无视邮件伪装，直击底层路由 `Received` 戳，提取真实发件 IP，联动威胁情报库定位黑产源头（ASN/国家）。
* **🧬 附件内存级不落地查杀**：拦截附件后，在内存中直接计算 SHA-256 特征码并向云端沙箱核验，**彻底杜绝勒索/木马文件落盘导致的主机感染风险**。
* **⚡ 本地 YARA-lite 静态秒杀**：内置高危特征字典，支持毫秒级阻断 `EICAR` 测试附件与 `GTUBE` 垃圾邮件标准字符串，无须消耗云端 API 额度。
* **🤖 AI 威胁行为翻译官**：自动将晦涩的杀软命名（如 `HEUR:Trojan.Win32`）翻译为人类可读的破坏行为画像（如“勒索加密”、“键盘记录”）。

---

## 🚀 极速部署指南

### 1. 环境准备
克隆本项目并安装核心依赖：
```bash
git clone [https://github.com/YourUsername/SecBot-SOAR.git](https://github.com/YourUsername/SecBot-SOAR.git)
cd SecBot-SOAR
pip install -r requirements.txt

```

### 2. 注入密钥配置

将项目根目录下的 `config_template.py` 复制并重命名为 `config.py`（该文件已被内置 `.gitignore` 保护，防止泄露）。
在 `config.py` 中填入您的真实密钥：

* `TG_BOT_TOKEN` & `TG_CHAT_ID`: 您的 Telegram 机器人凭证与个人接收坐标。
* `VT_API_KEY`: VirusTotal 威胁情报调用凭证。
* `EMAIL_ACCOUNT` & `EMAIL_PASSWORD`: 被保护的邮箱账号及 IMAP 专用授权码。

### 3. 引擎点火

执行以下命令启动双核引擎（推荐在云端 Linux 生产环境使用 `tmux` 或 `nohup` 进行 7x24 小时守护进程挂机）：

```bash
python soar_bot_pro.py

```

---

## 📊 战报效果预览

当捕获到真实恶意邮件或高危附件时，您将在手机端收到如下格式的微隔离告警：

> 🚨 **[SOC 恶意附件告警]** 🚨
> ━━━━━━━━━━━━━━━━━━━━━━
> 📧 **邮件主题:** `关于 2026 年第一季度财务报表的通知`
> 📎 **高危附件:** `report.exe`
> 🧬 **SHA-256:** `275a021bbfb6489e54d471899f7db9d1...`
> 🦠 **云端查杀分布 (42家报毒):**
> ┠ 🛡️ Kaspersky: `HEUR:Trojan.Win32.Generic`
> ┠ 🛡️ Microsoft: `Trojan:Win32/Wacatac.B!ml`
> ┗ ...等共 42 家安全引擎拦截

---

## ⚠️ 免责声明

本项目仅供合法授权的企业安全防御建设及个人网络安全学习、研究使用。严禁使用本工具/代码库进行任何非法的钓鱼测试、滥发垃圾邮件或破坏第三方系统稳定性的行为。使用者需严格遵守《中华人民共和国网络安全法》及所在地相关法律法规。

```

---


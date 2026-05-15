<p align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-blue.svg" alt="Version" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License" />
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python" />
  <img src="https://img.shields.io/badge/dependencies-zero-orange.svg" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/rules-14-red.svg" alt="14 Rules" />
  <img src="https://img.shields.io/badge/tests-58%20passed-brightgreen.svg" alt="Tests" />
</p>

<h1 align="center">🛡️ ActionSentry</h1>

<p align="center">
  <strong>Lightweight GitHub Actions Workflow Security Static Analysis Engine</strong><br/>
  轻量级 GitHub Actions 工作流安全静态分析引擎
</p>

<p align="center">
  <a href="#-项目介绍">简体中文</a> ·
  <a href="#-簡體中文繁體版">繁體中文</a> ·
  <a href="#-project-introduction">English</a>
</p>

---

<a id="-项目介绍"></a>

## 🎉 项目介绍

**ActionSentry** 是一款专为 GitHub Actions 工作流设计的安全静态分析（SAST）引擎。它能够深度扫描 `.github/workflows/` 目录下的 YAML 工作流文件，自动检测 **14 类常见安全漏洞与不良实践**，帮助开发者在代码合并前发现并修复潜在的安全风险。

### 🔥 解决的核心痛点

- **供应链攻击防护**：检测未固定版本的 Action 引用，防止恶意代码注入
- **权限泄漏预警**：发现过度权限配置和密钥继承问题
- **命令注入防御**：识别不受信任输入直接用于 shell 命令的危险模式
- **CI/CD 安全审计**：一键生成 SARIF 报告，无缝集成 GitHub Code Scanning

### ✨ 自研差异化亮点

| 特性 | ActionSentry | 其他同类工具 |
|------|-------------|-------------|
| **外部依赖** | 🟢 零依赖（纯 Python 标准库） | 🔴 需要 Ruby / Node.js 运行时 |
| **安装方式** | 🟢 `pip install` 或直接运行 | 🔴 需要编译安装 |
| **输出格式** | 🟢 终端 / JSON / SARIF / Markdown | 🟡 仅终端或 JSON |
| **自动修复** | 🟢 内置 `--fix` 自动修复引擎 | 🔴 仅检测不修复 |
| **规则扩展** | 🟢 基于类的规则架构，易于扩展 | 🟡 配置式规则，灵活性有限 |
| **配置文件** | 🟢 支持 `.actionsentry.yml` 项目配置 | 🟡 无或有限配置 |

---

<a id="-核心特性"></a>

## ✨ 核心特性

### 🔍 14 条内置安全规则

| 规则 ID | 严重级别 | 描述 |
|---------|---------|------|
| 🔴 `CMD-001` | **HIGH** | **命令注入**：不受信任的输入直接用于 shell 命令 |
| 🔴 `SEC-001` | **HIGH** | **继承密钥**：`secrets: inherit` 可能将密钥泄漏到 fork 仓库 |
| 🔴 `SEC-002` | **HIGH** | **硬编码密钥**：在环境变量中发现潜在的密钥/令牌 |
| 🔴 `TRG-001` | **HIGH** | **危险触发器**：`pull_request_target` 可执行来自 fork 的不受信任代码 |
| 🔴 `ENV-001` | **HIGH** | **环境变量注入**：不受信任的输入赋值给环境变量 |
| 🔴 `SEC-004` | **HIGH** | **危险令牌访问**：GITHUB_TOKEN 传递给外部 Action |
| 🟡 `PERM-001` | **MEDIUM** | **过度权限**：使用 `write-all` / `read-all` |
| 🟡 `PIN-001` | **MEDIUM** | **未固定 Action**：使用分支/标签引用而非 commit SHA |
| 🟡 `SEC-003` | **MEDIUM** | **自托管 Runner**：使用自托管 Runner 存在持久化威胁风险 |
| 🟡 `EXE-001` | **MEDIUM** | **危险脚本执行**：`actions/github-script` 中的危险操作 |
| 🟡 `AUT-001` | **MEDIUM** | **自动合并检测**：自动合并操作可能绕过代码审查 |
| 🟡 `CHK-001` | **MEDIUM** | **持久化凭据**：`actions/checkout` 的 `persist-credentials: true` |
| 🔵 `WRK-001` | **LOW** | **未限制触发器**：工作流触发器未限制分支或路径 |
| 🔵 `SHL-001` | **LOW** | **Shell 问题**：检测 `eval`、`curl|bash`、`chmod 777` 等危险模式 |

### 📤 多格式输出

- 🖥️ **终端输出**：彩色分级显示，一目了然
- 📋 **JSON 输出**：结构化数据，便于 CI/CD 集成
- 📊 **SARIF v2.1.0**：无缝对接 GitHub Code Scanning
- 📝 **Markdown 报告**：生成安全审计报告文档

### 🔧 自动修复引擎

```bash
# 一键自动修复可修复的安全问题
python -m actionsentry scan --fix
```

支持自动修复：过度权限降级、持久化凭据关闭等常见问题。

### ⚙️ 项目级配置

在项目根目录创建 `.actionsentry.yml`：

```yaml
# .actionsentry.yml
ignore:
  - PIN-001    # 忽略未固定 Action 规则
  - WRK-001    # 忽略未限制触发器规则

severity:
  SHL-001: INFO  # 将 Shell 问题降级为 INFO

exclude:
  - .github/workflows/internal-*.yml  # 排除内部工作流
```

---

<a id="-快速开始"></a>

## 🚀 快速开始

### 📋 环境要求

- **Python 3.8+**（无需安装任何第三方依赖）

### 📦 安装

```bash
# 方式一：直接下载使用（推荐）
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry

# 方式二：pip 安装
pip install .

# 方式三：无需安装，直接运行
python -m actionsentry version
```

### 🏃 本地启动

```bash
# 扫描当前项目的 GitHub Actions 工作流
python -m actionsentry scan

# 扫描指定目录
python -m actionsentry scan /path/to/your/project

# 仅显示 HIGH 级别问题
python -m actionsentry scan --severity HIGH

# 输出 JSON 格式（用于 CI/CD 集成）
python -m actionsentry scan --json

# 输出 SARIF 格式（用于 GitHub Code Scanning）
python -m actionsentry scan --sarif > results.sarif

# 输出 Markdown 报告
python -m actionsentry scan --markdown > security-report.md

# 自动修复可修复的问题
python -m actionsentry scan --fix

# 忽略特定规则
python -m actionsentry scan --ignore PIN-001,WRK-001

# 查看所有可用规则
python -m actionsentry list-rules

# 查看版本号
python -m actionsentry version
```

---

<a id="-详细使用指南"></a>

## 📖 详细使用指南

### 🔗 集成到 GitHub Actions

在 CI/CD 中集成 ActionSentry，每次推送自动扫描工作流安全：

```yaml
# .github/workflows/actionsentry.yml
name: ActionSentry Security Scan

on:
  push:
    paths:
      - '.github/workflows/**'
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ActionSentry
        run: pip install git+https://github.com/gitstq/ActionSentry.git

      - name: Scan Workflows
        run: |
          python -m actionsentry scan --sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### 🎯 典型使用场景

#### 场景一：新项目安全检查

```bash
# 克隆项目后，立即扫描工作流安全
git clone https://github.com/your-org/your-project.git
cd your-project
python -m actionsentry scan
```

#### 场景二：CI/CD 质量门禁

```bash
# 在 CI 中扫描，发现 HIGH 级别问题时返回非零退出码
python -m actionsentry scan --severity HIGH --json
if [ $? -ne 0 ]; then
  echo "❌ 发现高危安全问题，请修复后再合并"
  exit 1
fi
```

#### 场景三：批量修复

```bash
# 先预览可修复的问题
python -m actionsentry scan --fix --dry-run

# 确认后执行自动修复
python -m actionsentry scan --fix
```

### 📊 输出示例

```
ActionSentry - GitHub Actions Workflow Security Scanner

  ./github/workflows/deploy.yml

    🔴 HIGH CMD-001: Command Injection
       File: ./github/workflows/deploy.yml:24
       Context: Expression: ${{ github.event.inputs.user_input }} in run step
       Code: - run: echo "${{ github.event.inputs.user_input }}"
       Fix: Avoid using untrusted input directly in shell commands.

    🟡 MEDIUM PIN-001: Unpinned Action
       File: ./github/workflows/deploy.yml:12
       Context: Action 'actions/checkout@v3' uses tag reference '@v3'
       Code: - uses: actions/checkout@v3
       Fix: Pin to a specific commit SHA: actions/checkout@<commit-sha>

  Scanned 3 file(s) | Found 5 issue(s) | 2 HIGH | 2 MEDIUM | 1 LOW
  Scan completed in 12ms
```

---

<a id="-设计思路与迭代规划"></a>

## 💡 设计思路与迭代规划

### 🎨 设计理念

1. **零依赖哲学**：仅使用 Python 标准库，包括自研的 YAML 解析器，确保在任何 Python 环境中开箱即用
2. **规则即代码**：每条安全规则都是一个独立的 Python 类，继承自 `BaseRule`，便于扩展和自定义
3. **安全左移**：在代码提交前发现工作流安全问题，而非事后补救
4. **开发者友好**：清晰的错误提示、精准的代码定位、可操作的修复建议

### 🏗️ 技术选型

| 组件 | 选型 | 原因 |
|------|------|------|
| 语言 | Python 3.8+ | GitHub Actions 用户群体广泛，上手成本低 |
| YAML 解析 | 自研解析器 | 零外部依赖，支持工作流常用语法 |
| CLI 框架 | argparse | 标准库内置，无需额外安装 |
| 输出格式 | 终端/JSON/SARIF/MD | 覆盖人读和机读场景 |

### 🗺️ 后续迭代计划

- [ ] **v1.1.0**：支持自定义规则（通过 Python 插件）
- [ ] **v1.2.0**：支持 GitHub App 模式，自动创建 Issue
- [ ] **v1.3.0**：增加基线文件（baseline）功能，只报告新增问题
- [ ] **v2.0.0**：支持扫描 GitHub Actions Reusable Workflows
- [ ] **v2.1.0**：支持扫描 GitHub Actions Composite Actions

---

<a id="-打包与部署指南"></a>

## 📦 打包与部署指南

### 📌 作为 Python 包安装

```bash
# 从源码安装
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
pip install .

# 验证安装
actionsentry version
# 或
python -m actionsentry version
```

### 📌 作为独立脚本使用

```bash
# 下载后直接运行，无需安装
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
python -m actionsentry scan /path/to/project
```

### 📌 集成到 pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/ActionSentry
    rev: v1.0.0
    hooks:
      - id: actionsentry
        args: ['--severity', 'HIGH']
```

### 🔧 兼容环境

| 环境 | 支持情况 |
|------|---------|
| Python 3.8 | ✅ 支持 |
| Python 3.9 | ✅ 支持 |
| Python 3.10 | ✅ 支持 |
| Python 3.11 | ✅ 支持 |
| Python 3.12 | ✅ 支持 |
| Python 3.13 | ✅ 支持 |
| Windows | ✅ 支持 |
| macOS | ✅ 支持 |
| Linux | ✅ 支持 |

---

<a id="-贡献指南"></a>

## 🤝 贡献指南

我们欢迎并鼓励社区贡献！以下是参与贡献的方式：

### 📋 提交 Issue

- 🐛 **Bug 反馈**：请包含复现步骤、预期行为和实际行为
- 💡 **功能建议**：请描述使用场景和期望的行为
- 📝 **规则建议**：欢迎提出新的安全检测规则

### 🔀 提交 PR

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature`
3. 编写代码和测试
4. 确保所有测试通过：`python tests/test_runner.py`
5. 提交 PR，描述变更内容

### 📐 代码规范

- 遵循 PEP 8 编码规范
- 新规则需继承 `BaseRule` 类
- 新规则需包含对应的测试用例
- 提交信息遵循 Angular 规范：`feat:` / `fix:` / `docs:` / `refactor:`

---

<a id="-开源协议说明"></a>

## 📄 开源协议说明

本项目基于 [MIT License](LICENSE) 开源。

```
MIT License

Copyright (c) 2025 ActionSentry Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">Lobster Dev</a>
</p>

---

<a id="-簡體中文繁體版"></a>

---

<h1 align="center">🛡️ ActionSentry</h1>

<p align="center">
  <strong>輕量級 GitHub Actions 工作流程安全靜態分析引擎</strong><br/>
  Lightweight GitHub Actions Workflow Security Static Analysis Engine
</p>

<p align="center">
  <a href="#-项目介绍">简体中文</a> ·
  <a href="#-簡體中文繁體版">繁體中文</a> ·
  <a href="#-project-introduction">English</a>
</p>

---

<a id="-項目介紹-1"></a>

## 🎉 項目介紹

**ActionSentry** 是一款專為 GitHub Actions 工作流程設計的安全靜態分析（SAST）引擎。它能夠深度掃描 `.github/workflows/` 目錄下的 YAML 工作流程檔案，自動偵測 **14 類常見安全漏洞與不良實踐**，協助開發者在程式碼合併前發現並修復潛在的安全風險。

### 🔥 解決的核心痛點

- **供應鏈攻擊防護**：偵測未固定版本的 Action 引用，防止惡意程式碼注入
- **權限洩漏預警**：發現過度權限配置和密鑰繼承問題
- **命令注入防禦**：識別不受信任輸入直接用於 shell 命令的危險模式
- **CI/CD 安全稽核**：一鍵產生 SARIF 報告，無縫整合 GitHub Code Scanning

### ✨ 自研差異化亮點

| 特性 | ActionSentry | 其他同類工具 |
|------|-------------|-------------|
| **外部依賴** | 🟢 零依賴（純 Python 標準庫） | 🔴 需要 Ruby / Node.js 執行時 |
| **安裝方式** | 🟢 `pip install` 或直接執行 | 🔴 需要編譯安裝 |
| **輸出格式** | 🟢 終端 / JSON / SARIF / Markdown | 🟡 僅終端或 JSON |
| **自動修復** | 🟢 內建 `--fix` 自動修復引擎 | 🔴 僅偵測不修復 |
| **規則擴展** | 🟢 基於類別的規則架構，易於擴展 | 🟡 配置式規則，靈活性有限 |
| **配置檔案** | 🟢 支援 `.actionsentry.yml` 專案配置 | 🟡 無或有限配置 |

---

<a id="-核心特性-1"></a>

## ✨ 核心特性

### 🔍 14 條內建安全規則

| 規則 ID | 嚴重級別 | 描述 |
|---------|---------|------|
| 🔴 `CMD-001` | **HIGH** | **命令注入**：不受信任的輸入直接用於 shell 命令 |
| 🔴 `SEC-001` | **HIGH** | **繼承密鑰**：`secrets: inherit` 可能將密鑰洩漏到 fork 倉庫 |
| 🔴 `SEC-002` | **HIGH** | **硬編碼密鑰**：在環境變數中發現潛在的密鑰/令牌 |
| 🔴 `TRG-001` | **HIGH** | **危險觸發器**：`pull_request_target` 可執行來自 fork 的不受信任程式碼 |
| 🔴 `ENV-001` | **HIGH** | **環境變數注入**：不受信任的輸入賦值給環境變數 |
| 🔴 `SEC-004` | **HIGH** | **危險令牌存取**：GITHUB_TOKEN 傳遞給外部 Action |
| 🟡 `PERM-001` | **MEDIUM** | **過度權限**：使用 `write-all` / `read-all` |
| 🟡 `PIN-001` | **MEDIUM** | **未固定 Action**：使用分支/標籤引用而非 commit SHA |
| 🟡 `SEC-003` | **MEDIUM** | **自託管 Runner**：使用自託管 Runner 存在持久化威脅風險 |
| 🟡 `EXE-001` | **MEDIUM** | **危險腳本執行**：`actions/github-script` 中的危險操作 |
| 🟡 `AUT-001` | **MEDIUM** | **自動合併偵測**：自動合併操作可能繞過程式碼審查 |
| 🟡 `CHK-001` | **MEDIUM** | **持久化憑證**：`actions/checkout` 的 `persist-credentials: true` |
| 🔵 `WRK-001` | **LOW** | **未限制觸發器**：工作流程觸發器未限制分支或路徑 |
| 🔵 `SHL-001` | **LOW** | **Shell 問題**：偵測 `eval`、`curl|bash`、`chmod 777` 等危險模式 |

### 📤 多格式輸出

- 🖥️ **終端輸出**：彩色分級顯示，一目了然
- 📋 **JSON 輸出**：結構化資料，便於 CI/CD 整合
- 📊 **SARIF v2.1.0**：無縫對接 GitHub Code Scanning
- 📝 **Markdown 報告**：產生安全稽核報告文件

### 🔧 自動修復引擎

```bash
# 一鍵自動修復可修復的安全問題
python -m actionsentry scan --fix
```

支援自動修復：過度權限降級、持久化憑證關閉等常見問題。

### ⚙️ 專案級配置

在專案根目錄建立 `.actionsentry.yml`：

```yaml
# .actionsentry.yml
ignore:
  - PIN-001    # 忽略未固定 Action 規則
  - WRK-001    # 忽略未限制觸發器規則

severity:
  SHL-001: INFO  # 將 Shell 問題降級為 INFO

exclude:
  - .github/workflows/internal-*.yml  # 排除內部工作流程
```

---

<a id="-快速開始-1"></a>

## 🚀 快速開始

### 📋 環境要求

- **Python 3.8+**（無需安裝任何第三方依賴）

### 📦 安裝

```bash
# 方式一：直接下載使用（推薦）
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry

# 方式二：pip 安裝
pip install .

# 方式三：無需安裝，直接執行
python -m actionsentry version
```

### 🏃 本地啟動

```bash
# 掃描當前專案的 GitHub Actions 工作流程
python -m actionsentry scan

# 掃描指定目錄
python -m actionsentry scan /path/to/your/project

# 僅顯示 HIGH 級別問題
python -m actionsentry scan --severity HIGH

# 輸出 JSON 格式（用於 CI/CD 整合）
python -m actionsentry scan --json

# 輸出 SARIF 格式（用於 GitHub Code Scanning）
python -m actionsentry scan --sarif > results.sarif

# 輸出 Markdown 報告
python -m actionsentry scan --markdown > security-report.md

# 自動修復可修復的問題
python -m actionsentry scan --fix

# 忽略特定規則
python -m actionsentry scan --ignore PIN-001,WRK-001

# 查看所有可用規則
python -m actionsentry list-rules

# 查看版本號
python -m actionsentry version
```

---

<a id="-詳細使用指南-1"></a>

## 📖 詳細使用指南

### 🔗 整合到 GitHub Actions

在 CI/CD 中整合 ActionSentry，每次推送自動掃描工作流程安全：

```yaml
# .github/workflows/actionsentry.yml
name: ActionSentry Security Scan

on:
  push:
    paths:
      - '.github/workflows/**'
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ActionSentry
        run: pip install git+https://github.com/gitstq/ActionSentry.git

      - name: Scan Workflows
        run: |
          python -m actionsentry scan --sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### 🎯 典型使用場景

#### 場景一：新專案安全檢查

```bash
# 克隆專案後，立即掃描工作流程安全
git clone https://github.com/your-org/your-project.git
cd your-project
python -m actionsentry scan
```

#### 場景二：CI/CD 品質閘門

```bash
# 在 CI 中掃描，發現 HIGH 級別問題時返回非零退出碼
python -m actionsentry scan --severity HIGH --json
if [ $? -ne 0 ]; then
  echo "❌ 發現高危安全問題，請修復後再合併"
  exit 1
fi
```

#### 場景三：批次修復

```bash
# 先預覽可修復的問題
python -m actionsentry scan --fix --dry-run

# 確認後執行自動修復
python -m actionsentry scan --fix
```

### 📊 輸出範例

```
ActionSentry - GitHub Actions Workflow Security Scanner

  ./github/workflows/deploy.yml

    🔴 HIGH CMD-001: Command Injection
       File: ./github/workflows/deploy.yml:24
       Context: Expression: ${{ github.event.inputs.user_input }} in run step
       Code: - run: echo "${{ github.event.inputs.user_input }}"
       Fix: Avoid using untrusted input directly in shell commands.

    🟡 MEDIUM PIN-001: Unpinned Action
       File: ./github/workflows/deploy.yml:12
       Context: Action 'actions/checkout@v3' uses tag reference '@v3'
       Code: - uses: actions/checkout@v3
       Fix: Pin to a specific commit SHA: actions/checkout@<commit-sha>

  Scanned 3 file(s) | Found 5 issue(s) | 2 HIGH | 2 MEDIUM | 1 LOW
  Scan completed in 12ms
```

---

<a id="-設計思路與迭代規劃-1"></a>

## 💡 設計思路與迭代規劃

### 🎨 設計理念

1. **零依賴哲學**：僅使用 Python 標準庫，包含自研的 YAML 解析器，確保在任何 Python 環境中開箱即用
2. **規則即程式碼**：每條安全規則都是一個獨立的 Python 類別，繼承自 `BaseRule`，便於擴展和自訂
3. **安全左移**：在程式碼提交前發現工作流程安全問題，而非事後補救
4. **開發者友善**：清晰的錯誤提示、精準的程式碼定位、可操作的修復建議

### 🏗️ 技術選型

| 元件 | 選型 | 原因 |
|------|------|------|
| 語言 | Python 3.8+ | GitHub Actions 使用者群體廣泛，上手成本低 |
| YAML 解析 | 自研解析器 | 零外部依賴，支援工作流程常用語法 |
| CLI 框架 | argparse | 標準庫內建，無需額外安裝 |
| 輸出格式 | 終端/JSON/SARIF/MD | 涵蓋人讀和機讀場景 |

### 🗺️ 後續迭代計畫

- [ ] **v1.1.0**：支援自訂規則（透過 Python 外掛）
- [ ] **v1.2.0**：支援 GitHub App 模式，自動建立 Issue
- [ ] **v1.3.0**：增加基線檔案（baseline）功能，只報告新增問題
- [ ] **v2.0.0**：支援掃描 GitHub Actions Reusable Workflows
- [ ] **v2.1.0**：支援掃描 GitHub Actions Composite Actions

---

<a id="-打包與部署指南-1"></a>

## 📦 打包與部署指南

### 📌 作為 Python 套件安裝

```bash
# 從原始碼安裝
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
pip install .

# 驗證安裝
actionsentry version
# 或
python -m actionsentry version
```

### 📌 作為獨立腳本使用

```bash
# 下載後直接執行，無需安裝
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
python -m actionsentry scan /path/to/project
```

### 📌 整合到 pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/ActionSentry
    rev: v1.0.0
    hooks:
      - id: actionsentry
        args: ['--severity', 'HIGH']
```

### 🔧 相容環境

| 環境 | 支援情況 |
|------|---------|
| Python 3.8 | ✅ 支援 |
| Python 3.9 | ✅ 支援 |
| Python 3.10 | ✅ 支援 |
| Python 3.11 | ✅ 支援 |
| Python 3.12 | ✅ 支援 |
| Python 3.13 | ✅ 支援 |
| Windows | ✅ 支援 |
| macOS | ✅ 支援 |
| Linux | ✅ 支援 |

---

<a id="-貢獻指南-1"></a>

## 🤝 貢獻指南

我們歡迎並鼓勵社群貢獻！以下是參與貢獻的方式：

### 📋 提交 Issue

- 🐛 **Bug 回饋**：請包含重現步驟、預期行為和實際行為
- 💡 **功能建議**：請描述使用場景和期望的行為
- 📝 **規則建議**：歡迎提出新的安全偵測規則

### 🔀 提交 PR

1. Fork 本倉庫
2. 建立特性分支：`git checkout -b feature/your-feature`
3. 撰寫程式碼和測試
4. 確保所有測試通過：`python tests/test_runner.py`
5. 提交 PR，描述變更內容

### 📐 程式碼規範

- 遵循 PEP 8 編碼規範
- 新規則需繼承 `BaseRule` 類別
- 新規則需包含對應的測試用例
- 提交資訊遵循 Angular 規範：`feat:` / `fix:` / `docs:` / `refactor:`

---

<a id="-開源協議說明-1"></a>

## 📄 開源協議說明

本專案基於 [MIT License](LICENSE) 開源。

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">Lobster Dev</a>
</p>

---

<a id="-project-introduction"></a>

---

<h1 align="center">🛡️ ActionSentry</h1>

<p align="center">
  <strong>Lightweight GitHub Actions Workflow Security Static Analysis Engine</strong><br/>
  轻量级 GitHub Actions 工作流安全静态分析引擎
</p>

<p align="center">
  <a href="#-项目介绍">简体中文</a> ·
  <a href="#-簡體中文繁體版">繁體中文</a> ·
  <a href="#-project-introduction">English</a>
</p>

---

## 🎉 Project Introduction

**ActionSentry** is a security static analysis (SAST) engine purpose-built for GitHub Actions workflows. It deeply scans YAML workflow files in the `.github/workflows/` directory and automatically detects **14 categories of common security vulnerabilities and bad practices**, helping developers identify and fix potential security risks before code is merged.

### 🔥 Core Pain Points Solved

- **Supply Chain Attack Prevention**: Detects unpinned action references to prevent malicious code injection
- **Permission Leak Warning**: Identifies excessive permission configurations and secret inheritance issues
- **Command Injection Defense**: Recognizes dangerous patterns where untrusted input flows directly into shell commands
- **CI/CD Security Audit**: One-click SARIF report generation for seamless GitHub Code Scanning integration

### ✨ Differentiation Highlights

| Feature | ActionSentry | Other Similar Tools |
|---------|-------------|---------------------|
| **External Dependencies** | 🟢 Zero (pure Python stdlib) | 🔴 Requires Ruby / Node.js runtime |
| **Installation** | 🟢 `pip install` or run directly | 🔴 Requires compilation |
| **Output Formats** | 🟢 Terminal / JSON / SARIF / Markdown | 🟡 Terminal or JSON only |
| **Auto-Fix** | 🟢 Built-in `--fix` engine | 🔴 Detection only |
| **Rule Extensibility** | 🟢 Class-based architecture | 🟡 Config-based, limited flexibility |
| **Configuration** | 🟢 `.actionsentry.yml` support | 🟡 None or limited |

---

## ✨ Core Features

### 🔍 14 Built-in Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| 🔴 `CMD-001` | **HIGH** | **Command Injection**: Untrusted input used directly in shell commands |
| 🔴 `SEC-001` | **HIGH** | **Inherited Secrets**: `secrets: inherit` can leak secrets to forked repos |
| 🔴 `SEC-002` | **HIGH** | **Hardcoded Secrets**: Potential secret/token found in environment variables |
| 🔴 `TRG-001` | **HIGH** | **Risky Trigger**: `pull_request_target` can execute untrusted code from forks |
| 🔴 `ENV-001` | **HIGH** | **Environment Variable Injection**: Untrusted input assigned to env vars |
| 🔴 `SEC-004` | **HIGH** | **Dangerous Token Access**: GITHUB_TOKEN passed to external actions |
| 🟡 `PERM-001` | **MEDIUM** | **Excessive Permissions**: Using `write-all` / `read-all` |
| 🟡 `PIN-001` | **MEDIUM** | **Unpinned Action**: Using branch/tag references instead of commit SHA |
| 🟡 `SEC-003` | **MEDIUM** | **Self-Hosted Runner**: Potential persistent threat from self-hosted runners |
| 🟡 `EXE-001` | **MEDIUM** | **Dangerous Script Execution**: Risky operations in `actions/github-script` |
| 🟡 `AUT-001` | **MEDIUM** | **Automatic Merge Detection**: Auto-merge may bypass code review |
| 🟡 `CHK-001` | **MEDIUM** | **Persisted Credentials**: `actions/checkout` with `persist-credentials: true` |
| 🔵 `WRK-001` | **LOW** | **Unrestricted Triggers**: Workflow triggers not restricted to branches/paths |
| 🔵 `SHL-001` | **LOW** | **Shell Issues**: Detects `eval`, `curl|bash`, `chmod 777` patterns |

### 📤 Multiple Output Formats

- 🖥️ **Terminal**: Color-coded severity display
- 📋 **JSON**: Structured data for CI/CD integration
- 📊 **SARIF v2.1.0**: Seamless GitHub Code Scanning integration
- 📝 **Markdown**: Security audit report generation

### 🔧 Auto-Fix Engine

```bash
# Auto-fix fixable security issues with one command
python -m actionsentry scan --fix
```

Supports auto-fixing: excessive permission downgrading, persisted credential disabling, and more.

### ⚙️ Project-Level Configuration

Create `.actionsentry.yml` in your project root:

```yaml
# .actionsentry.yml
ignore:
  - PIN-001    # Ignore unpinned action rule
  - WRK-001    # Ignore unrestricted trigger rule

severity:
  SHL-001: INFO  # Downgrade shell issues to INFO

exclude:
  - .github/workflows/internal-*.yml  # Exclude internal workflows
```

---

## 🚀 Quick Start

### 📋 Requirements

- **Python 3.8+** (no third-party dependencies required)

### 📦 Installation

```bash
# Option 1: Clone and use directly (Recommended)
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry

# Option 2: pip install
pip install .

# Option 3: Run without installation
python -m actionsentry version
```

### 🏃 Usage

```bash
# Scan GitHub Actions workflows in the current project
python -m actionsentry scan

# Scan a specific directory
python -m actionsentry scan /path/to/your/project

# Show only HIGH severity issues
python -m actionsentry scan --severity HIGH

# JSON output (for CI/CD integration)
python -m actionsentry scan --json

# SARIF output (for GitHub Code Scanning)
python -m actionsentry scan --sarif > results.sarif

# Markdown report
python -m actionsentry scan --markdown > security-report.md

# Auto-fix fixable issues
python -m actionsentry scan --fix

# Ignore specific rules
python -m actionsentry scan --ignore PIN-001,WRK-001

# List all available rules
python -m actionsentry list-rules

# Show version
python -m actionsentry version
```

---

## 📖 Detailed Usage Guide

### 🔗 GitHub Actions Integration

Integrate ActionSentry into your CI/CD pipeline for automatic workflow security scanning on every push:

```yaml
# .github/workflows/actionsentry.yml
name: ActionSentry Security Scan

on:
  push:
    paths:
      - '.github/workflows/**'
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ActionSentry
        run: pip install git+https://github.com/gitstq/ActionSentry.git

      - name: Scan Workflows
        run: |
          python -m actionsentry scan --sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### 🎯 Typical Use Cases

#### Use Case 1: New Project Security Check

```bash
# Clone the project and immediately scan workflow security
git clone https://github.com/your-org/your-project.git
cd your-project
python -m actionsentry scan
```

#### Use Case 2: CI/CD Quality Gate

```bash
# Scan in CI, return non-zero exit code when HIGH issues found
python -m actionsentry scan --severity HIGH --json
if [ $? -ne 0 ]; then
  echo "❌ High severity security issues found. Please fix before merging."
  exit 1
fi
```

#### Use Case 3: Batch Fix

```bash
# Preview fixable issues first
python -m actionsentry scan --fix --dry-run

# Execute auto-fix after confirmation
python -m actionsentry scan --fix
```

### 📊 Output Example

```
ActionSentry - GitHub Actions Workflow Security Scanner

  ./github/workflows/deploy.yml

    🔴 HIGH CMD-001: Command Injection
       File: ./github/workflows/deploy.yml:24
       Context: Expression: ${{ github.event.inputs.user_input }} in run step
       Code: - run: echo "${{ github.event.inputs.user_input }}"
       Fix: Avoid using untrusted input directly in shell commands.

    🟡 MEDIUM PIN-001: Unpinned Action
       File: ./github/workflows/deploy.yml:12
       Context: Action 'actions/checkout@v3' uses tag reference '@v3'
       Code: - uses: actions/checkout@v3
       Fix: Pin to a specific commit SHA: actions/checkout@<commit-sha>

  Scanned 3 file(s) | Found 5 issue(s) | 2 HIGH | 2 MEDIUM | 1 LOW
  Scan completed in 12ms
```

---

## 💡 Design Philosophy & Roadmap

### 🎨 Design Principles

1. **Zero-Dependency Philosophy**: Only Python standard library is used, including a custom-built YAML parser, ensuring it works out of the box in any Python environment
2. **Rules as Code**: Each security rule is an independent Python class inheriting from `BaseRule`, making it easy to extend and customize
3. **Shift Security Left**: Discover workflow security issues before code is committed, not after the fact
4. **Developer-Friendly**: Clear error messages, precise code location, actionable fix suggestions

### 🏗️ Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.8+ | Broad GitHub Actions user base, low learning curve |
| YAML Parser | Custom-built | Zero external dependencies, supports common workflow syntax |
| CLI Framework | argparse | Built into stdlib, no extra installation needed |
| Output Formats | Terminal/JSON/SARIF/MD | Covers both human-readable and machine-readable scenarios |

### 🗺️ Roadmap

- [ ] **v1.1.0**: Custom rules support (via Python plugins)
- [ ] **v1.2.0**: GitHub App mode with automatic Issue creation
- [ ] **v1.3.0**: Baseline file support (report only new issues)
- [ ] **v2.0.0**: Scan GitHub Actions Reusable Workflows
- [ ] **v2.1.0**: Scan GitHub Actions Composite Actions

---

## 📦 Packaging & Deployment

### 📌 Install as Python Package

```bash
# Install from source
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
pip install .

# Verify installation
actionsentry version
# or
python -m actionsentry version
```

### 📌 Use as Standalone Script

```bash
# Download and run directly, no installation needed
git clone https://github.com/gitstq/ActionSentry.git
cd ActionSentry
python -m actionsentry scan /path/to/project
```

### 📌 Integrate with pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/ActionSentry
    rev: v1.0.0
    hooks:
      - id: actionsentry
        args: ['--severity', 'HIGH']
```

### 🔧 Compatible Environments

| Environment | Support |
|-------------|---------|
| Python 3.8 | ✅ Supported |
| Python 3.9 | ✅ Supported |
| Python 3.10 | ✅ Supported |
| Python 3.11 | ✅ Supported |
| Python 3.12 | ✅ Supported |
| Python 3.13 | ✅ Supported |
| Windows | ✅ Supported |
| macOS | ✅ Supported |
| Linux | ✅ Supported |

---

## 🤝 Contributing

We welcome and encourage community contributions! Here's how to get involved:

### 📋 Submitting Issues

- 🐛 **Bug Reports**: Include reproduction steps, expected behavior, and actual behavior
- 💡 **Feature Requests**: Describe your use case and expected behavior
- 📝 **Rule Suggestions**: Propose new security detection rules

### 🔀 Submitting PRs

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write code and tests
4. Ensure all tests pass: `python tests/test_runner.py`
5. Submit a PR describing your changes

### 📐 Code Standards

- Follow PEP 8 coding standards
- New rules must inherit from `BaseRule`
- New rules must include corresponding test cases
- Commit messages follow Angular convention: `feat:` / `fix:` / `docs:` / `refactor:`

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">Lobster Dev</a>
</p>

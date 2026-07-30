# RepoProof

## 项目简介

RepoProof 是离线优先、默认只读的仓库发布前审计 CLI。它将文档、CI、Git
过程、分发和疑似凭据要求写入声明式 profile；同一仓库快照和 profile 会得到
确定性的终端、JSON 或 HTML 报告。内置 `ai4se-b` profile 用于 AI4SE B 类项目，
自定义 YAML profile 则可复用同一规则引擎。

## 安装

需要 Python 3.12 或更新版本。在源码根目录执行：

```powershell
python -m pip install -e .
```

安装后可用 `repoproof version` 确认命令可用。

## 运行

在要审计的仓库根目录运行下列命令。`--offline` 禁用远程采集，适合作为默认的
本地自检方式。

```powershell
repoproof audit --profile ai4se-b --offline .
repoproof audit . --format json --output report.json
repoproof audit . --format html --output report.html
repoproof auth login
```

默认输出到终端。只有显式传入 `--output` 时才写入报告文件；审计本身不会修复或
修改被审计仓库。退出码为：无 `FAIL` 时 0、有 `FAIL` 时 1、命令或 profile 错误
时 2、仓库/网络或运行时错误时 3。

## 测试

安装开发依赖并运行静态检查、类型检查和默认测试：

```powershell
python -m pip install -e ".[dev]"
make verify
python -m pytest tests/performance -m performance -q
```

性能测试单独标记，不包含在默认 `pytest` 集合中。

## 分发

发布后，从 GitHub Release 下载
`repoproof-<version>-windows-x86_64.exe` 及同名 `.sha256` 文件，并以
`Get-FileHash -Algorithm SHA256` 核对哈希。1.0 的 Windows x64 单文件程序未作
Authenticode 签名，Windows SmartScreen 可能显示警告；核对校验和后再决定是否
运行。也可以按“安装”中的方式从源码运行。具体 PowerShell 校验步骤见
[`RELEASE.md`](RELEASE.md)。

当前源码版本已更新为 `1.0.0` 发布候选，并包含生成该资产的 tag 触发 Release
workflow；尚未创建发布 tag、GitHub Release 或托管构建结果。真实下载链接与校验
证据将在托管 CI 完成后补充，不以本地候选状态替代。

## 目录结构

- `src/repoproof`：CLI、profile、采集器、规则引擎、报告器和凭据边界。
- `tests`：单元、集成、端到端、安全、交付配置和性能测试。
- `examples`：合规与不合规仓库夹具，用于端到端审计行为。
- `docs/superpowers`：已批准的设计与实现计划。
- `.github/workflows`、`.gitlab-ci.yml`：GitHub Actions 与课程要求的 GitLab
  `unit-test` 配置。
- `pyproject.toml`、`repoproof.spec`、`scripts/write_checksum.ps1`：Python
  打包、Windows 单文件构建和 SHA-256 生成配置。

## 安全边界

RepoProof 默认只读；报告写入必须由用户显式指定 `--output`。仓库路径会被限制在
目标根目录内，YAML 以安全解析和严格 schema 读取，profile 不能执行脚本、表达式
或动态导入。

核心审计不使用 LLM，不执行被审计仓库代码，不上传源码或报告。疑似 Secret 的
输出仅保留位置、类别和短指纹，匹配原文会替换为 `<redacted>`。可选 GitHub 远程
证据只在 profile 需要且未使用 `--offline` 时启用；Token 通过隐藏输入写入操作
系统 keyring，keyring 不可用时拒绝登录，绝不退回明文凭据文件。

## 已知限制

这是静态、声明式检查：它不能证明反思质量、模块职责质量或 TDD 实际先后顺序，
这些由报告的人工复核项和过程证据补充。远程历史或发布信息可能因未配置 Token、
权限或网络不可用而不完整；相应规则会按证据状态降级而非猜测。Secret 检测是有限
模式与熵检查，仍可能误报或漏报，不能替代专业 SAST 或完整 Secret 扫描产品。

1.0 仅计划发布未签名的 Windows x64 二进制；macOS/Linux 可从源码安装，但不承诺
原生单文件二进制。

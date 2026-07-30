# RepoProof 项目反思

## 需求取舍

项目选择了通用声明式策略引擎并内置 `ai4se-b`，而不是硬编码一份课程清单：
`src/repoproof/profile/builtin/ai4se-b.yml` 把课程规则与引擎分开，
`3f84d4e`（`feat: add strict profiles and AI4SE policy`）提供了这条可复用的
路径。`SPEC_PROCESS.md` 的“迭代 1”和已批准的 `15de2c7` 规格记录了选择理由。

没有使用 LLM，是因为离线、可复核的规则结果不应依赖概率性服务或付费 API；没有
开发 WebUI，是因为课程澄清允许 CLI 加托管 Release，而有限时间应优先投向规则、
测试和安全边界。这些范围也由 `SPEC.md` 的“不做”条目和 `README.md` 的命令行
入口明确约束。

## 架构与确定性

`src/repoproof/app.py` 负责组装，collectors 只生成 Evidence，`rules.py` 只从
Profile 和 Evidence 推导 Finding，reporters 从同一 AuditReport 渲染三种格式。
这使 `tests/e2e/test_examples.py::test_repeated_audits_are_semantically_identical` 和
`tests/e2e/test_report_parity.py::test_console_json_and_html_have_identical_finding_identity_and_summary`
能检验可重复与报告同源性；相应报告器交付提交为 `ee2a770`。

这种分层也意味着静态规则保持克制：它能判断已声明的文件、标题、CI job、Git
证据、分发配置和扫描发现，不能声称理解自然语言反思的质量或开发过程的真实顺序。
这些刻意不自动化的项目被 profile 的 `manual_checks` 和人工复核保留。

## 安全与凭据治理

非披露测试改变了实现优先级。`tests/e2e/test_non_disclosure.py::test_canary_is_absent_from_console_json_html_and_errors`
要求测试诱饵不出现在任何报告或错误输出；`ac29429` 建立了非披露 Secret Evidence，
随后一系列 redaction 修复提交（例如 `e4dc334`、`a2163d0`）收紧了截断和异常路径。

Token 的生命周期集中在 `src/repoproof/credentials.py` 和 CLI 的 `auth` 子命令。
`tests/integration/test_cli_auth.py::test_auth_lifecycle_never_prints_token` 覆盖不回显，
`4f678d8` 记录了 keyring 实现。系统 keyring 不可用即报用法错误，不存在明文回退；
远程 GitHub 证据在离线或 Token 缺失时降级，相关行为见
`tests/integration/test_remote_degradation.py::test_missing_token_skips_remote_rule_without_runtime_exit`。
根目录 `.repoproofallowlist.yml` 仅以规则 ID、路径和短指纹抑制测试夹具中的已知
诱饵及常量，不保存原值；这使对本仓库的自审仍能区分测试材料与未知发现。

## TDD 与评审证据

实现计划 `docs/superpowers/plans/2026-07-29-repoproof-implementation.md` 为每个任务
规定 RED、最小实现、GREEN 和 focused commit。可审计的交付历史列在 `PLAN.md`：
从 `7d4fbc2` 的领域契约到 `e709c69` 的交付自动化均可用 `git log` 复核。

本任务的课程文档行为测试 `tests/unit/test_course_documents.py::test_course_documents_pass_the_bundled_profile`
先于文档完成而运行，初次退出码为 1，原因是 required documents/sections/ledger
尚不完整；最终 GREEN、静态检查和全套验证结果记录在 `AGENT_LOG.md`。计划自审已在
`SPEC_PROCESS.md` 中记录；截至本反思撰写时，尚未进行独立托管 PR 评审，不能把本地
检查表述为外部代码评审。

## CI、分发与限制

`e709c69` 增加 GitHub Actions 的 Python 3.12/3.13 verify workflow、GitLab 的
`unit-test` job 和 Windows Release workflow；`0321c8c` 加入 `RELEASE.md` 的
校验和与未签名提示。`tests/unit/test_delivery_config.py::test_release_is_tag_only_and_validates_artifacts_before_publishing`
验证配置结构，但不等同于真实托管 runner 或已发布资产。

目前 Release workflow、校验脚本和 `repoproof.spec` 已在仓库中；PR、托管 CI、tag、
Release、下载的 exe 和实际 checksum 验证仍是 Task 15 的待办事实。因此 Windows
二进制仍须视为未签名，且不能把 workflow 文件的存在宣称为发布已完成。

Task 14 的 `--offline` 自审结果为 0 个 `FAIL`、0 个 `WARN`、1 个 `SKIP`：
`git.process-evidence` 在本地没有 merge 且离线模式禁止查询可选远程 PR 证据时只能
诚实地跳过。它不表示已有 PR 或托管 CI；这些证据仍须在 Task 15 实际产生。

## 如果继续迭代

下一步应先完成独立评审和受保护分支上的托管 CI，再创建 tag 并下载验证 Release
资产。产品层面可在保持“无代码执行、无明文凭据回退”的边界下，增加更多声明式
规则和更精细的 Secret 误报治理。任何扩展都应先通过 profile schema 和端到端
行为测试，而不是以 LLM 判断或静态源码文本清单替代可观察审计结果。

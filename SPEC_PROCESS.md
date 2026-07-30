# SPEC_PROCESS

## 文档状态

Superpowers brainstorming 的四节设计及最终书面规约均已获得学生批准。规格提交为
`15de2c7`（`docs: define RepoProof specification`），实现计划提交为 `52d36a8`
（`docs: plan RepoProof implementation`）。实现位于隔离分支
`agent/implementation-repoproof`；Task 14 正在补齐 AC-19/AC-20 的课程文档与过程
证据。下方“前置上下文”保留设计开始前的真实历史。

## 实现状态与外部证据

- **已批准范围**：`SPEC.md` 是验收的权威来源；正式设计记录位于
  `docs/superpowers/specs/2026-07-29-repoproof-design.md`，实现计划位于
  `docs/superpowers/plans/2026-07-29-repoproof-implementation.md`。
- **实现台账**：根目录 `PLAN.md` 用实际 Git feature commit 记录已完成的 Task 1–13；
  Task 14 仅在其提交创建后才可标为 completed，Task 15 仍待执行。
- **已确认澄清**：助教允许 CLI + GitHub Release，因此不实现 WebUI；核心审计不用
  LLM 或付费 API；PLAN commit 证据由 `markdown_sections` 的可选检查承载，不新增
  第七种规则；Secret allowlist 不保存原文，`manual_checks` 不伪装成自动结论。
- **本地验证**：Task 14 的 RED、GREEN、离线自审、Ruff、mypy、`git diff --check`
  和 Makefile `verify` 目标的等价直接命令结果记录在 `AGENT_LOG.md`。当前环境没有
  `make`，因此不把该命令表述为已执行；这些均为本地证据，不是托管 CI。
- **PR / 托管 CI / Release**：截至此文档更新时均为 pending。远程 `origin` 只记录
  `main`；尚未创建 implementation branch 的 PR，尚无可链接的托管 CI run，未创建
  `v1.0.0` tag、GitHub Release 或可下载 Windows 资产。Task 15 必须在真实外部动作
  完成后补充 URL、artifact 和 checksum 证据，不能预填。

## 前置上下文

### 决策 1：选择 B 而不是 A

- **原始问题**：Coding Agent Harness 与普通应用项目哪一个更适合当前条件？
- **分析**：A 需要自研 Agent 主循环、工具分发、记忆、治理、反馈和 mock LLM 测试；B 可以选择确定性普通应用，风险更可控。
- **学生决定**：选择 B。
- **影响**：项目不会为了“看起来像 AI 项目”而加入自主 Agent；若使用外部 API，也只作为普通确定性功能。

### 决策 2：CLI Release 而不是强制 WebUI

- **原始矛盾**：通用要求允许 CLI，但最终清单写有“必须提供 WebUI”。
- **外部澄清**：助教明确 A/B 均可仅提供 CLI 和托管平台 Release 链接；WebUI 是可选增强。
- **决定**：优先选择 CLI + GitHub Release。
- **影响**：将有限时间投入核心规则机制、测试、安全和分发质量，而不是额外维护 WebUI。

### 决策 3：不把 API Key 当作开工前置条件

- **原始疑问**：是否必须先准备 LLM API Key？
- **分析**：B 项目不强制调用 LLM。核心开发和测试应能离线运行；若加入 GitHub 私有仓库支持，令牌只是可选能力，必须安全存储且可查看状态、更新和清除。
- **决定**：核心功能不依赖付费 API；是否加入可选 GitHub 鉴权能力在正式 brainstorming 中确定。

## 候选方向：RepoProof

RepoProof 是一个发布前仓库审计与证据报告 CLI。目标用户是需要在提交、课程验收或小型发布前进行自检的学生和开发团队。

初步价值主张：

> 将散落在作业要求、团队约定和发布清单中的规则变成可重复运行的确定性检查，在提交前发现缺失文档、CI 错误、测试证据不足、分发配置缺失和疑似凭据泄漏。

此候选方向在当时尚未通过 Superpowers brainstorming；后续四节正式设计已逐节签字，最终边界以 `SPEC.md` 为准。

## 正式阶段记录要求

本过程文档按课程要求记录：

1. 用户与真实使用场景迭代；
2. 功能模块、输入输出、错误与明确不做范围迭代；
3. 架构、安全、分发和客观验收标准迭代；
4. `writing-plans` 后由不同类型智能体执行冷启动试验；
5. 根据冷启动问题记录 SPEC/PLAN 修订前后差异。

## Superpowers 正式 brainstorming

### 迭代 1：目标用户与产品定位

**时间**：2026-07-29 16:55
**触发技能**：`using-superpowers`、`brainstorming`

**关键问题**：RepoProof 应当是通用仓库发布审计工具、仅服务 AI4SE 的作业检查器，还是以凭据泄漏为主的安全扫描器？

**已有约束与授权**：

- 学生已选择 B 类项目，并授权 Codex 在必须人工决定前自主推进。
- 助教允许以 CLI + GitHub Release 交付。
- 项目必须具有真实价值、至少三个清晰模块、确定性测试、CI、安全边界和完整过程证据。
- 在 SPEC、PLAN 与冷启动验证完成前不得编写实现。

**三种方向比较**：

1. **可扩展策略引擎 + 内置 AI4SE 模板（采用）**
   - 优点：既直接服务本次作业，又能由其他课程或小团队复用；规则、证据与报告形成清晰模块边界；可通过新增 YAML profile 扩展。
   - 代价：需要设计稳定的规则 schema、证据模型和失败语义。
2. **硬编码 AI4SE 检查清单**
   - 优点：实现最短、验收直接。
   - 缺点：一次性脚本特征明显，扩展性和工程深度不足，较难证明真实用户价值。
3. **以秘密泄漏检测为核心**
   - 优点：安全价值明确，可深入模式匹配、熵检测和脱敏。
   - 缺点：与“发布证据治理”的主线偏离，误报治理会挤占课程交付时间，也容易与成熟工具重复。

**决策**：采用方向 1。RepoProof 是通用、离线优先、默认只读的发布前仓库审计 CLI，并内置 `ai4se-b` profile。秘密检测作为其中一个证据采集器，而不是产品全部。

**成功标准草案**：

- 对一个本地 Git 仓库执行单条命令即可完成审计。
- 同一仓库与同一 profile 的结果确定、可重复且不依赖 LLM。
- 发现必备文档、CI、测试/分发配置、Git 过程与疑似凭据问题。
- 输出终端摘要和结构化报告，并使用稳定退出码支持 CI。
- 默认不修改目标仓库、不上传源码、不回显疑似凭据明文。
- 以 Windows x64 单文件 CLI 的 GitHub Release 作为最低分发目标。

**设计签字**：学生于后续对话明确回复“批准”，确认第 1 节产品边界与主流程。

### 迭代 2：架构与模块边界

**关键设计**：

- CLI 层仅处理命令和输入输出。
- Profile 模块加载并验证内置或自定义 YAML 规则；规则不能执行任意代码。
- Collectors 分别采集文件/Markdown、Git、CI、测试/分发、疑似凭据和可选 GitHub 远程证据。
- Rule Engine 只接收结构化 Evidence 并产生 Finding，不直接访问文件、Git 或网络。
- Reporters 将同一 AuditReport 渲染为终端、JSON 和自包含 HTML。
- Credential Store 通过操作系统钥匙串保存可选 GitHub Token，支持隐藏录入、状态、更新和清除。

**边界理由**：采集、判断、展示和凭据访问互相隔离，使每一层都能在无网络、无真实凭据的情况下确定性测试。

**设计签字**：学生明确回复“批准”，确认第 2 节架构与模块边界。

### 迭代 3：规则语义、错误与安全

**关键修正**：将“发现问题”拆分为稳定状态与退出码，避免报告展示、CI 判定和程序故障混为一谈。

- 规则结果固定为 `PASS`、`WARN`、`FAIL`、`SKIP`。
- 退出码固定为：0 无 FAIL；1 审计完成但有 FAIL；2 命令/profile 错误；3 仓库、网络或内部运行错误。
- 首版规则仅允许预定义类型，禁止 profile 执行脚本或动态导入。
- 路径规范化后必须留在仓库根目录内；不跟随越界符号链接。
- Secret 输出只能包含位置、类别和短指纹，原值必须脱敏。
- GitHub Token 只经隐藏输入进入系统钥匙串；离线审计不要求 Token。

**设计签字**：学生明确回复“批准”，确认第 3 节规则、错误与安全设计。

### 迭代 4：技术、测试、性能与分发

**决策**：

- Python 3.12+；Typer、Pydantic、PyYAML、Rich、markdown-it-py、pathspec、keyring、HTTPX。
- Pytest/Hypothesis 执行单元、集成、安全、端到端和性质测试。
- PyInstaller 构建未签名 Windows x64 单文件产物。
- GitHub Actions 执行测试、lint、类型检查、构建、smoke test 和 Release。
- 同时提供含 `unit-test` job 的 `.gitlab-ci.yml`。
- 10,000 个候选文件、500 MiB 仓库的离线审计目标为 15 秒内完成。

**设计签字**：学生明确回复“批准”，确认第 4 节技术、测试、性能与分发设计。

### 规约落盘

- 课程规范：`SPEC.md`
- Superpowers 设计文档：`docs/superpowers/specs/2026-07-29-repoproof-design.md`
- 两份文档基于四节已批准设计；`SPEC.md` 是后续 PLAN 和验收的权威需求来源。

### 规约自审

按 `brainstorming` 技能完成四项快速自审：

1. **占位符**：未发现 TODO、TBD、FIXME、待定或未决占位。
2. **内部一致性**：明确 `git_history` 可组合本地 merge 与可选远程 PR Evidence；明确 `distribution_ready` 可由本地 Release workflow 或远程 Release Evidence 满足。
3. **范围**：保持六类预定义规则、CLI + Release、无 WebUI、无 LLM，不引入插件代码执行。
4. **歧义**：固定四种规则状态、四档退出码、离线/远程降级、报告输出与 Token 生命周期。

机械检查结果：8 个唯一用户故事、20 个唯一验收标准、无 Git diff whitespace error。

### 最终书面规约批准

- 学生审阅已提交的 `SPEC.md` 后明确回复“批准”。
- 规格提交：`15de2c7`（`docs: define RepoProof specification`）。
- 允许进入 `writing-plans`，但在计划完成并选择执行方式前不编写产品代码。
- 文件映射时发现 PLAN commit 证据缺少独立规则类型；为保持六种规则边界，将其明确为 `markdown_sections` 的可选 checklist commit 检查，而不新增规则类型。
- Secret allowlist 固定为严格的 `.repoproofallowlist.yml`，只接受规则 ID、相对路径和 8 位短指纹，禁止保存 Secret 原文。
- Profile 增加严格的可选 `manual_checks` 列表，让无法确定性判断的质量要求进入三种报告，但不伪装成自动规则或影响退出码。

### 实现计划

- 详细计划：`docs/superpowers/plans/2026-07-29-repoproof-implementation.md`
- 课程执行台账：`PLAN.md`
- 计划拆为 15 个依赖有序的 TDD Task，每个 Task 包含明确文件、接口、RED 命令、最小实现、GREEN 命令和 focused commit。
- 覆盖检查：AC-01 至 AC-20 全部映射到 Task 和客观验证。
- 结构检查：Task 1–15 各出现一次，240 个 Markdown fence 配对。
- 完整性检查：禁止的未来工作/含糊占位语言为 0，跨 Task 锁定接口均存在，`git diff --check` 无错误。
- 下一门禁：学生选择 Subagent-Driven 或 Inline Execution 后，才进入实现。

### 执行方式与测试准则裁决

- 学生选择 Subagent-Driven Development。
- 执行前扫描发现 Task 13/14/15 的源码文本断言与 `writing-good-tests` 的行为测试准则冲突。
- 学生批准按推荐方案修订：CI 使用解析后的配置结构与真实构建/冒烟验证，课程文档使用 RepoProof 自审结果验证，版本使用安装后元数据与 CLI 输出验证。
- 隔离实现分支：`agent/implementation-repoproof`。

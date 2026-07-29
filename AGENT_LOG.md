# AGENT_LOG

本日志按时间顺序记录 AI4SE 期末项目的智能体协作、人工决策、验证证据与偏离说明。

## 2026-07-29

### 16:00–16:15 · P0 · 理解作业与选择方向

- **参与者**：学生、Codex
- **技能 / 工作流**：尚未启用 Superpowers；本阶段为作业要求梳理。
- **关键上下文**：阅读 `要求.md`、A/B 两类项目说明。
- **决策**：学生选择 B（非 Harness 应用类项目），删除 A 方向说明。
- **人工干预**：学生明确以降低风险为目标选择 B。
- **产物**：`B项目完成流程.md`。
- **教训**：通用要求与最终交付清单对 WebUI、GitHub/GitLab CI 的表述存在冲突，不能自行忽略，应记录助教澄清。

### 16:15–16:25 · P0 · 部署方式澄清

- **参与者**：学生、助教说明、Codex
- **关键上下文**：助教明确 A/B 均可二选一：
  1. 仅 CLI，并提交托管平台 Release 链接；
  2. CLI + WebUI，并提交 WebUI 访问链接。
- **决策**：B 项目优先采用“CLI + GitHub Release”，不把 WebUI 作为强制范围。
- **人工干预**：学生提供助教原始说明。
- **产物**：修订 `B项目完成流程.md`。
- **教训**：课程后续说明应优先于原始文档中的冲突表述，并保留来源与决策记录。

### 16:25–16:45 · P0 · 环境与仓库准备

- **参与者**：学生、Codex
- **技能 / 工作流**：GitHub 通用仓库定向技能；本地 Git 只读检查。
- **关键上下文**：
  - 远程仓库：`https://github.com/zhuangyifan-666/njuise-2026-summer.git`
  - 远程仓库当前为空。
  - 本机已有 Git、Python、Node.js、npm、Codex CLI。
  - 本机未检测到 Docker、GitHub CLI、Superpowers。
  - GitHub 连接器当前未登录。
- **决策**：
  - 在当前目录初始化 `main` 分支并绑定远程 `origin`。
  - Docker 不是前置依赖，分发优先采用单文件 CLI Release。
  - 在 Superpowers 启用前不生成正式 SPEC/PLAN，不编写业务实现。
- **人工干预**：学生授权 Codex 在遇到真正无法自行解决的问题前自主推进。
- **教训**：开发工具和课程方法论是两项独立前置条件；Codex 可用不等于 Superpowers 已安装。

### 16:45 · P1 · 初步选题

- **参与者**：Codex（学生已授权自主决策）
- **技能 / 工作流**：Superpowers brainstorming 待启用；此处仅记录候选方向，不视为正式 brainstorming 产物。
- **项目代号**：RepoProof
- **问题陈述草案**：学生和小型开发团队常在提交或发布前才发现必备文档缺失、CI 配置错误、测试证据不足或仓库泄漏疑似凭据。RepoProof 将声明式交付规则转换为确定性检查，并生成可机器读取和可人工审阅的发布证据报告。
- **初步模块**：
  1. 声明式策略解析与规则引擎；
  2. 文件、Git、CI、分发配置及疑似凭据的证据采集器；
  3. 终端、JSON 与 HTML 报告生成器；
  4. 可选 GitHub 状态采集及安全凭据管理。
- **范围约束**：
  - 它不是自主 Agent，不包含多轮 LLM 决策或工具自主调用。
  - 核心离线审计不依赖网络或付费 API。
  - 不自动修改用户仓库，默认只读。
  - 分发采用 CLI + GitHub Release。
- **下一门禁**：安装并启用 Superpowers 后，使用 brainstorming 正式质询选题、分块确认设计，并生成 `SPEC_PROCESS.md` 与 `SPEC.md`。

### 16:50–17:00 · P0 · Superpowers 与 GitHub 工具就绪

- **参与者**：学生、Codex
- **技能 / 工作流**：OpenAI Docs、Codex Skill Installer、GitHub 发布工作流。
- **Superpowers 来源**：`obra/superpowers`，固定版本 `v6.2.0`。
- **安装事实**：
  - 已通过 Codex CLI 注册 `obra/superpowers-marketplace`。
  - 当前 Codex CLI 没有非交互式 `plugin install` 子命令，因此按学生“由 Codex 自行安装”的授权，使用 Codex Skill Installer 从官方仓库安装全部 14 个 Superpowers 技能。
  - 已逐项验证每个技能目录都包含 `SKILL.md`。
- **已安装技能**：`using-superpowers`、`brainstorming`、`writing-plans`、`using-git-worktrees`、`subagent-driven-development`、`executing-plans`、`test-driven-development`、`requesting-code-review`、`receiving-code-review`、`finishing-a-development-branch`、`verification-before-completion`、`systematic-debugging`、`dispatching-parallel-agents`、`writing-skills`。
- **GitHub 状态**：GitHub CLI 已安装；已验证账号 `zhuangyifan-666` 使用系统 keyring 登录，Git 协议为 HTTPS。日志不记录也不回显令牌。
- **额外工具**：为核对 Codex 插件机制，注册 OpenAI 官方文档 MCP；使用命令级临时覆盖绕过当前 CLI 对全局 `service_tier = "priority"` 的兼容问题，未修改用户全局模型配置。
- **偏离说明**：由于 Codex CLI 的非交互接口只能注册 marketplace，无法执行 UI 中的插件安装动作，本次使用同一官方仓库、同一固定版本的完整技能集安装作为兼容方案。后续所有必需 Superpowers 技能将逐项触发并记录。
- **教训**：必须区分“注册 marketplace”“插件 UI 安装”和“技能实际可发现”三个状态，不能仅看到源码缓存就声称安装成功。

### 16:55–17:00 · P1 · Superpowers brainstorming：定位收敛

- **触发技能**：`using-superpowers`、`brainstorming`。
- **关键问题**：项目应做通用审计、AI4SE 专用检查，还是安全扫描？
- **采用方案**：通用声明式策略引擎，并内置 AI4SE B 类作业 profile。
- **推翻方案**：
  - 放弃硬编码课程检查清单，因为复用性与工程深度不足。
  - 放弃安全扫描器主线，因为会偏离交付证据治理并扩大误报治理范围。
- **当前边界**：离线优先、默认只读、无自主 Agent、无 LLM 依赖、CLI + GitHub Release。
- **详细证据**：见 `SPEC_PROCESS.md` 的“迭代 1”。
- **门禁**：设计尚未得到学生批准，不得生成实现或调用实现技能。

### P1 · 设计签字 1：产品边界

- **学生反馈**：明确回复“批准”。
- **批准内容**：本地只读审计；检查文档、CI、Git 过程、分发与疑似凭据；输出终端/JSON/HTML 报告与稳定退出码；不自动修复、不上传源码、不依赖 LLM、首版不开发 WebUI。
- **影响**：允许继续呈现架构设计，但在全部设计批准前仍不得实现。

### P1 · 设计签字 2：架构与模块

- **学生反馈**：明确回复“批准”。
- **批准内容**：CLI、Profile、Collectors、Rule Engine、Reporters、Credential Store / GitHub Gateway 的分层架构，以及 Profile、Rule、Evidence、Finding、AuditReport 核心实体。
- **影响**：模块可独立测试；继续细化规则语义、错误与安全设计。

### P1 · 设计签字 3：规则、错误与安全

- **学生反馈**：明确回复“批准”。
- **批准内容**：六类首版规则、四种结果状态、四档稳定退出码、路径围栏、扫描资源上限、Secret 脱敏、系统钥匙串和受限 GitHub HTTPS 访问。
- **影响**：安全机制和错误语义已具备可测试的客观边界；继续确认技术栈、测试与分发。

### P1 · 设计签字 4 与规约落盘

- **学生反馈**：明确回复“批准”。
- **批准内容**：Python 技术栈、分层测试、性能目标、GitHub/GitLab CI 和 Windows x64 GitHub Release。
- **产物**：`SPEC.md`、`docs/superpowers/specs/2026-07-29-repoproof-design.md`。
- **人工干预**：四节设计均由学生逐节批准；文档细化由 Codex 完成。
- **门禁**：对书面 SPEC 完成自审并由学生最终审阅后，才允许进入 `writing-plans`。

### P1 · 规约自审

- **触发技能**：`brainstorming` 的 Spec Self-Review。
- **检查**：占位符、内部一致性、范围、歧义、whitespace。
- **修正**：
  - 明确本地 merge / 远程 PR Evidence 与 `git_history` 的关系。
  - 明确本地 Release workflow / 远程 Release Evidence 与 `distribution_ready` 的关系。
  - 将 `SPEC_PROCESS.md` 的历史“前置准备”状态更新为已完成设计、等待书面审阅。
- **证据**：8 个唯一用户故事；20 个唯一验收标准；占位符扫描为 0；`git diff --check` 无错误。
- **门禁**：学生尚需审阅已落盘的书面 `SPEC.md`。

### P1 · 最终书面规约批准与计划启动

- **学生反馈**：审阅已提交规格后明确回复“批准”。
- **规格提交**：`15de2c7`（`docs: define RepoProof specification`）。
- **触发技能**：`writing-plans`。
- **边界澄清**：PLAN 已完成项 commit 证据由 `markdown_sections` 的可选 checklist 检查实现，保持六种预定义规则不变。
- **安全澄清**：Secret allowlist 使用严格的 `.repoproofallowlist.yml`，只能记录规则 ID、相对路径和 8 位短指纹。
- **覆盖澄清**：Profile 使用可选 `manual_checks` 承载反思质量、模块职责等人工复核内容；三种报告展示但不计入自动状态。
- **当前门禁**：先完成实现计划、自审和提交，再由学生选择 Subagent-Driven 或 Inline Execution。

### P1 · 实现计划完成与自审

- **技能**：`writing-plans`。
- **产物**：`docs/superpowers/plans/2026-07-29-repoproof-implementation.md`、`PLAN.md`。
- **任务拆分**：15 个有序 TDD Task，覆盖领域模型、Profile、Collectors、Rule Engine、Reporters、CLI、凭据、GitHub、验收、性能、CI、打包、课程文档和 Release。
- **自审修正**：
  - PLAN commit 证据归入 `markdown_sections` 可选检查，不扩张六种规则。
  - Secret allowlist 固定为无原文的严格结构，并支持多条 Secret 规则各自过滤。
  - Profile 路径统一使用 `SafeRepoPath`。
  - GitHub Collector 改为本地 Git 证据之后才创建的 factory。
  - Evidence provenance 使用应用层注入的统一 snapshot 时间。
  - 人工质量要求使用 `manual_checks` 进入三种报告而不影响退出码。
- **机械证据**：Task 1–15 各一次；AC-01–20 全覆盖；240 个 fence 配对；禁止未来工作语言 0；`git diff --check` 无错误。
- **人工干预**：本阶段无需新增人工输入。
- **下一门禁**：提交计划后由学生选择执行方式。

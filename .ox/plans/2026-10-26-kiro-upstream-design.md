# Kiro 上游接入设计

日期：2026-10-26
状态：已与用户分三部分确认，待详细实施计划

## 1. 目标与决策

在 cardinal 中原生接入 Kiro 上游，由现有 OpenAI Chat 入站端点经 IR 翻译到 Kiro KAS，不引入 kiro2claude sidecar，不新增 `/v1/kiro` 入站端点。

首版按完整 coding 链路验收：流式/非流式文本、多轮历史、system、工具声明、并行工具调用、工具结果、reasoning、凭证刷新与重启恢复。

已确认的边界：

- 以 `/Users/john/github/kiro2claude` 为规范参考实现；所有有意偏离必须登记。
- 当前目录的 kiro-account-lite JSON 只由一次性导入脚本处理，不新增常驻导入 API 或 GUI 导入。
- 导入后账号由 cardinal 独占刷新；其他程序不得再旋转同一账号的 refresh token。
- 首版接入 Kiro 配额查询，复用现有 GUI key 卡片、配额历史与 Smart 路由额度缓存。
- 遵守仓库约定：验证测试临建、运行、记录结果后删除，不建立常驻测试体系。

## 2. 方案比较

| 方案 | 判断 |
| --- | --- |
| 原生 Kiro kernel + IR 方言 | 采用。直连上游，复用 cardinal 路由、failover、计量和流式截断机制。 |
| 把 Kiro 当普通 OpenAI HTTP 上游 | 拒绝。AWS 二进制 Event Stream 与 OIDC/KAS 语义无法由普通包装消除。 |
| kiro2claude sidecar | 拒绝。增加 Node 进程和网络跳点，割裂凭证、错误与流式状态。 |

## 3. 总体链路

```text
POST /v1/chat/completions
  -> OpenAI Chat to_ir
  -> capabilities 选择 Kiro 目标方言
  -> translation::kiro（会话、历史、工具、模型、effort）
  -> protocol::kiro（KAS 请求画像、profileArn、AWS JSON 1.0）
  -> 按 key 隔离的 OIDC TokenManager
  -> POST https://runtime.{apiRegion}.kiro.dev/
       x-amz-target: KiroRuntimeService.GenerateAssistantResponse
  -> AWS Event Stream
  -> Kiro StreamDecoder
  -> 现有 translated pump
  -> OpenAI Chat SSE 或非流式 JSON
```

Kiro 只作为翻译目标加入 IR 矩阵。非流式与流式复用同一个 Kiro StreamDecoder，避免两套事件语义漂移。

## 4. Schema、Admin 与依赖边界

### 4.1 Migration

新增 `migrations/0007_kiro.sql`，同时完成：

- 替换 `gateway_providers_protocol_check`，允许 `kiro`；不能只改 Rust 枚举。
- 为 `gateway_provider_keys` 增加 `auth_kind` 与 `oauth`。
- 不改 `gateway_requests.protocol`，该列没有协议 CHECK。

所有 `ProviderKeyRow` 查询显式选择新列，不能依赖 `SELECT *` 隐式变化。

### 4.2 Admin

- static 认证继续要求非空 `api_key`。
- `kiro_oidc` 使用空 `api_key`，并要求完整 OAuth 字段。
- 普通 key 列表不得返回 OAuth；现有 reveal 响应结构也不因新增字段而自动泄露 secrets。
- 模型列表探测首版不调度 Kiro，模型配置走手工入口；配额探测走专用 Kiro 分支。

### 4.3 Relay 依赖

`DispatchDeps` 显式携带 DB pool 与 `KiroTokens`，由 `api.rs` 的 AppState 投影注入。`resolve` 可以 async，但不得在锁内执行网络或 DB I/O。candidate 的 semaphore permit 继续跟随 attempt，确保 failover 和等待刷新时释放。

translated 路径不得再无条件向 Kiro body 写入 `stream:true`；断言放在 `prepare_translated` 边界，覆盖真实请求路径。

## 5. 一次性账号导入

脚本通过 Admin API 创建或更新 provider/key，只从 kiro-account-lite JSON 提取白名单字段：

- `credentials.clientId`
- `credentials.clientSecret`
- `credentials.refreshToken`
- `credentials.accessToken`
- `credentials.expiresAt`（毫秒转秒）
- `credentials.region`
- 顶层 `profileArn`

`authRegion/apiRegion` 首版跟随 `region=us-east-1`。

不得导入或记录密码、邮箱、CSRF、机器标识及其他账号管理字段。脚本与请求日志不得输出 access token、refresh token、client secret 或完整 OAuth body。JSON 原文件是用户资料，不由设计文档提交或删除。

导入初始 access token 与 expiry，避免服务启动后无谓刷新。

## 6. AWS Event Stream

`protocol::awseventstream` 是无 I/O 的独立帧层：

- 解析 total length、header length、prelude CRC、headers、payload 与 message CRC。
- header name length 为 **1 字节**；string/bytes value length 为 2 字节。
- 支持全部 10 种 header value type；type 8 是 timestamp，type 9 是 UUID。
- 校验两段 CRC、长度边界和 UTF-8/JSON。
- 单帧与缓冲区上限均为 16 MiB。
- HTTP chunk 可在任意字节位置切分帧。
- `finish()` 遇到残留半帧必须报截断，不能清空后静默成功。
- RawFrame 保留 `:message-type`、`:event-type`、`:error-code`、`:exception-type`。

只有未知普通 `event` 可以忽略；`error`、`exception`、CRC 错误、非法 header 和坏 JSON 都进入错误路径。

验证使用独立固定字节金样本、参考样例与任意切分，禁止用同一个错误编码器自编自解形成假阳性。

## 7. KAS 请求画像

以参考 `client-profile.ts`、`provider.ts` 和 `retry-executor.ts` 为基线，集中拥有 wire 格式：

- `content-type: application/x-amz-json-1.0`
- `x-amz-target: KiroRuntimeService.GenerateAssistantResponse`
- 完整 Kiro CLI/KAS user-agent 与 x-amz-user-agent 形状
- `x-amzn-codewhisperer-optout: true`
- `x-amzn-kiro-client-attribution: kiro-cli`
- `amz-sdk-invocation-id`
- `amz-sdk-request`
- `x-kiro-attempt`
- `Authorization: Bearer ...`

同一次内部认证重试共用 invocation ID 并递增 attempt；换 failover candidate 是新的逻辑调用。

`profileArn` 从当前 candidate key 的 OAuth 数据借出并注入 body。`AttemptContext` 只增加必要的借用字段，不克隆整份凭证。

## 8. IR 到 Kiro 会话转换

以参考 `claude/converter.ts` 为语义基线，而非简单 role 循环：

- system 折叠进第一条 user 文本，不伪造 assistant 应答。
- 最后一条 user 是 currentMessage，之前历史进入 history。
- 连续 user 按参考规则合并。
- 工具声明只写入 currentMessage 的 userInputMessageContext.tools。
- assistant tool call 与 tool result 按 ID 配对。
- 缺失结果和孤立结果使用安全、明确的占位文本，不暗示执行成功。
- assistant 结尾 continuation 按参考规则处理。
- 借用 IR 并按索引划分 current/history；不得克隆整段消息历史。

会话字段：

```text
conversationId       = sess_<UUID 形状的稳定派生值>
rootConversationId   = conversationId
agentContinuationId  = 每个用户轮次稳定、工具往返不变
agentTaskType        = vibe
agentMode            = vibe
chatTriggerType      = MANUAL
origin               = KIRO_CLI
```

IR 增加可选 `prompt_cache_key` 槽，Chat 与 Responses 不再无条件丢弃它；不支持该概念的其他目标继续显式记录 drop。Kiro 优先用它派生会话 ID。

未提供 cache key 时，cardinal 使用 system + 首轮 user 稳定派生。这是相对参考随机 ID 的明确偏差：相同开场的不同会话可能共享缓存分组，但每次仍发送完整历史，不共享或省略内容。

模型映射与 `additionalModelRequestFields` 以参考当前表格为准。显式 off 必须经过独立分支，不能在 GPT 族被 `chat_name()` 默认值改写成 `low`。

首版 IR 不承载 Kiro reasoning signature。无签名 Thinking 不写成需要签名的 Kiro reasoningContent；若最终实现不产生该字段，就不增加无调用方的 signature-strip retry。

## 9. Kiro 响应状态机

一个 StreamDecoder 同时服务流式与非流式：

- assistantResponseEvent -> 文本增量。
- reasoningContentEvent -> reasoning 增量；signature 只在内部保留，不虚构跨协议签名。
- toolUseEvent -> 按 toolUseId 分配稳定 index，支持并行工具；不能固定 index 0。
- metadataEvent -> 正常收尾证据；有工具调用时 finish_reason 为 tool_calls。
- meteringEvent -> 保存原始 usage；不从 credits 反推 token。
- contextUsageEvent -> 仅诊断，不写入 token usage。
- error/exception -> 保留上游错误类别并进入截断/错误处理。
- 半帧 EOF、CRC/JSON 错误 -> 让现有 pump 合成可见错误终结帧并写账本。

观测不到 token usage 时，客户端 body 省略 usage，不返回 prompt/completion/total 三个硬编码 0。账本同样不得把未知伪造成真实计量。

protocol kernel 只产出 ObservedResponse；IR 转换留在 translation 层，避免 protocol -> translation -> protocol 的依赖倒置。

## 10. OIDC TokenManager

每个 key 独立保存：

```text
accessToken / expiresAt
refreshToken
clientId / clientSecret
region / authRegion / apiRegion
profileArn
```

状态机：

1. access token 距过期超过 10 分钟：直接复用。
2. 临近过期：single-flight 刷新；等待者拿锁后再次检查。
3. 刷新前重读 DB 中该 key 最新 OAuth，避免 RouteCache 的旧 refresh token 污染进程。
4. OIDC CreateToken 使用 camelCase：clientId/clientSecret/refreshToken/grantType。
5. 成功后保存完整 access token、expiry、profileArn 与可选轮换 refresh token；响应未给新 refresh token 时保留旧值。
6. runtime bearer-invalid 401/403：按旧 bearer 去重；刷新前在锁内重读 DB，若外部登录已写入不同的新鲜 bearer 则直接复用，否则以 DB 中较新的 bundle 作为刷新基；仅重试当前 candidate 一次。
7. invalid_grant：先按参考实现的窄路径恢复——内存已知与 DB 一致时锁内重读一次；DB 中 refresh token/client identity/auth region 确实变化时用新 bundle 重试 CreateToken 至多一次，未变化则视为永久凭证错误，跳过 candidate 并要求重新导入。同一 bundle 永不重试，内存不因失败回滚。
8. OIDC 429/5xx 与网络错误：保持临时故障语义，不混入永久失效。
9. 持久化失败：不记录秘密；保留已刷新内存凭证并 warn，不能继续写回旧轮换令牌。

刷新路径上的锁使用可跨 await 的异步互斥；热路径锁不得 unwrap/expect，失败须降级并 warn。

## 11. Kiro 配额查询与 GUI

### 11.1 复用边界

不新增 GUI 组件或前端协议。Kiro 读数转换为现有 `quota::KeyQuota`，后续沿用：

- `gateway_key_quota_snapshots` 持久化与首次绘制
- 每 300 秒后台配额探测器
- `SmartCache` 的额度窗口与剩余时间排序
- GUI provider key 卡片的进度条、剩余额度、重置时间和趋势图
- Admin 手动刷新与 `QuotaRefreshed` 推送

### 11.2 请求

`GetUsageLimits` 使用 **Shell 请求画像**，不是聊天 KAS 画像：

- host：`codewhisperer.us-east-1.amazonaws.com`；非 `us-east-1` 按参考表使用 `q.{region}.amazonaws.com`
- `x-amz-target: AmazonCodeWhispererService.GetUsageLimits`
- content-type、Shell user-agent、x-amz-user-agent
- `amz-sdk-invocation-id`、`amz-sdk-request`；不发送没有抓包证据的 `x-kiro-attempt`
- 单次调用，不重试
- `profileArn` 同时放 query string 与 JSON body
- `isEmailRequired=false`：额度卡片不需要邮箱，避免额外拉取 PII

探测通过 KiroTokens 获取有效 bearer，与聊天共用 single-flight，不能另建独立刷新路径。

探测 fan-out 必须在“跳过无 api_key 的 key”之前按 `provider.protocol` 分支：Kiro key 的静态 api_key 本来为空。后台探测器与 Admin 手动刷新共用同一 Kiro 分支，因此两者都需要拿到共享 KiroTokens，不能只在启动路径注入。

### 11.3 映射

主额度来自 `usageBreakdownList` 中 `resourceType=CREDIT` 的条目：

```text
name           = "本月 Credits"
used_pct       = currentUsageWithPrecision / usageLimitWithPrecision × 100
total          = "<usageLimitWithPrecision 或 usageLimit> Credits"
resets_at      = usageBreakdown.nextDateReset 或顶层 nextDateReset（Unix 秒）
period_minutes = 30 天近似值
```

`used_pct` clamp 到 0–100。没有 precision 字段时退回整数 `currentUsage/usageLimit`。GUI 的“剩余 x / total”由现有百分比渲染逻辑生成。

首版不把 `bonuses` 重复加到主额度，也不把 credits 换算成 token；这些需要独立的产品语义，不能伪造。

### 11.4 生命周期

- 成功：解析后排序窗口，写快照、更新 SmartCache，并推送 GUI 刷新。
- 空 `usageBreakdownList` 或无可识别 CREDIT 条目：视为无有效读数，保留上一快照并 warn。
- 401/403：先走共享 token manager；刷新仍失败则保留旧快照。
- 429/5xx/网络/超时：配额是装饰信息，warn 后保留旧快照，不影响聊天。
- 探测日志不得输出完整响应中的用户标识；只记录状态、窗口数和安全错误摘要。

## 12. 实施阶段

1. Schema/Admin：migration、认证校验、key 查询与 secret 边界。
2. 协议身份：ProtocolId、capabilities、全部穷尽 match、IR cache key。
3. 帧与 kernel：纯帧层、WireFramer 行为保持重构、KAS prepare、stream 字段门控。
4. 翻译：请求会话/工具/模型/effort、响应状态机、IR 矩阵、usage 省略。
5. OIDC：DispatchDeps、single-flight、最新 DB 凭证、完整持久化、401 恢复、永久错误。
6. 配额：Shell 请求画像、GetUsageLimits 解析、共享 token、快照/SmartCache/GUI 链路。
7. 导入与验收：一次性脚本、手工模型配置、假上游和真实账号端到端验证。

每阶段至少运行 `cargo build` 与 `cargo clippy -- -D warnings`。临时行为测试的红绿结果记入实施记录，随后删除测试。

## 13. 验收矩阵

| 类别 | 必须场景 |
| --- | --- |
| Schema/Admin | Kiro provider/key 可建；static 空 key 仍拒绝；列表不泄露 OAuth |
| 帧 | 金样本、任意切分、CRC/长度错误、半帧 EOF、error/exception |
| 请求 wire | 完整 KAS 画像、无 stream、profileArn、模型映射、system、多轮历史 |
| 会话 | 工具往返 ID 不变；下一用户轮次更换 continuation；无 cache key 行为确定 |
| 工具 | 并行 index、参数增量、结果配对、缺失/孤立结果安全处理 |
| Reasoning | 文本增量、effort 映射、GPT 显式 off 不变成 low |
| Token | 新鲜复用、并发单刷、轮换落库、重启复用、401 单次恢复、invalid_grant |
| 配额 | CREDIT 窗口映射、重置时间、旧快照保留、Smart 排序参与、GUI 无需改动即可显示 |
| 流式错误 | post-commit 截断合成错误帧并记账；异常不视为正常 EOF |
| Usage | 有 metering 保留原值；未知时省略，不伪造 token 0 |
| 真实链路 | 流式/非流式问答、多轮、实际工具往返、刷新后重启 |
| 回归 | 现有 provider、路由、failover、其他 chat 翻译行为不变 |

假上游必须把响应拆成多个 HTTP chunk，并至少把一帧从中间劈开；整包一次写出不算覆盖增量解析。

## 14. 相对 kiro2claude 的偏差清单

1. 使用 cardinal IR/relay，不移植 Node 服务与插件体系。
2. 首版只验收 OpenAI Chat -> Kiro；Responses 仅保留 cache key，不新增专项端点验收。
3. 无 prompt_cache_key 时稳定派生会话 ID，而非每请求随机。
4. 不接 MCP、subagent、GUI 导入或常驻导入器。
5. 配额请求不发 `isEmailRequired=true`，不把邮箱拉进 gateway。
6. 配额窗口使用 30 天近似周期作为排序/趋势键，重置时刻仍用上游真实时间。
7. 不把 bonuses 重复计入主额度，不把 credits 换算成 token。
8. 不伪造 Anthropic 签名思考块。
9. 保留 cardinal failover 与流式截断终结，不移植 kiro2claude 下游错误格式。
10. 凭证存 PostgreSQL，不回写 kiro-cli SQLite；账号由 cardinal 独占。
11. 测试验证后删除，不建立常驻测试体系。
12. OIDC `CreateToken` 响应要求 `expiresIn`：参考实现缺失时保留旧 expiry，cardinal 以 `InvalidResponse` 拒绝——没有可信 expiry 的 bearer 无法参与新鲜度判断。
13. OIDC 请求不手写参考实现的 `host` 与 `Connection: close` 头：`reqwest` 从 URL 派生 `Host`，连接生命周期由 transport 的 idle/opening deadline 管理，强制关闭会无收益地禁用连接复用。
14. `invalid_grant` 仅匹配 HTTP 400 + 有界 body 中的 `invalid_grant`，不再额外要求人类可读的 `Invalid refresh token provided`：OAuth 错误码才是稳定的机器字段，该句式已在 AWS 端点间漂移；body 只用于分类，绝不记录或转发。

## 15. 安全与交付约束

- 不把账号 JSON、token、client secret 或含秘密的日志加入提交。
- 不改动无关用户文件。
- 真实账号验证只执行无副作用或明确安全的工具往返。
- 部署不属于本设计文档的自动动作；实施后如需上线，必须走既有构建、同步、重启与产物新鲜度验证流程。

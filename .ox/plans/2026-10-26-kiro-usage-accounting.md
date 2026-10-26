# Kiro 用量与费用记账（token 估算 + 挂牌价折算）

## 分析与方案

### 现象

`gateway_requests` 里 Kiro 的行（id 15416–15418，`protocol=kiro`，`status=200`）的
`input_tokens` / `output_tokens` / `cost_usd` 全为 NULL，GUI 请求页的
`Token 入/出` 与 `费用` 两列显示 `—` / `—`。

### 根因（三处，缺一不可）

1. **内核主动不报用量。** `src/protocol/kiro.rs:438` 的 `usage()` 恒返 `None`，
   模块文档把它写成设计（"No token accounting"，`kiro.rs:29`）。而
   `src/relay.rs:1108` 的 `AttemptLog::from_observed` 只从 `observed.usage` 推
   token 与 `cost_usd`（`relay.rs:1119-1136`），所以三列为空。
2. **流式路径根本看不到计费帧。** 本地真打 KAS（2026-10-26，`gpt-5.6-sol`）的帧序是
   `initial-response` → `assistantResponseEvent` → `metadataEvent` →
   `contextUsageEvent{"contextUsagePercentage":0.16616052389144897}` →
   `meteringEvent{"unit":"credit","usage":0.11385345505804313}`。后两帧在
   `metadataEvent` **之后**；`src/relay/streaming.rs:648` 在 `Finish` 事件处
   `done = true` 直接退出循环，尾帧从不交给 decoder。参考实现明确相反
   （`kiro2claude/packages/core/src/claude/stream-handler.ts:339`：计费尾帧只在
   EOF 前到，故"ALWAYS read to EOF"）。
3. **价格表没有 Kiro 的模型。** `gateway_model_prices` 现只有 7 行，无
   `gpt-5.6-sol`。`src/prices.rs:262 find_cost` 只导入 MAKERS 名单（含 `openai`），
   实测 `~/.ox/models-dev.json` 的 `openai` 条目里就有 `gpt-5.6-sol`
   （input 4 / output 20 USD per Mtok，272k 以上进 8/30 档）。目录同步按
   `served_models_for_pricing`（`src/store/price.rs:210`，取近 30 天
   `served_model` 并集）会写 `provider_id = 0` 的全局行；Kiro 的请求
   `served_model = gpt-5.6-sol`，`price_cache.get(provider_id, target_model)`
   因此能命中全局行。**不需要手工种价格。**

### 费用口径（全局规则，用户 2026-10-26 明确）

账本 `cost_usd` **一律**由 token × 价格表计算，绝不采用厂商自报金额或 credits 换算，
不管接的是哪个 provider。价格只有两个来源：models.dev 目录价（`source='catalog'`，
写入 `provider_id = 0` 全局行，只导入 MAKERS 名单里的 maker 价）与人工固定价
（`source='manual'`，config/DB 种入，优先于目录价）。没有价格 → `cost_usd` 留 NULL；
没有观测 token → 省略 usage。现状符合该规则（`src/relay.rs:1123` 与 `2153` 都只从
`ModelPrice` 算），Kiro 只是"没有 token"这一个洞。

### 决策

用户已选：**只估算 token，用 models.dev 挂牌价折 USD**，不引入 credits 列、不把
credits 换算成钱。据此：

- **input**：`floor(contextUsagePercentage × window / 100)`（参考
  `kiro2claude/packages/core/src/claude/converter.ts:439` 的同一公式）。
- **output**：`floor((可见文本 + reasoning + 已完成/未完成的工具参数) 字符数 / 4)`。
  参考对文本用 `estimateTokens(content)`（`stream.ts:1129,1214`）、对工具输入用
  `floor((input.length + 3) / 4)`（`stream.ts:1496`）；cardinal 在 `usage()` 时
  从 decoder **已累计的** `text` / `reasoning` / `tools[].arguments` 一次性算，
  不新增 per-chunk 计数器（少一份状态，也没有逐块取整漂移）。
- **window 来源**：key 的模型快照 `ProbeModel.context`（KAS
  `ListAvailableModels` 的 `tokenLimits.maxInputTokens`，本地实测
  `gpt-5.6-sol = 922000`）。**不**用 `gateway_routes.context_window`（本地
  `kiro-test` 声明的是 262144，与上游宣称值不同；百分比的分母是上游的窗口）。
  窗口缺失 → `usage()` 返回 `None`，绝不返回 `{0,0}`（项目既有语义：没有观测就省略，
  `UsageCounts` 的 input/output 都是非 Option，填 0 等于撒谎）。
- **credits 仍只作诊断**：`meteringEvent` 已以 `tracing::debug` 记录
  （`kiro.rs:297-310`）并保留 `metering()` 访问器，不写入账本。
- **客户端可见流不变**：Kiro 不在 Chat 帧里注入 usage（用户诉求是 GUI/账本）。
- **流式要读到 EOF**：`metadataEvent` 后的两帧只能靠 tail drain 拿到。

### 模块边界与所有权

| 模块 | 拥有什么 | 输入 → 输出 |
| --- | --- | --- |
| `src/protocol/kiro.rs` | KAS 事件语义与 token 估算（唯一知道 `contextUsagePercentage` 含义的地方） | 构造时收 `context_window: Option<u64>`；`usage()` → `Option<UsageCounts>` |
| `src/protocol/mod.rs` | 只做转发：`Decoder::new(protocol, context_window)`、`parse_json(protocol, body, context_window)`；非 Kiro 内核忽略该 hint | 透传 |
| `src/relay/candidates.rs` | "这个候选模型的声明窗口是多少"（key 快照，按 `upstream_model` 精确匹配） | `Candidate.context_window: Option<u64>` |
| `src/relay.rs` | 装配：候选窗口 → `AttemptContext` → 三个 decode 入口 | 不解释窗口语义 |
| `src/relay/streaming.rs` | 帧泵：终端帧后的有界 tail drain、循环末尾读 `upstream.usage()` | 无协议知识 |
| `src/translation/mod.rs` + 4 个 dialect | `response_to_ir` 收同一个 hint（Kiro 用，其余忽略） | 透传 |

依赖单向：kiro 内核不知道候选/路由；candidates 不知道协议；streaming 不知道 Kiro。

### 不变量

1. 没有窗口或没有 `contextUsagePercentage` → `usage()` 为 `None`，账本留空。
2. 估算值绝不进入客户端可见帧（`StreamEvent::Usage` 不由 Kiro 产生）。
3. tail drain 里的读取失败/超时**不**设 `interrupted`、不合成错误帧：响应已在
   `Finish` 时完成，账本少一行数字比把成功请求标成截断好。
4. 估算只读已累计状态，`usage()` 可重复调用、无副作用。

### 被否决的方案

- **A. 账本记真实 credits（新增 `credits` 列，GUI 显 `0.11 cr`）**：credits 是上游真实
  扣费，但无法诚实折 USD，也不进入现有 dashboard 的美元汇总；用户已选挂牌价折算。
- **B. 把估算 usage 也注入客户端帧**：改变客户端可见输出（多一帧 usage），与用户诉求
  （GUI 费用）无关，风险大于收益。
- **C. 用 `gateway_routes.context_window` 当分母**：那是运营声明（本地 262144），
  与上游宣称的 922000 不同，换算会系统性偏差。验收里会实证标定一次，
  确认快照值是不是真正的分母。
- **D. 非流式 translated 路径再跑一次 `parse_json` 取 usage**：同一 body 解两遍
  （多一份全文副本），只为了绕开 vtable 签名；改为给 `response_to_ir` 传 hint。
- **E. 从上游响应反查模型窗口**：KAS 事件不带 model id（`kiro.rs` 的注释已说明），不可行。

### 相对 `kiro2claude` 的偏差（登记）

1. 参考把 credits 以 `kiro.creditsUsed` 暴露给插件/日志（`stream.ts:156`）；cardinal
   只写 tracing，不进账本、不进客户端。
2. 参考在 `contextUsageEvent` 缺失时用本地 prompt 估算兜底（`stream.ts:1675`
   的 `contextInputTokens ?? estimated`）；cardinal 的 decoder 看不到请求体，缺失即省略整个 usage。
3. 参考会把派生 usage 写进 Claude 的 usage 字段（客户端可见）；cardinal 只在账本/GUI 记。
4. cardinal 的 output 估算把 reasoning 字符一并计入（参考的 `estimateTokens` 只覆盖它
   收到的文本增量）；理由是 reasoning 也是上游生成、也计费。

### 验收标准

- 非流式与流式各一次真实 Kiro 请求后，`gateway_requests` 的 `input_tokens`、
  `output_tokens`、`cost_usd` 非空，且 input 随上下文字数增加而上升（量级合理：
  文本字符数 /4 与估算 diff 同量级）。
- 窗口标定：两次仅提示词长度不同的请求，用 `Δpct` 与已知 `Δtokens` 反解窗口，
  结果应接近 922000（而非 262144）。
- 已完成的流式响应在 tail drain 超时/上游不关连接时，客户端流仍以 `[DONE]` 正常结束，
  `gateway_requests.error` 仍为 NULL。
- 其它协议（deepseek 静态 key、chat 非流式/流式）行为不变：usage 与以前逐字节一致。
- `cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo build --release` 通过。

## 实施任务

> 全部在 worktree `.ox/worktrees/kiro-usage` 内执行；Rust 命令一律带
> `CARGO_TARGET_DIR=<worktree>/target`。每个任务一个 subagent，任务后做规格与质量双审。

### 任务 1：Kiro 内核的 token 估算

- `src/protocol/kiro.rs`
  - `StreamDecoder` 增加 `context_window: Option<u64>`；`new(context_window: Option<u64>)`
    （去掉 `derive(Default)` 或改为显式 `Default` 忽略）。
  - `usage()` 实现估算：input 用 `context_usage_percentage` × window；
    output 用 `text.chars().count() + reasoning.chars().count()` 加各工具的
    `arguments.chars().count()`，除以 4 取整。`context_window` 或百分比缺一 → `None`。
  - `aggregate(body, context_window)`、`parse_json(body, context_window)`。
  - 模块文档：删掉 "No token accounting" 与 "Post-`metadataEvent` diagnostics are
    not observed on the stream" 两条偏差，换成新的偏差条目（本文件"偏差"节）。
- `src/protocol/mod.rs`：`parse_json(protocol, body, context_window)`（非 Kiro 忽略）。
- 验证：`cargo build`；手工用真实 KAS body（离线夹具，跑完删除）核对
  `aggregate` 的 input/output 与手算一致；`cargo clippy --all-targets -D warnings`。
- 提交：`feat: derive Kiro token usage from KAS context and content`

### 任务 2：候选窗口装配

- `src/relay/candidates.rs`：新增 `fn model_context(key: &ProviderKeyRow, model: &str)
  -> Option<u64>`（读 `key.models` 里 `id == model` 的 `context`）；`Candidate` 加
  `context_window: Option<u64>`，`expand_direct` 的 3 处字面量与 `make_candidate` 填值。
- `src/relay.rs`：`AttemptContext` 加 `context_window: Option<u64>`（含 `relay.rs:379`
  的解构与 `relay.rs:1983` 的构造）。
- 验证：`cargo build` + `cargo clippy --all-targets -D warnings`。
- 提交：`feat: carry a candidate model's declared context window into the attempt`

### 任务 3：decode 入口接线

- `src/protocol/mod.rs`：`Decoder::new(protocol, context_window)`，Kiro 分支传入。
- `src/translation/mod.rs`：`Dialect.response_to_ir: fn(&[u8], Option<u64>) -> ...`；
  `openai_chat` / `anthropic_messages` / `openai_responses` 的实现各加 `_context_window`
  并忽略；`kiro::response_to_ir(raw, context_window)` 传下去。
- `src/relay.rs`：`attempt_stream`（`StreamPump::Translated` 的 `Decoder` 在泵内构造，
  见任务 4）与 `attempt_json`（`parse_json` + `response_to_ir`）把
  `ctx.context_window` 传到。
- `src/relay/streaming.rs`：`StreamPump::Translated` 增加 `context_window: Option<u64>`
  字段，泵内 `Decoder::new(upstream, context_window)`。
- 验证：`cargo build` + clippy；`cargo build --release`。
- 提交：`feat: pass the context window to the response decoders`

### 任务 4：流式 tail drain

- `src/relay/streaming.rs`（translated 分支）：
  - `terminal_at_eof` 时不再直接 `done = true`，先跑有界 drain（`TAIL_DRAIN = 3s`，
    `tokio::time::timeout_at` 包裹 `reader.next_wire_frame()`），逐帧
    `decoder.observe_wire` 并丢弃事件；`Eof` / 错误 / 超时都静默结束。
  - 分支末尾 `if let Some(counts) = upstream.usage() { usage = Some(counts) }`
    （tail 里的百分比只能在读完后换算出 input）。
  - 注释说明为什么需要（KAS 计费尾帧在 `metadataEvent` 之后）和为什么有界。
- 验证：真实 Kiro 流式请求 → 客户端帧序与改造前一致（文本/reasoning/tool、
  `stop`、`[DONE]`），账本出现 input/output/cost。
- 提交：`feat: drain the KAS tail so streamed Kiro usage reaches the ledger`

### 任务 5：实证标定与端到端验收

- 标定：两条仅提示词长度不同的请求（A 短、B 约 4 万字符），由
  `Δpct × W / 100 ≈ Δchars / 4` 反解 `W`；记录结论（是否 922000）。
- 非流式、流式各一次：`gateway_requests` 三列非空；GUI 请求页显示
  `Token 入/出`、`费用`（`$0.xxxx`）；`format_speed` 列也应有数。
- 价格：如 `gateway_model_prices` 仍无 `gpt-5.6-sol`，把 `~/.ox/models-dev.json`
  mtime 调旧后重启本地 gateway 触发启动同步，确认写入 `provider_id=0`、
  `source='catalog'` 的行；不改代码兜底。
- 回归：deepseek（静态 key）非流式与流式各一次，usage 与改造前一致。
- 尾帧缺失容错：假上游（临时，跑完删除）只发到 `metadataEvent` 就挂断，
  客户端仍正常收尾、`error` 为 NULL、账本 usage 只有 output（input 缺 → 整体 None，
  **确认走的是 None 而不是 0**）。
- 清理临时脚本与夹具。

### 任务 6：文档与收尾

- `.ox/plans/2026-10-26-kiro-upstream-design.md`、`2026-10-26-kiro-upstream-layer.md`：
  修正"无 token 记账"的旧结论，登记本文件"偏差"节的 4 条。
- `src/protocol/kiro.rs` 模块文档复核（偏差清单与代码一致）。
- `git add -f` 本计划文件；worktree 内提交随各任务；最后按仓库流程 squash 合入 main。

## 验收记录（2026-10-26，本地 gateway + 真实 KAS）

- **窗口标定**：直连 KAS 解码原始帧（临时脚本，跑完即删）。短提示词
  `contextUsagePercentage=0.16616052389144897`，约 40k 字符提示词 `1.1425162553787231`，
  `Δchars=40502`、`Δpct=0.9763557314872742`。以该填充文本的真实切分密度
  （≈4.5 字符/token）反解得窗口 ≈921,841，与 key 快照的
  `tokenLimits.maxInputTokens = 922000` 一致（偏差 0.017%），且与路由声明的
  262144 明显不符 → 确认分母就是上游声明窗口，不是路由声明值。
- **价格**：`~/.ox/models-dev.json` mtime 调旧重启触发目录同步，
  `gateway_model_prices` 出现 `provider_id=0`、`source='catalog'` 的
  `gpt-5.6-sol`（4 / 20）与 `gpt-5.6-luna`（0.2 / 1.2），均为 models.dev 的
  `openai` maker 条目。没有新增任何 Kiro 专用计价代码。
- **真实请求**：非流式 `input=1533 output=2 cost=0.00030900`；流式
  `input=1533 output=3 cost=0.00031000 ttft=718ms`。两者 cost 均等于
  `token × 目录价`，`error` 为 NULL，`/api/requests`（GUI 数据源）同样返回这些字段。
- **客户端可见性**：非流式 body 与流式帧都不含估算 usage（流式 `stop` + `[DONE]`，
  无 usage 帧；非流式 body 无 `usage` 字段）。为此在 `Dialect` 上加了
  `estimates_usage` 标记：Kiro 为 true，`attempt_json` 把估算从 IR 取出交给账本、
  不放进客户端 body。这是计划"估算只进账本/GUI"的实现手段，不影响任何其它方言。
- **回归**：deepseek（静态 key、chat 直通）非流式 `35/14 cost=0.00001400`、
  流式 `36/32 cost=0.00002500`，均来自厂商原始 usage，与改造前同口径。
- **临时测试（已删除）**：`protocol::kiro::temp_usage_estimate` 5/5 通过——
  缺窗口 → None、缺百分比 → None、`922000 × 0.16616…% → 1532`、
  reasoning 与工具参数计入 output、非法/缺失百分比 → None。
- **尾帧缺失容错未做实机假上游**：Kiro 凭证管理器有刻意的
  `EndpointMismatch` 守卫（`src/upstream/kiro_tokens.rs`），provider base_url 必须等于
  `https://runtime.{apiRegion}.kiro.dev`，因此 loopback 假 KAS 无法在不放宽该守卫的
  前提下走通 kernel。相应保障来自代码路径本身：`drain_tail` 只观测不转发、
  读取失败/超时不写 `interrupted`、不合成错误帧，缺百分比时 `usage()` 返回 None
  （已由上述临时测试覆盖）；正常 EOF 与完整尾帧已用真实 KAS 验证。

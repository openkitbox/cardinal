# Kiro Native Upstream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 cardinal 中原生接入 Kiro KAS 上游，使 OpenAI Chat 客户端获得流式/非流式 coding、工具、多轮、OIDC 自刷新和现有 GUI 月度 Credits 配额展示。

**Architecture:** 新增只作为上游目标的 `ProtocolId::Kiro`、IR 方言和 AWS Event Stream kernel，继续复用 cardinal 的 candidate/failover/translated pump/ledger。一个共享 `KiroTokens` 同时服务聊天和配额；OIDC 凭证只存在于 key 存储、relay 与配额探测路径，响应与 GUI 继续走现有结构。

**Tech Stack:** Rust 2024、Tokio、reqwest、sqlx/PostgreSQL、serde/serde_json、bytes、secrecy、uuid、crc32fast；规范参考为 `/Users/john/github/kiro2claude`。

---

## 0. 执行约束与事实底座

- 设计权威：`.ox/plans/2026-10-26-kiro-upstream-design.md`。本计划替代此前同名草案中的错误帧格式、凭证和会话细节。
- 首版只开放 `OpenAiChat -> Kiro`；不新增 Kiro 入站端点，不接 MCP/subagent，不做模型列表探测，不改 GUI。
- 测试遵守仓库约定：每个行为测试先红后绿，记录命令与结果，提交前删除临时测试；不得把测试留在最终提交。
- 并发测试用 barrier/oneshot 和 bounded wait 同步，禁止用固定 sleep 判断刷新或流式状态。
- 不提交账号 JSON、OAuth 日志或真实凭证。当前 `kiro-account-*.json` 保持未跟踪且不被脚本删除。
- 热路径锁不得 `unwrap/expect`，不得新增 `#[allow]`；生产路径不克隆整段 IR 历史。
- 参考源码：`parser/header.ts`、`parser/frame.ts`、`retry-executor.ts`、`token-manager.ts`、`client-profile.ts`、`model/events/base.ts`、`claude/converter.ts`。
- AWS 帧硬约束：prelude 12 字节；header name length **1 字节**；string/bytes length 2 字节；type 8 timestamp、9 UUID；两段 CRC；16 MiB 上限；半帧 EOF 是错误。
- KAS body 没有 `stream` 字段。流式与非流式客户端请求都打同一个 KAS endpoint，差别只在 cardinal 如何聚合/翻译响应。
- `meteringEvent` 的 credits 不是 token。没有 token 观测时 `usage=None`，不得返回三个 0。

### 文件结构

| 文件 | 责任 |
| --- | --- |
| `migrations/0007_kiro.sql` | provider 协议白名单、key 认证方式与 OAuth JSONB |
| `src/kiro/credentials.rs` | 纯 OAuth 数据、校验、expiry；无 I/O |
| `src/kiro/profile.rs` | KAS/Shell 画像、endpoint 与 retry header 唯一格式 |
| `src/kiro/mod.rs` | 上述纯共享模块出口 |
| `src/store/key.rs` | OAuth 持久化、key 查询与凭据轮换；普通 View 不含 OAuth |
| `src/admin.rs`, `src/admin_ops.rs` | 现有 key API 的 Kiro 创建/轮换分支与共享 token 注入 |
| `src/protocol/awseventstream.rs` | 独立二进制帧解析，无 Kiro 业务语义 |
| `src/protocol/kiro.rs` | KAS prepare、非流式观察与流式事件状态机 |
| `src/protocol/wire.rs` | `WireFrame`/`WireFramer`，隔离 SSE 与 AWS 帧 |
| `src/translation/kiro.rs` | 借用 IR 的会话/工具/模型转换及完整响应聚合 |
| `src/upstream/kiro_tokens.rs` | per-key single-flight OIDC、DB 重读/持久化、401 去重 |
| `src/relay.rs`, `src/relay/streaming.rs` | 依赖注入、translated body 门控、认证重试与通用帧泵 |
| `src/quota.rs` | GetUsageLimits 请求与 CREDIT -> `KeyQuota` 纯映射 |
| `scripts/import-kiro-account.py` | 一次性白名单导入，复用现有 Admin API |

## Task 0: 建立隔离工作区与绿色基线

**Files:** 无源码修改。

- [ ] **Step 1: 从默认分支建立隔离 worktree**

```bash
git switch main
git pull --ff-only
git worktree add .ox/worktrees/kiro-upstream -b feat/kiro-upstream main
cd .ox/worktrees/kiro-upstream
```

- [ ] **Step 2: 运行基线**

```bash
cargo build
cargo clippy --all-targets -- -D warnings
```

Expected: 两个命令均退出 0。若基线失败，先记录并修复/报告既有问题，不把失败归因于 Kiro。

- [ ] **Step 3: 准备一次性验证数据库**

```bash
createdb cardinal_kiro_verify
DATABASE_URL=postgresql://beaver:beaver@127.0.0.1/cardinal_kiro_verify cargo build
```

Expected: 数据库可连接。真实账号 E2E 前保留该库；Task 11 完成后删除。任何测试不得依赖用户 home 中已有 cardinal 数据。

## Task 1: Schema、OAuth 数据与 Admin 秘密边界

**Files:**
- Create: `migrations/0007_kiro.sql`
- Create: `src/kiro/mod.rs`, `src/kiro/credentials.rs`
- Modify: `src/lib.rs`, `src/store/key.rs`, `src/store/mod.rs`, `src/admin.rs`, `src/admin_ops.rs`
- Temporary test: `src/admin.rs` 内 `#[cfg(test)] mod kiro_task1_verification`，提交前删除

- [ ] **Step 1: 写失败的 schema/secret 验证**

验证 migration 后 `protocol='kiro'` 可插入；`auth_kind='kiro_oidc'` 必须有 OAuth，static 不得带 OAuth；`ProviderKeyView` 与 reveal JSON 均不含 `accessToken`、`refreshToken`、`clientSecret` 或 `oauth`。static 创建仍拒绝空 `api_key`。

```rust
#[test]
fn kiro_task1_public_key_shapes_hide_oauth() {
    let row = ProviderKeyRow {
        id: 1, provider_id: 2, label: "kiro".into(), api_key: None,
        enabled: true, position: 0, max_concurrency: None, models: None,
        allowed_models: None, auth_kind: "kiro_oidc".into(),
        oauth: Some(KiroOAuth {
            access_token: "fake-access".into(), expires_at: 2_000_000_000,
            refresh_token: "fake-refresh".into(), client_id: "fake-client".into(),
            client_secret: "fake-secret".into(), region: "us-east-1".into(),
            auth_region: "us-east-1".into(), api_region: "us-east-1".into(),
            profile_arn: Some("arn:aws:iam::123456789012:profile/fake".into()),
        }),
    };
    let listed = serde_json::to_string(&ProviderKeyView::new(&row, None)).unwrap();
    let revealed = serde_json::to_string(&crate::admin_ops::key_view(&row, String::new())).unwrap();
    for json in [listed, revealed] {
        assert!(!json.contains("oauth"));
        assert!(!json.contains("accessToken"));
        assert!(!json.contains("refreshToken"));
        assert!(!json.contains("clientSecret"));
    }
}
```

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task1 -- --nocapture`

Expected: FAIL，原因是 `auth_kind`/`oauth` 尚不存在。

- [ ] **Step 3: 添加 migration 与纯凭证类型**

```sql
ALTER TABLE public.gateway_providers DROP CONSTRAINT IF EXISTS gateway_providers_protocol_check;
ALTER TABLE public.gateway_providers ADD CONSTRAINT gateway_providers_protocol_check
CHECK (protocol = ANY (ARRAY[
  'anthropic_messages'::text, 'openai_chat'::text, 'openai_responses'::text,
  'gemini'::text, 'openai_embeddings'::text, 'kiro'::text
]));

ALTER TABLE public.gateway_provider_keys
  ADD COLUMN auth_kind text NOT NULL DEFAULT 'static',
  ADD COLUMN oauth jsonb;
ALTER TABLE public.gateway_provider_keys
  ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind IN ('static', 'kiro_oidc')),
  ADD CONSTRAINT gateway_provider_keys_oauth_check
    CHECK ((auth_kind = 'static' AND oauth IS NULL)
        OR (auth_kind = 'kiro_oidc' AND oauth IS NOT NULL));
```

`api_key` 已是 nullable，不改列。`KiroOAuth` 使用 camelCase JSON、Unix 秒 expiry，且 Debug 必须全量遮蔽：

```rust
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroOAuth {
    pub access_token: String,
    pub expires_at: i64,
    pub refresh_token: String,
    pub client_id: String,
    pub client_secret: String,
    pub region: String,
    pub auth_region: String,
    pub api_region: String,
    pub profile_arn: Option<String>,
}

impl KiroOAuth {
    pub fn validate(&self) -> anyhow::Result<()> {
        for value in [&self.access_token, &self.refresh_token, &self.client_id,
                      &self.client_secret, &self.region, &self.auth_region, &self.api_region] {
            anyhow::ensure!(!value.trim().is_empty(), "Kiro OAuth fields must not be empty");
        }
        Ok(())
    }
    pub fn fresh_for(&self, now: i64) -> bool { self.expires_at > now + 600 }
}
impl std::fmt::Debug for KiroOAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KiroOAuth").field("expires_at", &self.expires_at)
            .field("region", &self.region).finish_non_exhaustive()
    }
}
```

测试只能使用上述假值；真实账号字段不得复制进测试或失败输出。

- [ ] **Step 4: 扩展 row 查询与现有 Admin key API**

`ProviderKeyRow` 增加 `auth_kind:String` 和 `#[sqlx(json(nullable))] #[serde(skip)] oauth:Option<KiroOAuth>`；所有显式 SELECT 加这两列。`ProviderKeyView`、`KeyView` 不变。

保留 `insert_provider_key` static 包装，新增 `insert_kiro_key` 与 `replace_kiro_oauth`，避免改无关调用方。`KeyBody` 增加可选 `auth_kind`/`oauth`；static 仍要求非空 `api_key`，Kiro 要求 `provider.protocol == "kiro"`、`api_key` 空、OAuth 校验通过。`PatchKeyBody.oauth` 只允许更新已有 Kiro key，不把 static key 改成 OIDC。

Admin 更新 OAuth 后调用 `KiroTokens::replace`（Task 8 接入内存失效；本任务只完成 store 接口与标注调用点，不提前引用未创建类型）；删除 key 时的 token state 清理同样在 Task 8 接通。普通列表和 reveal 不新增 OAuth 字段。

- [ ] **Step 5: 验证、删除临时测试并提交**

```bash
DATABASE_URL=postgresql://beaver:beaver@127.0.0.1/cardinal_kiro_verify cargo test kiro_task1 -- --nocapture
cargo build
cargo clippy --all-targets -- -D warnings
```

Expected: 测试 PASS；build/clippy 退出 0。删除临时测试后再次 build/clippy。

```bash
git add migrations/0007_kiro.sql src/lib.rs src/kiro/mod.rs src/kiro/credentials.rs src/store/key.rs src/store/mod.rs src/admin.rs src/admin_ops.rs
git commit -m "feat: store Kiro OIDC credentials without exposing them"
```

## Task 2: `ProtocolId::Kiro`、capabilities 与 IR cache key

**Files:**
- Modify: `src/protocol/mod.rs`, `src/relay/capabilities/mod.rs`, `src/translation/mod.rs`
- Modify: `src/translation/stream.rs`, `src/translation/effort_clamp.rs`, `src/relay/route_cache.rs`, `src/api.rs`, `src/relay.rs`
- Modify: `src/translation/ir.rs`, `src/translation/openai_chat.rs`, `src/translation/openai_responses.rs`, `src/translation/anthropic_messages.rs`
- Create: `src/protocol/kiro.rs`（本任务仅为让穷尽分支持续编译的 unsupported stub，Task 5 完整实现）
- Temporary test: `src/translation/mod.rs` 内临时模块

- [ ] **Step 1: 写失败的矩阵测试**

```rust
#[test]
fn kiro_task2_only_chat_translates_to_kiro() {
    assert!(translatable(ProtocolId::OpenAiChat, ProtocolId::Kiro));
    assert!(!translatable(ProtocolId::Kiro, ProtocolId::OpenAiChat));
    assert!(!translatable(ProtocolId::AnthropicMessages, ProtocolId::Kiro));
    assert!(!translatable(ProtocolId::OpenAiResponses, ProtocolId::Kiro));
    assert!(!translatable(ProtocolId::Kiro, ProtocolId::Kiro));
}
```

另验证 Chat `prompt_cache_key` 进入 `IrRequest`，Responses 也保留；现有 emitter 不把它发给 Chat/Anthropic 目标。

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task2 -- --nocapture`
Expected: FAIL，`Kiro` 与 `prompt_cache_key` 尚不存在。

- [ ] **Step 3: 增加封闭协议分支**

`ProtocolId::Kiro`：`as_str/from_str = "kiro"`，`client_paths=[]`，`streaming_shares_endpoint=true`。`MATRIX_DIALECTS` 扩为 4 项并加入 Kiro（它表示参与 IR 的 dialect，不是入站端点集合）。所有 match 显式处理 Kiro，未实现 kernel 暂返 `UnsupportedApi`，不得落进 Chat。

capabilities 走 `single_protocol`：`protocol_suffix(Kiro)=""`，endpoint 为 provider `base_url + "/"`，静态 auth header 最终由 Task 8 替换为 OAuth bearer。`OPENED` 仅加 `(OpenAiChat,Kiro)`。

- [ ] **Step 4: 给 IR 增加可选 cache key**

```diff
 pub struct IrRequest {
+    pub prompt_cache_key: Option<String>,
 }
```

三个 parser 的所有构造点显式赋值；Chat/Responses 从 body 取非空字符串并移出 dropped 列表，Anthropic 为 `None`。不支持它的目标继续记录 `prompt_cache_key` drop，Kiro 消费它。

- [ ] **Step 5: 验证、清理并提交**

```bash
cargo test kiro_task2 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: PASS/0/0。删除临时测试。

```bash
git add src/protocol/mod.rs src/protocol/kiro.rs src/relay/capabilities/mod.rs src/relay/route_cache.rs src/relay.rs src/api.rs src/translation/mod.rs src/translation/stream.rs src/translation/effort_clamp.rs src/translation/ir.rs src/translation/openai_chat.rs src/translation/openai_responses.rs src/translation/anthropic_messages.rs
git commit -m "feat: register Kiro as a translated upstream protocol"
```

## Task 3: AWS Event Stream 纯帧层

**Files:**
- Create: `src/protocol/awseventstream.rs`
- Modify: `src/protocol/mod.rs`, `Cargo.toml`
- Temporary test: `src/protocol/awseventstream.rs` 内临时模块

- [ ] **Step 1: 用独立金字节写失败测试**

测试向量不得由本实现 encoder 生成。使用参考 `frame.ts/header.ts` 的字段布局手工列字节，至少覆盖：一帧跨所有字节切分、连续两帧、全部 10 种 header type、两段 CRC 损坏、错误 total/header length、16 MiB+1 拒绝、EOF 半帧。

核心断言：

```rust
#[test]
fn kiro_task3_golden_frame_and_every_split() {
    // :message-type=event, :event-type=assistantResponseEvent,
    // payload={"content":"ok"}；prelude/message CRC 由 Python zlib 独立计算。
    let golden: &[u8] = &[
        0,0,0,91, 0,0,0,59, 155,234,200,151,
        13,58,109,101,115,115,97,103,101,45,116,121,112,101,7,0,5,101,118,101,110,116,
        11,58,101,118,101,110,116,45,116,121,112,101,7,0,22,97,115,115,105,115,116,97,
        110,116,82,101,115,112,111,110,115,101,69,118,101,110,116,
        123,34,99,111,110,116,101,110,116,34,58,34,111,107,34,125,
        128,78,148,37,
    ];
    for split in 0..=golden.len() {
        let mut framer = Framer::new();
        let mut frames = framer.push(&golden[..split]).unwrap();
        frames.extend(framer.push(&golden[split..]).unwrap());
        assert_eq!(frames.len(), 1, "split={split}");
        assert_eq!(frames[0].string_header(":message-type"), Some("event"));
        assert_eq!(frames[0].string_header(":event-type"), Some("assistantResponseEvent"));
        assert_eq!(frames[0].payload.as_ref(), br#"{"content":"ok"}"#);
        framer.finish().unwrap();
    }
}

#[test]
fn kiro_task3_truncated_finish_is_an_error() {
    let mut framer = Framer::new();
    framer.push(&[0, 0, 0, 20, 0, 0]).unwrap();
    assert_eq!(framer.finish(), Err(AwsError::Truncated));
}
```

该向量不得用本实现输出重新生成；修改解析器时若向量失败，应先证明解析器而非金样本有误。

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task3 -- --nocapture`
Expected: FAIL，模块/类型不存在。

- [ ] **Step 3: 实现有界增量解析**

增加 `crc32fast = "1"`。公共类型：

```rust
pub const MAX_FRAME: usize = 16 << 20;
pub struct Message { pub headers: Vec<(String, HeaderValue)>, pub payload: bytes::Bytes }
pub enum HeaderValue { Bool(bool), Byte(i8), Short(i16), Integer(i32), Long(i64),
    Bytes(bytes::Bytes), String(String), Timestamp(i64), Uuid([u8;16]) }
pub enum AwsError { Truncated, FrameTooLarge, InvalidLength, InvalidPreludeCrc,
    InvalidMessageCrc, InvalidHeader, InvalidUtf8 }
pub struct Framer { buffer: bytes::BytesMut }
```

`Framer::new()` 以空 `BytesMut` 初始化；`push(&[u8]) -> Result<Vec<Message>,AwsError>` 返回本次新完成的帧；`finish()` 只在 buffer 为空时返回 `Ok(())`，否则 `Err(AwsError::Truncated)`。

解析顺序：至少读 12 字节 prelude -> 验证 total>=16、header length 与 total 边界、prelude CRC -> 等完整帧 -> message CRC -> 精确消费 headers/payload。Header name length 为 u8；type 0/1 无 value 字节，2/3/4/5 分别 1/2/4/8，6/7 先读 u16 length，8 读 i64 millis，9 读 16 字节。未知 type、空 name、header 未恰好耗尽均报错。只用 `split_to` 移出完成帧，不逐 chunk 深拷贝既有 buffer。

提供 `Message::string_header(name)` 供 kernel 读取 `:message-type` 等，不把 AWS header 塞进 SSE event 字符串。

- [ ] **Step 4: 验证、清理并提交**

```bash
cargo test kiro_task3 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 金样本、任意切分和错误矩阵 PASS。删除临时测试。

```bash
git add Cargo.toml Cargo.lock src/protocol/mod.rs src/protocol/awseventstream.rs
git commit -m "feat: parse bounded AWS Event Stream frames"
```

## Task 4: 通用 `WireFrame` 与行为保持的流式泵

**Files:**
- Create: `src/protocol/wire.rs`
- Modify: `src/protocol/mod.rs`, `src/upstream/transport.rs`, `src/relay.rs`, `src/relay/streaming.rs`
- Temporary test: `src/relay/streaming.rs` 内临时模块

- [ ] **Step 1: 先写现有 SSE 回归测试**

使用内存帧而非网络：SSE chunk 任意切分后 `WireFrame::Sse` 与旧 `RawFrame` 完全相同；正常 stop、[DONE]、无终结 EOF 三种门控不变。Kiro AWS 半帧 EOF 返回 `TransportError::InvalidBody`，translated pump post-commit 走现有 error 合成与 `StreamOutcome::Interrupted`。

- [ ] **Step 2: 运行并确认 AWS 用例红灯**

Run: `cargo test kiro_task4 -- --nocapture`
Expected: SSE 用例可先 PASS；AWS 类型/半帧用例 FAIL。

- [ ] **Step 3: 引入封闭 wire 抽象**

```rust
pub enum WireFrame { Sse(crate::protocol::sse::RawFrame), Aws(crate::protocol::awseventstream::Message) }
pub enum WireFramer { Sse(crate::protocol::sse::Framer), Aws(crate::protocol::awseventstream::Framer) }
impl WireFramer {
    pub fn for_protocol(protocol: ProtocolId) -> Self {
        if protocol == ProtocolId::Kiro { Self::Aws(crate::protocol::awseventstream::Framer::new()) }
        else { Self::Sse(crate::protocol::sse::Framer::new()) }
    }
}
```

`Transport::stream(response, deadline, protocol)` 构造对应 framer，`StreamReader.pending` 改为 `VecDeque<WireFrame>`，`next_wire_frame` 统一读取。SSE finish 保持旧尾部行为；AWS finish 的 `Truncated` 映射 `InvalidBody`，不能静默成功。

`Decoder::observe_wire(&WireFrame)` 对现有协议只接受 Sse，对 Kiro 只接受 Aws；不匹配返 `InvalidUpstreamResponse`，不 panic。PassThrough 只渲染 Sse（Kiro 无入站，因此不会出现 Kiro->Kiro）。`stream_error_frames` 仍由客户端协议的 decoder 生成，不能尝试把 SSE error 渲染成 AWS。

- [ ] **Step 4: 验证、清理并提交**

```bash
cargo test kiro_task4 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 全部 PASS，现有 SSE 行为无差异。删除临时测试。

```bash
git add src/protocol/wire.rs src/protocol/mod.rs src/upstream/transport.rs src/relay.rs src/relay/streaming.rs
git commit -m "refactor: support SSE and AWS wire framing in the relay"
```

## Task 5: KAS 请求画像与 Kiro kernel prepare

**Files:**
- Create: `src/kiro/profile.rs`
- Modify: `src/kiro/mod.rs`, `src/protocol/kiro.rs`, `src/protocol/mod.rs`, `src/relay.rs`, `Cargo.toml`
- Temporary test: `src/protocol/kiro.rs` 内临时模块

- [ ] **Step 1: 写失败的 wire 契约测试**

断言 `Prepared.url = https://runtime.us-east-1.kiro.dev/`，content type/target/UA/optout/attribution/retry headers 完整；body 不含 `stream`。attempt 1 无 ttl，attempt 2 同 invocation、有 ttl 且两条 attempt header 均为 2；新 candidate prepare 得新 invocation。

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task5 -- --nocapture`
Expected: FAIL，KAS prepare 仍 unsupported。

- [ ] **Step 3: 集中定义画像与重试头**

增加 `uuid = { version = "1", features = ["v4", "v5"] }`。`profile.rs` 固化参考 `client-profile.ts` 的 KAS 2.34.0/KAS 0.66.62 UA、Shell 1.3.10 UA，以及：

```rust
pub const KAS_TARGET: &str = "KiroRuntimeService.GenerateAssistantResponse";
pub const USAGE_TARGET: &str = "AmazonCodeWhispererService.GetUsageLimits";
pub const KIRO_MAX_ATTEMPTS: u32 = 3;
pub fn kas_endpoint(region: &str) -> String { format!("https://runtime.{region}.kiro.dev/") }
pub fn runtime_host(region: &str) -> String {
    if region == "us-east-1" { format!("codewhisperer.{region}.amazonaws.com") }
    else { format!("q.{region}.amazonaws.com") }
}
pub fn retry_headers(invocation: &str, attempt: u32, max: u32, kiro: bool, now: chrono::DateTime<chrono::Utc>) -> Vec<(&'static str, String)> {
    let ttl = if attempt > 1 { format!("ttl={}; ", (now + chrono::Duration::hours(1)).format("%Y%m%dT%H%M%SZ")) } else { String::new() };
    let mut headers = vec![
        ("amz-sdk-invocation-id", invocation.to_owned()),
        ("amz-sdk-request", format!("{ttl}attempt={attempt}; max={max}")),
    ];
    if kiro { headers.push(("x-kiro-attempt", format!("{attempt};max={max}"))); }
    headers
}
```

KAS prepare 生成一次 invocation，初始 attempt=1；静态头含 `application/x-amz-json-1.0`、完整 UA/x-amz-user-agent、optout=true、attribution=kiro-cli。不要把 `connection`/`host` 交给 reqwest 手工伪造。

- [ ] **Step 4: 接通 kernel 并门控 translated `stream`**

`protocol::prepare(Kiro)` 调 KAS prepare，`parse_json` 与 Decoder 在 Task 7 完成。`prepare_translated` 仅在目标不是 Kiro 时保留现有 `stream:true` 注入；并在 Kiro 分支注入当前 candidate 的 `key.oauth.profileArn`，绝不读 provider 级缓存：

```rust
if upstream == ProtocolId::Kiro {
    let oauth = ctx.candidate.key.oauth.as_ref().ok_or(ProtocolError::UpstreamAuthenticationFailed)?;
    if let Some(profile_arn) = oauth.profile_arn.as_deref() {
        upstream_value["profileArn"] = serde_json::Value::String(profile_arn.to_owned());
    }
    anyhow::ensure!(upstream_value.get("stream").is_none(), "Kiro KAS body must not contain stream");
}
```

optional-strip 重试不得重新生成 Kiro invocation；首版 Kiro 不进入 Chat/GLM 的 strip 分支。

- [ ] **Step 5: 验证、清理并提交**

```bash
cargo test kiro_task5 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: PASS/0/0。删除临时测试。

```bash
git add Cargo.toml Cargo.lock src/kiro/mod.rs src/kiro/profile.rs src/protocol/kiro.rs src/protocol/mod.rs src/relay.rs
git commit -m "feat: prepare Kiro KAS requests with the CLI wire profile"
```

## Task 6: 借用 IR 的会话、工具、模型与 effort 转换

**Files:**
- Create: `src/translation/kiro.rs`
- Modify: `src/translation/mod.rs`, `src/relay.rs`
- Temporary test: `src/translation/kiro.rs` 内临时模块

- [ ] **Step 1: 写失败的请求语义矩阵**

覆盖：system 折进第一条 user；最后 user 为 currentMessage；连续 user 合并；assistant tool call/result 按 ID 配对；缺失与孤立结果明确标注未提供而非成功；工具声明仅 current context；两个并行工具保持顺序；工具往返 continuation 不变，下一真实用户轮次改变；有/无 `prompt_cache_key` 的确定性；GPT 显式 off 不变成 low。

关键断言：

```rust
#[test]
fn kiro_task6_tool_round_trip_keeps_conversation_and_continuation() {
    let first = from_ir(&tool_round_trip_ir(None), "claude-sonnet-4.5").unwrap();
    let repeat = from_ir(&tool_round_trip_ir(None), "claude-sonnet-4.5").unwrap();
    assert_eq!(first["conversationState"]["conversationId"], repeat["conversationState"]["conversationId"]);
    assert_eq!(first["conversationState"]["agentContinuationId"], repeat["conversationState"]["agentContinuationId"]);
    assert_eq!(first["conversationState"]["history"].as_array().unwrap().len(), 2);
}

#[test]
fn kiro_task6_gpt_off_is_not_low() {
    let body = from_ir(&ir_with_effort(Effort::None), "gpt-5.6").unwrap();
    assert_ne!(body["additionalModelRequestFields"]["reasoning_effort"], "low");
    assert!(body["additionalModelRequestFields"].get("reasoning_effort").is_none());
}
```

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task6 -- --nocapture`
Expected: FAIL，`from_ir` 不存在。

- [ ] **Step 3: 实现索引化 current/history 转换**

公共入口：

```rust
pub fn from_ir(request: &IrRequest, model: &str) -> crate::translation::Parsed<serde_json::Value>;
```

先扫描 `request.messages` 找最后一个真实 user/current 边界，再用索引遍历，不 `clone()` 整段消息。输出顶层 `agentMode="vibe"`、`chatTriggerType="MANUAL"`、`origin="KIRO_CLI"`；conversationState 包含 `conversationId`、`rootConversationId`、`agentContinuationId`、`agentTaskType="vibe"`、`currentMessage`、`history`。

会话派生：

```rust
let seed = request.prompt_cache_key.as_deref()
    .map(str::to_owned)
    .unwrap_or_else(|| stable_opening_seed(&request.system, &request.messages));
let conversation = format!("sess_{}", uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, seed.as_bytes()));
let continuation = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL,
    format!("{conversation}\n{}", user_turn_key(&request.messages)).as_bytes()).to_string();
```

`user_turn_key` 按参考：连续有内容 user 合并为一轮；含 tool result 的 user 不算新轮次；轮次文本参与 hash，避免压缩后序号回落复用旧 continuation。完整 history 每次照发，稳定 ID 只用于分组。

- [ ] **Step 4: 移植模型/effort 表与响应请求字段**

以参考 `converter.ts` 当前 `modelMap` 和 `buildAdditionalModelRequestFields` 为基线，逐项复制首版支持模型，未知模型返 `InvalidRequest`，不得猜测。显式 `Effort::None` 独立分支：Kiro 无 off wire 时省略 reasoning 控制并使用上游默认，不得经 `chat_name()` 变成 low。其他 effort 按模型表映射；不支持档位按现有 `effort_clamp` 已解析结果发送，不新增第二套 clamp。

首版不承载 Anthropic reasoning signature，不生成需签名的 history `reasoningContent`，因此不增加 signature-strip retry。

- [ ] **Step 5: 验证、清理并提交**

```bash
cargo test kiro_task6 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 全矩阵 PASS，GPT off 断言 PASS。删除临时测试。

```bash
git add src/translation/kiro.rs src/translation/mod.rs src/relay.rs
git commit -m "feat: translate chat conversations into Kiro KAS sessions"
```

## Task 7: 共用流式/非流式响应状态机与 IR 枢纽

**Files:**
- Modify: `src/protocol/kiro.rs`, `src/protocol/mod.rs`, `src/translation/kiro.rs`, `src/translation/mod.rs`
- Modify: `src/translation/openai_chat.rs`（仅在现有 emitter 尚不能省略 usage 时）
- Temporary test: `src/protocol/kiro.rs` 内临时模块

- [ ] **Step 1: 写失败的事件与 usage 测试**

同一组 AWS Message 分别驱动增量 Decoder 和完整 body 聚合，最终 `IrResponse` 等价。覆盖文本、reasoning、并行 toolUseId 的 index 稳定、参数增量、metadata 正常终止、无 metadata EOF 失败、工具时 finish=tool_calls、error/exception、坏 JSON、未知普通 event 忽略、未知 usage 省略。

```rust
#[test]
fn kiro_task7_parallel_tool_indices_follow_ids() {
    let mut decoder = StreamDecoder::new();
    let mut events = Vec::new();
    for message in parallel_tool_messages() { events.extend(decoder.observe(&message).unwrap()); }
    let first: Vec<_> = events.iter().filter_map(tool_index_and_id).collect();
    assert_eq!(first, vec![(0, "call-a".to_owned()), (1, "call-b".to_owned())]);
    assert_eq!(decoder.finish(), Terminal::Completed);
    assert_eq!(decoder.finish_reason(), Some("tool_calls"));
    assert!(decoder.usage().is_none());
}
```

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task7 -- --nocapture`
Expected: FAIL，Kiro Decoder/response 聚合尚未实现。

- [ ] **Step 3: 实现 Kiro Decoder**

状态包含文本/reasoning 聚合、`HashMap<String,u32>` 工具 index、按 index 的名称/参数累积、metadata 标志、原始 metering 诊断、失败标志。`assistantResponseEvent.content` -> `TextDelta`；`reasoningContentEvent.text` -> `ReasoningDelta`（signature 可内部保留，不对外伪造）；toolUseEvent 校验非空 id/name、input string、stop bool，以 ID 查/分配 index。

`metadataEvent` 只作为正常结束证据，stopReason 不决定是否工具终止。`meteringEvent` 保存原始 `usage/unit/unitPlural` 供诊断，不填 `UsageCounts`；`contextUsageEvent` 只诊断。`error`/`exception` 返回包含安全 error code/exception type 的 `InvalidUpstreamResponse`，未知普通 event 忽略，未知 message-type 报错。

`parse_json(Kiro)` 用 AWS Framer 解完整 body并复用 Decoder，返回 `ObservedResponse { usage: None, .. }`；不能构造全零 usage。`translation::kiro::response_to_ir(&[u8])` 复用同一 Decoder 聚合内容，避免 protocol 反向依赖 translation。

- [ ] **Step 4: 注册目标方言并确保 Chat 省略未知 usage**

`translation::for_protocol(Kiro)` 注册 `from_ir/response_to_ir`；`to_ir` 与 `emit_response_json` 返回 `UnsupportedApi`，因为没有 Kiro 入站。`OPENED` 仍只有 Chat->Kiro。Chat emitter 对 `IrResponse.usage=None` 不输出 `usage` 字段，不能 `unwrap_or_default()`。

- [ ] **Step 5: 验证、清理并提交**

```bash
cargo test kiro_task7 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 流式/聚合等价、并行工具、截断与 usage 用例 PASS。删除临时测试。

```bash
git add src/protocol/kiro.rs src/protocol/mod.rs src/translation/kiro.rs src/translation/mod.rs src/translation/openai_chat.rs
git commit -m "feat: decode Kiro streams into chat responses and tool calls"
```

## Task 8: 共享 OIDC TokenManager 与 runtime 401 单次恢复

**Files:**
- Create: `src/upstream/kiro_tokens.rs`
- Modify: `src/upstream/mod.rs`, `src/api.rs`, `src/gateway.rs`, `src/relay.rs`, `src/admin.rs`, `src/admin_ops.rs`
- Modify: `src/relay/candidates.rs`, `src/relay/failover.rs`（仅错误映射需要时）
- Temporary test: `src/upstream/kiro_tokens.rs` 内临时模块

- [ ] **Step 1: 写失败的状态机测试**

用本地可控 HTTP server + 临时 PostgreSQL，覆盖：新鲜 token 零刷新；10 分钟内刷新；N 个并发只一次 CreateToken；等待者锁后复用；DB refresh token 比 RouteCache 新时使用 DB；响应无新 refresh token 保留旧值；轮换完整落库；旧 bearer 401 并发只强制刷新一次；401 原 candidate 只重试一次；invalid_grant 永久失败且提示重新导入；OIDC 429/5xx 临时失败；持久化失败仍可使用内存新 token 且 warn 不含秘密；落库失败后的下一次刷新/DB 重读不得恢复旧 refresh token。

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task8 -- --nocapture`
Expected: FAIL，`KiroTokens` 尚不存在。

- [ ] **Step 3: 实现 per-key single-flight**

```rust
#[derive(Clone)]
pub struct KiroTokens {
    transport: crate::upstream::transport::Transport,
    states: dashmap::DashMap<i64, std::sync::Arc<tokio::sync::Mutex<KiroTokenState>>>,
}
pub struct KiroTokenState {
    oauth: crate::kiro::credentials::KiroOAuth,
    /// false = 内存凭证比 DB 新；落库恢复前禁止被 DB 旧快照覆盖。
    persisted: bool,
}
pub struct KiroCallContext {
    pub bearer: secrecy::SecretString,
    pub profile_arn: Option<String>,
}
impl KiroTokens {
    pub fn remove(&self, key_id: i64) { self.states.remove(&key_id); }
}
```

其余公共契约为：`new(transport)` 初始化空状态表；`access_token(pool,key) -> Result<KiroCallContext,KiroTokenError>` 返回 fresh token 或执行刷新；`recover_invalidated(pool,key,old_bearer) -> Result<KiroCallContext,KiroTokenError>` 按旧 bearer 去重并强制刷新；`replace(key_id,oauth)` 在 Admin 轮换后替换内存状态并标记 `persisted=true`。调用方只能接触 bearer/profileArn，不能接触 refresh token。

锁内 fresh 检查通过立即返回；需刷新且 `persisted=true` 时先 `store::kiro_oauth(pool,key.id)` 重读并再次 fresh 检查，再发 OIDC。`recover_invalidated` 获锁后若当前 access token 已不同于 old，直接复用，不重复刷新。所有异步锁错误/中毒路径降级并 warn，不能 unwrap。

刷新成功后立即把完整新 OAuth 放进内存，再尝试落库：成功设 `persisted=true`，失败设 `false`。`persisted=false` 时不得用 DB 旧 OAuth 覆盖内存；后续先重试持久化这份完整状态。即使再次落库失败，fresh access token 仍可用；必须再次刷新时也使用内存里最新的 refresh token，不能回退到旧轮换令牌。RouteCache 初次播种和 Admin 成功轮换都标记 `persisted=true`。

- [ ] **Step 4: 实现 CreateToken 与原子持久化**

通过共享 `Transport` 发 `https://oidc.{authRegion}.amazonaws.com/token`，JSON 严格为：

```json
{"clientId":"<clientId>","clientSecret":"<clientSecret>","refreshToken":"<refreshToken>","grantType":"refresh_token"}
```

OIDC 使用 `amz-sdk-*`、`max=4`、不发 `x-kiro-attempt`。响应读取 `accessToken/expiresIn/refreshToken?/profileArn?`，计算 `expiresAt=now+expiresIn`，未返 refresh token 则保留旧值。`store::replace_kiro_oauth` 一次性 UPDATE 完整 JSONB；失败仅记录 key_id/status，保留内存新凭证。

400 `invalid_grant` -> `KiroTokenError::Permanent`（“Kiro credentials invalidated; re-import the account”）；429/5xx/网络/超时 -> Temporary；错误 Display/日志不拼 OAuth body。

- [ ] **Step 5: 注入 relay 并做原 candidate 单次 401 重试**

`AppState` 新增 `Arc<KiroTokens>`；`DispatchDeps` 同时携带 `pool:&PgPool` 与 `kiro_tokens:&KiroTokens`。relay resolve 无需在锁内 DB I/O：RouteCache 提供初始 OAuth，真正刷新由 manager 重读 DB。

`fetch_key_secrets` 在检查空 `api_key` 前按 `auth_kind` 分支：`kiro_oidc` 要求完整 OAuth 并保留 candidate，static 维持现有缺失凭证跳过逻辑。Kiro candidate 的静态 `secret` 永不作为上游 bearer 使用；只有 `KiroCallContext.bearer` 能覆盖 Authorization。

Kiro `send_attempt` 取 `KiroCallContext` 后覆盖 Authorization；runtime 401/403 且 bounded error body 匹配参考的 bearer-invalid 标记 `The bearer token included in the request is invalid` 时，先读完 body，再 `recover_invalidated(old)`，复用同一 Prepared invocation，attempt 增为 2，只重发当前 candidate 一次。若 context 带回新 profileArn，在冷路径解析并更新 Prepared body 的该字段后重发，invocation 不变。第二次失败交回现有 failover。换 candidate 重新 prepare，产生新 invocation/attempt=1。

`AttemptError` 增加持有 `KiroTokenError` 的显式分支：Permanent 的 client status 为 401、message 固定包含“re-import the account”，Temporary 按 OIDC status/timeout 映射现有临时故障；failover 仍跳过当前 candidate，不能把永久凭证失效伪装成请求 JSON 错误。

Admin OAuth replace/delete 接 `KiroTokens::replace/remove`，避免重新导入后旧新鲜 token 残留。

- [ ] **Step 6: 验证、清理并提交**

```bash
DATABASE_URL=postgresql://beaver:beaver@127.0.0.1/cardinal_kiro_verify cargo test kiro_task8 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 状态机全 PASS，日志扫描不含假 secret。删除临时测试。

```bash
git add src/upstream/kiro_tokens.rs src/upstream/mod.rs src/api.rs src/gateway.rs src/relay.rs src/relay/candidates.rs src/relay/failover.rs src/admin.rs src/admin_ops.rs
git commit -m "feat: refresh and persist Kiro OIDC tokens per key"
```

## Task 9: GetUsageLimits 接入现有配额、SmartCache 与 GUI

**Files:**
- Modify: `src/quota.rs`, `src/admin_ops.rs`, `src/gateway.rs`, `src/admin.rs`, `src/api.rs`
- Modify: `src/kiro/profile.rs`
- Temporary test: `src/quota.rs` 内临时模块

- [ ] **Step 1: 写失败的纯映射与请求测试**

构造 CREDIT precision/整数 fallback/顶层 reset/空列表/非 CREDIT/零 limit 响应用例。断言：

```rust
#[test]
fn kiro_task9_credit_window_maps_existing_quota_shape() {
    let quota = parse_kiro_quota(kiro_usage_fixture()).unwrap();
    assert_eq!(quota.windows.len(), 1);
    let window = &quota.windows[0];
    assert_eq!(window.name, "本月 Credits");
    assert_eq!(window.used_pct, 54.6938);
    assert_eq!(window.total.as_deref(), Some("10000 Credits"));
    assert_eq!(window.period_minutes, Some(30 * 1440));
    assert_eq!(window.resets_at.unwrap().timestamp(), 1777593600);
}
```

另断言请求 `isEmailRequired=false` 同时在 query/body，profileArn 双写，Shell target/UA，无 `x-kiro-attempt`，不读取/记录 userInfo。

- [ ] **Step 2: 运行并确认红灯**

Run: `cargo test kiro_task9 -- --nocapture`
Expected: FAIL，Kiro quota parser 不存在。

- [ ] **Step 3: 实现共享 token 的配额探测**

`fetch_kiro_quota(pool, tokens, key)` 调 `tokens.access_token`，使用共享 Transport POST `https://{runtime_host(apiRegion)}/`，query 为 `isEmailRequired=false` 与可选 `profileArn=<返回 context 的 ARN>`。Shell retry headers `attempt=1; max=1`，单次不重试。响应 bounded read，非 2xx/坏 JSON/无 CREDIT 返回 None 并 warn，不影响聊天。

解析只选 `resourceType="CREDIT"`：precision 优先，整数 fallback；`used/limit*100` clamp 0–100，limit<=0 无有效读数；total 保留 Credits 文本；reset 用 breakdown 后顶层 Unix 秒；不加 bonuses，不换 token，period=30*1440。

- [ ] **Step 4: 在跳过空 api_key 之前分派 Kiro**

`probe_all_quotas(pool, smart_cache, kiro_tokens)` 按 `provider.protocol=="kiro"` 调专用分支，其他 provider 保持 `fetch_quota`。`Admin` 持有共享 tokens，`Admin::quotas` 与 `gateway::quota_prober` 传同一个实例。成功仍走现有 snapshot upsert/history insert/SmartCache refresh/activity push，因此 GUI 无需修改且失败保留旧快照。

- [ ] **Step 5: 验证、清理并提交**

```bash
cargo test kiro_task9 -- --nocapture
cargo build && cargo clippy --all-targets -- -D warnings
```

Expected: 映射和请求画像 PASS，现有 provider quota 测试无回归。删除临时测试。

```bash
git add src/quota.rs src/admin_ops.rs src/gateway.rs src/admin.rs src/api.rs src/kiro/profile.rs
git commit -m "feat: show Kiro monthly credits in existing provider quotas"
```

## Task 10: 一次性账号白名单导入

**Files:**
- Create: `scripts/import-kiro-account.py`
- Temporary verification: `~/.ox/tmp/kiro-import-verify.json`（假凭证）

- [ ] **Step 1: 写脚本并先用假导出验证白名单**

接口：

```bash
CARDINAL_ADMIN_URL=https://c1.iios.net \
CARDINAL_ADMIN_KEY="$CARDINAL_ADMIN_KEY" \
python3 scripts/import-kiro-account.py \
  --input kiro-account-shengta.iq.uan1688-20261026-112628.json \
  --account 0 --provider kiro --label main
```

脚本只用 Python stdlib。读取 `accounts[index]`，仅提取 `credentials.{clientId,clientSecret,refreshToken,accessToken,expiresAt,region}` 与账号顶层 `profileArn`；毫秒 expiry 用整数除法 `expiresAt // 1000` 转成 Task 1 的 Unix 秒，authRegion/apiRegion=region。拒绝缺字段/空字段，不读取 password/email/csrfToken/machineId/nickname/usage/subscription 到 payload。

通过现有 Admin API：GET providers/keys -> 不存在则 POST，存在 provider 时用现有 PATCH 保持 `protocol=kiro`、`auth_scheme=bearer`、`base_url=https://runtime.{region}.kiro.dev` 与账号 region 一致，存在 Kiro key 则 PATCH `oauth`；若同名 provider/key 认证类型冲突则 fail closed。key body `auth_kind=kiro_oidc`、`api_key=null`、完整 OAuth。

Admin key 只从环境变量读取；HTTP 必须 HTTPS 或 loopback；错误只打印 HTTP status 和不含响应 body 的固定消息；成功只打印 provider/key id。禁止打印 payload、OAuth、admin key。

- [ ] **Step 2: 验证假导入与重复导入**

对临时验证 gateway 执行两次，第一次创建、第二次更新同 key；检查数据库仅有一行且 OAuth 更新，普通 `/api/bootstrap` 与 reveal 不含 OAuth。检查 shell 进程列表/日志不含假 token。

Expected: 幂等，无新增导入 API，无秘密输出。

- [ ] **Step 3: 编译检查并提交**

```bash
python3 -m py_compile scripts/import-kiro-account.py
git diff --check
```

Expected: 均退出 0；删除 `__pycache__` 与假导出，不删除用户真实 JSON。

```bash
git add scripts/import-kiro-account.py
git commit -m "feat: import Kiro account credentials through the admin API"
```

## Task 11: 真实 Transport 端到端、真实账号验收与清理

**Files:**
- Temporary test: `src/relay/streaming.rs` 或独立临时验证二进制，全部在提交前删除
- Modify: 仅当验收暴露实际缺陷时修改对应模块并回归相关任务矩阵

- [ ] **Step 1: 假 Kiro 全链路测试**

本地可控服务器接收真实 `Transport` 请求并返回固定 AWS 金帧；响应拆成多个 HTTP chunk，至少一帧从 header/payload 中间劈开。经真实 `/v1/chat/completions` 验证：
1. 非流式文本 + usage 省略；
2. 流式文本/reasoning；
3. 并行工具调用及下一轮 tool result；
4. 401 后刷新且同 invocation attempt=2；
5. post-commit 半帧 EOF 客户端收到 Chat error 终结帧，`gateway_requests.error` 非空；
6. failover 到其他协议仍正常，新 Kiro candidate 使用新 invocation。

Run: `DATABASE_URL=postgresql://beaver:beaver@127.0.0.1/cardinal_kiro_verify cargo test kiro_task11 -- --nocapture`
Expected: 六项 PASS。删除临时测试后 build/clippy。

- [ ] **Step 2: 真实账号无副作用验收**

先运行导入脚本并启动本地 gateway，配置手工 Kiro route；不得让 kiro2claude 或其他程序继续旋转该 refresh token。依次执行：
- 流式与非流式短问答；
- 带 system 的多轮对话；
- 一个只读取固定临时文件的工具调用与结果往返；
- 并行两个安全工具调用；
- 通过现有 Admin OAuth PATCH 把本地 expiry 改为过去（同时触发内存 replace），验证刷新后请求成功、DB 新 access/expiry/refresh/profileArn 完整；
- 重启 gateway，确认不重复刷新且请求成功；
- Admin 手动配额刷新，并用 bounded wait 轮询后台 300 秒探测的新快照；GUI 显示“本月 Credits”、百分比、剩余/总额、重置倒计时和趋势。

Expected: 真实 KAS 接受请求画像/历史/工具；日志无 token/client secret；无硬编码 usage=0；SmartCache 得到 Kiro 窗口。

- [ ] **Step 3: 全量回归与交付检查**

```bash
cargo fmt --check
cargo build
cargo clippy --all-targets -- -D warnings
git diff --check
git status --short
```

Expected: 全部命令退出 0；没有临时测试、验证服务器、账号 JSON、OAuth 输出或无关文件进入提交。

- [ ] **Step 4: 收尾**

若验收需要修复，按对应 Task 的红绿流程修复并单独提交行为修复。最终按仓库流程 rebase main、 squash 为一个行为提交，删除 worktree/branch。部署不是自动动作；如需上线，另走 `task prod`、产物 mtime、进程重启和真实行为验证。

```bash
dropdb cardinal_kiro_verify
```

## 12. 验收矩阵与任务索引

| 类别 | 必过场景 | Task |
| --- | --- | --- |
| Schema/Admin | Kiro provider/key；static 非空；列表/reveal 无 OAuth | 1 |
| 协议矩阵 | 仅 Chat->Kiro；无入站；cache key 保留 | 2 |
| AWS 帧 | 独立金样本、10 header type、任意切分、CRC、半帧 EOF | 3 |
| 泵回归 | SSE 不变；AWS 截断可见并记账 | 4 |
| KAS wire | 完整画像、无 stream、profileArn、retry header | 5 |
| 会话/工具 | system、多轮、配对、并行 index、continuation、GPT off | 6/7 |
| Token | 新鲜复用、并发单刷、DB 新值、轮换落库、401、invalid_grant | 8 |
| 配额 | Shell 画像、CREDIT 映射、快照/Smart/GUI、旧快照保留 | 9 |
| 导入 | 白名单、幂等、无日志泄密、无新 API | 10 |
| 真实链路 | 流式/非流式、多轮、实际工具、刷新重启、截断 | 11 |
| Usage | metering 保留诊断；未知 token 省略而非 0 | 7/11 |

## 13. 相对参考的已批准偏差

1. cardinal IR/relay 替代 Node 服务与插件；仅 Chat->Kiro。
2. 无 cache key 时以 system+首轮 user 稳定派生；历史始终完整发送。
3. 不接 MCP/subagent/GUI 导入；一次性脚本复用现有 Admin API。
4. `isEmailRequired=false`，不拉邮箱；CREDIT 不换 token，不重复累计 bonuses。
5. 不伪造 Anthropic 签名思考块；首版无 Kiro signature history 因而不加 signature-strip retry。
6. 保留 cardinal failover、错误格式、截断终结和账本。
7. OAuth 存 PostgreSQL，账号由 cardinal 独占；测试临建临删。

## 14. 安全底线

- 不把账号 JSON、access/refresh token、client secret、OAuth body 或完整配额用户信息写入提交/日志。
- 不把 Kiro 配额错误升级为聊天不可用；永久 OIDC 错误必须明确提示重新导入。
- 不用共享错误的测试 encoder 代替金字节，不把一次整包写入当作增量帧验证。
- 不在生产热路径对锁 unwrap/expect，不克隆整段 IR 历史，不用 credits 伪造 token usage。

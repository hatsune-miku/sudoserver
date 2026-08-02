# 可行性分析与架构

## 结论

原始需求在 Windows 与 Linux 上可行。跨平台的共同基础是 PowerShell 7 (`pwsh`)；认证、令牌和协议层可完全由安全 Rust 实现。真正的平台差异集中在服务生命周期、文件 ACL 和执行身份，因此二进制保留同一核心，在边缘使用 Windows SCM 与 systemd 适配。

## 组件

```text
Browser / Agent
  │ loopback HTTP JSON or MCP
  ▼
Axum transport ── admin authentication ── Argon2id / RFC 6238
  │
  ├─ runtime Ed25519 JWT issuer + in-memory revocation metadata
  │
  └─ token → strong handle → persistent pwsh child process
                              (native parser and session state)
```

管理 UI 与 server 打包为同一二进制，减少安装面和跨进程机密传递。逻辑模块仍分为 transport/UI、auth、session/shell 和平台服务适配。

## 关键取舍

### 命令执行

不自行解析、转义或重写用户命令。每个会话启动一个 `pwsh -NoProfile -NonInteractive -NoExit -Command -` 子进程，命令以 UTF-8→Base64 编码穿过 stdin framing，再由 `[ScriptBlock]::Create` 交给 PowerShell 原生 parser。随机 144-bit marker 将每个请求的结果定界；handle 自身为独立的 256-bit 随机秘密。

这比“每次调用启动一个 shell”多一些 framing 复杂度，但保留了变量、环境和当前目录，符合会话语义。比自行实现 shell grammar 可靠得多。命令本身拥有 root 权限，因此刻意伪造 framing 不构成额外权限提升。

### 动态密钥

Ed25519 signing key 只在内存中生成和持有。JWT 包含 instance issuer、audience、subject、jti、iat 和可选 exp。验证同时要求签名、当前 instance id 和内存中的签发记录匹配，因此重启后的 token 即使声明永久也无法使用。

### 凭据存储

Master Password 只保存 Argon2id PHC verifier。TOTP 验证在数学上必须持有可恢复的共享 secret；它使用 AES-256-GCM 加密，seal key 单独保存并受操作系统 ACL/权限保护。这满足静态存储不出现明文关键凭据，但无法也不试图抵御已经拥有 SYSTEM/root 的攻击者。

### 网络边界

纯 HTTP 只适合 loopback。配置验证硬性拒绝非 loopback bind，避免用户误把 Master Password、JWT 或 handle 发送到明文网络。远程版本需要不同的威胁模型（至少 TLS、服务器身份验证、推荐 mTLS），不应通过一个 `allow_remote` 开关草率实现。

## 需求覆盖

| 原始需求 | 实现 |
|---|---|
| Windows Administrator / Linux root | 启动身份检查；SCM LocalSystem / systemd root |
| 每次运行动态密钥对 | Ed25519 key 每进程生成，不落盘 |
| 用户亲自签发 token | 本地 UI + Argon2id Master / TOTP |
| 默认 24h、可永久 | issue API 和 UI presets |
| 一个 token 一个 session | 双向 token-jti/handle map，明确 reused 响应 |
| handle 是强密码 | CSPRNG 256 bit base64url |
| 完整 PowerShell 语义 | 持久化 `pwsh` 原生解析，跨平台集成测试 |
| 销毁 session/token | 立即移除映射并 kill shell；撤销级联 |
| HTTP + MCP | Axum JSON API + MCP JSON-RPC Streamable HTTP |
| Agent Skill 安全询问 | `skills/use-sudoserver` |
| 两端二进制 CI | Windows/Linux matrix + release artifacts |

## 剩余工程边界

- 当前输出为有上限的聚合响应，不支持 stdin 交互或实时流。需要长时间流式任务时应扩展 SSE/任务模型，而不是取消上限。
- Windows 服务安装路径指向当前二进制；升级时应先停止服务并原子替换已安装位置。Linux 同理。
- 审计日志有意不记录命令和 secret，避免产生第二份敏感数据。组织环境若需要审计，应设计带访问控制与脱敏策略的独立 sink。

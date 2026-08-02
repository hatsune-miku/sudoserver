# SudoServer

SudoServer 是一个由用户控制的本机提权代理：用户用 Master Password 或 Authenticator 动态码签发短期 JWT，Agent 再用 JWT 建立真实、持久化的管理员/root PowerShell 会话。服务同时提供 JSON HTTP API、MCP Streamable HTTP 端点和本地管理页面。

> 这是一个有意提供任意管理员/root 命令执行能力的安全敏感组件。请先阅读 [安全模型](#安全模型与已知边界)，不要把端口暴露到网络。

## 当前实现

- Windows 与 Linux 单一 Rust 二进制；服务启动时强制检查 Administrator/root 身份。
- 每次进程启动生成全新的 Ed25519 密钥对；此前签发的所有 JWT 会自然失效。
- Master Password 使用 Argon2id 保存为不可逆 verifier；TOTP 使用 RFC 6238 SHA-1/6 位/30 秒配置，兼容 Proton Authenticator。
- TOTP secret 以 AES-256-GCM 加密，seal key 与配置文件仅允许 SYSTEM/Administrators（Windows）或 owner（Linux）访问。
- 默认 JWT 有效期 24 小时，支持自定义有效期与“永久”（仍随服务重启失效）。
- 一个令牌最多拥有一个存活会话；重复进入会明确返回原 handle。handle 为 256 bit CSPRNG 随机值。
- 命令直接交给持久化 `pwsh` 解析和执行，支持管道、通配符、多行、Unicode、环境变量、变量/目录跨调用保持和原生命令退出码。
- 撤销令牌会同时终止其全部会话；命令超时或执行器失联会销毁会话。
- HTTP 和管理 UI 强制只绑定 loopback；敏感值只放 JSON body，不放 URL。

## 前置条件

- Windows 10/11 或使用 systemd 的 Linux
- [PowerShell 7 (`pwsh`)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- 从源码构建需要 Rust stable

## 构建与初始化

```powershell
cargo build --release
./target/release/sudoserver init --totp
```

初始化会安全地提示输入并确认至少 12 字符的 Master Password。使用 `--totp` 时会显示 `otpauth://` URI 和手动 secret，并要求输入当前动态码确认绑定；配置确认成功前不会落盘。

开发运行（非管理员，仅用于本地验证）：

```powershell
./target/release/sudoserver serve --allow-unelevated
```

生产安装必须在 Administrator/root 终端中执行：

```powershell
./target/release/sudoserver install
```

Windows 注册为 `SudoServer` 自启动服务并以 LocalSystem 运行；Linux 写入并启用 `sudoserver.service`。若初始化和安装使用不同账户，请在两条命令中都传入同一个绝对配置路径：`--config <path>`。

服务默认监听 `127.0.0.1:32119`：

- 管理 UI：`http://127.0.0.1:32119/`
- MCP：`http://127.0.0.1:32119/mcp`
- 健康检查：`http://127.0.0.1:32119/health`

将 [skills/use-sudoserver](skills/use-sudoserver/SKILL.md) 安装到 Agent 的 skills 目录。Skill 会要求 Agent 优先使用 Ask 工具索要 JWT、展示 sudo 的三条警示，并禁止索要 Master Password/TOTP。

## API 概览

所有写操作使用 `POST application/json`，避免把 token 或 handle 写入访问日志。完整示例见 [docs/API.md](docs/API.md)。

| 路径 | 请求核心字段 | 用途 |
|---|---|---|
| `/v1/sessions/enter` | `token` | 建立或复用令牌的会话 |
| `/v1/commands/run` | `handle`, `command` | 在持久化 PowerShell 中执行 |
| `/v1/sessions/destroy` | `handle` | 终止会话 |
| `/v1/tokens/revoke` | `token` | 撤销令牌并终止会话 |
| `/v1/admin/tokens/issue` | `credential`, duration | 签发令牌 |
| `/v1/admin/tokens/list` | `credential` | 列出当前运行期元数据 |
| `/v1/admin/tokens/revoke` | `credential`, `jti` | 由用户撤销指定令牌 |

## 配置

默认配置由平台配置目录决定。也可为所有命令显式传 `--config`。主要字段：

```toml
bind = "127.0.0.1:32119"
shell = "pwsh"
max_output_bytes = 8388608
max_command_seconds = 300
```

非 loopback 地址会被拒绝。若确实需要跨主机使用，应另行设计带双向认证和 TLS 的传输层；不要简单转发本端口。

## 安全模型与已知边界

- 信任边界与原始需求一致：正确提供 Master Password/TOTP 的主体视为用户本人；正确提供 JWT/handle 的主体拥有相应运行期权限。
- 管理凭据不会写入日志或明文存储，但会在验证时短暂存在于服务内存。拥有本机 root/Administrator 的攻击者本来就位于本组件保护边界之外，也能读取进程或 seal key。
- PowerShell 以 `-NoProfile -NonInteractive` 启动，继承系统服务的环境和执行身份；它不会继承某个桌面用户的交互式 profile。需要用户目录/网络凭据时必须在授权命令中显式处理。
- 命令输出先由 PowerShell 汇总再返回，不是流式接口；超过 `max_output_bytes` 会截断。超时会杀死 PowerShell 主进程，但命令主动分离出的后台进程可能继续运行。
- 本项目不声称抵抗已经取得本机高权限的恶意软件，也不替代操作系统审计、备份和最小权限策略。

更详细的可行性与设计取舍见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 验证

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

集成测试会调用本机 `pwsh` 验证管道、通配符、多行、Unicode、错误流、原生命令退出码、状态继承，以及完整 HTTP 签发/复用/执行/撤销生命周期。CI 在 Windows 和 Linux 上运行相同测试并产出 release 二进制。

## License

MIT

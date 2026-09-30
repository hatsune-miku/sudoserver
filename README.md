# SudoServer

> 让 AI 在确实需要时，方便、安全地执行管理员/root 命令：Windows 使用 PowerShell，Linux/macOS 使用 Bash。

SudoServer 是主要面向 AI Agent 的本机提权通道。当必要的系统操作被 Agent 沙箱、权限限制或提权边界拦住时，Agent 可以通过 MCP 请求一段由用户明确授权的高权限会话，直接完成安装软件、修改系统配置、管理服务等工作。

它不是让 AI 擅自“逃出沙箱”，而是把越过权限边界这件事变成一个清楚的用户决策：用户亲自签发短期令牌，Agent 只能凭该令牌建立会话；令牌和会话都可以随时撤销，服务重启后此前令牌自然失效。

> SudoServer 有意提供任意管理员/root 命令执行能力，是安全敏感组件。请先阅读 [安全模型](#安全模型与已知边界)，不要把端口暴露到网络。

## 为什么给 AI 使用

沙箱适合阻止 Agent 在未经允许时修改系统，但也会阻断用户真正想让它完成的工作。缺少标准提权路径时，Agent 往往只能反复尝试受限命令、设计脆弱的绕行方案，或者频繁打断用户。

SudoServer 提供一条简单、确定且失败关闭的路径：

- **不和沙箱对抗**：需要高权限时直接走 SudoServer，不尝试 sandbox escape 或临时拼装提权技巧。
- **用户掌握授权**：Agent 只向用户索要 SudoServer 令牌，永远不接触 Master Password 或 Authenticator 动态码。
- **原生脚本体验**：Windows 命令交给持久化 `pwsh`，Linux/macOS 命令交给持久化 `/bin/bash`，由原生 shell 解析。
- **少打扰**：一个 token 自动复用一个会话，变量、工作目录和环境可以跨命令保持，不必每执行一步都重新授权。
- **边界明确**：撤销 token 会终止它的会话；token 和 handle 校验出错只会拒绝执行，不会降级到不安全路径。

典型工作流只有四步：

```text
Agent 判断任务需要管理员/root 权限
    → 通过 Ask 请求 SudoServer 令牌
    → 用户在本地页面签发并粘贴令牌
    → Agent 进入会话、完成任务并销毁会话
```

一次授权对应一段任务。SudoServer 不引入桌面弹窗、托盘程序或异步审批状态机，以免提权路径本身变得比沙箱更难用、更难测试。

## 核心能力

- Windows、Linux 与 macOS 均提供独立 Rust 二进制；服务启动时强制检查 Administrator/root 身份。
- 令牌是 22 位纯字母数字随机串，约 131 bit 熵；服务端只在内存中保存 SHA-256 哈希和授权元数据。
- Master Password 使用 Argon2id 保存为不可逆 verifier；TOTP 使用 RFC 6238 SHA-1/6 位/30 秒配置，兼容 Proton Authenticator。
- TOTP secret 以 AES-256-GCM 加密，seal key 与配置文件仅允许 SYSTEM/Administrators（Windows）或 owner（Linux/macOS）访问。
- 默认令牌有效期 24 小时，支持自定义有效期与“永久”（仍随服务重启失效）。
- 一个令牌最多拥有一个存活会话；重复进入会明确返回原 handle。handle 为 256 bit CSPRNG 随机值。
- 命令直接交给平台原生 shell 解析和执行，支持管道、通配符、多行、Unicode、环境变量、函数/变量/目录跨调用保持和原生命令退出码。
- 会话没有独立的运行时间上限，命令默认无限时；调用方可选传 `timeout_seconds`，不设服务端最大值。令牌的授权有效期规则不变。
- 撤销令牌会同时终止其全部会话；命令超时或执行器失联会销毁会话。
- HTTP 和管理 UI 强制只绑定 loopback；敏感值只放 JSON body，不放 URL。

## 前置条件

- Windows 10/11：安装 [PowerShell 7 (`pwsh`)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- Linux：使用 `/bin/bash`，自动安装服务需要 systemd
- macOS：使用系统 `/bin/bash`（兼容 Bash 3.2）和 launchd；支持 Apple Silicon 与 Intel
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

Windows 注册为 `SudoServer` 自启动服务并以 LocalSystem 运行；Linux 写入并启用 `sudoserver.service`；macOS 写入 `/Library/LaunchDaemons/dev.sudoserver.plist`，通过 launchd 以 root 自动运行。若初始化和安装使用不同账户，请在两条命令中都传入同一个绝对配置路径：`--config <path>`。二进制应放在稳定路径中，安装后不要移动它。

macOS 安装示例（先把二进制放到 `/usr/local/bin/sudoserver`）：

```bash
sudo /usr/local/bin/sudoserver init --config /Library/SudoServer/config.toml --totp
sudo /usr/local/bin/sudoserver install --config /Library/SudoServer/config.toml
# 查看服务状态
sudo launchctl print system/dev.sudoserver
```

卸载系统服务需要 Administrator/root 权限。该操作会停止并注销服务，但保留配置文件和 `seal.key`：

```powershell
./target/release/sudoserver uninstall
```

服务默认监听 `127.0.0.1:32119`：

- 管理 UI：`http://127.0.0.1:32119/`
- MCP：`http://127.0.0.1:32119/mcp`
- 健康检查：`http://127.0.0.1:32119/health`

## 命令行自更新

```powershell
sudoserver update --check                 # 只查询 GitHub，不需要提权
sudoserver update                         # 最新稳定版
sudoserver update --prerelease            # 包含 RC，仍按语义版本选择最新版
sudoserver update --tag v0.1.0-rc.8.1      # 指定标签（示例）
# 确认需要降级时，同时指定 --tag 和 --allow-downgrade
```

实际更新需要 Administrator/root，来源固定为 `hatsune-miku/sudoserver` 的 GitHub Releases，不需要 GitHub 登录。`--check` 不下载二进制、不修改文件、不停止服务。稳定通道同时排除 prerelease 标记和带预发布后缀的标签，不会把历史上误标为正式版的 RC 当成稳定版；没有稳定版时使用 `--prerelease`。

更新前先完成下载、SHA-256 校验、平台匹配和二进制版本检查，再备份旧程序并更新。已安装的系统服务只在原本运行时停止和恢复；不会改写服务注册、配置、Master Password 或 `seal.key`。重启会中断会话并使全部运行期 token 失效。新版本服务状态与 `/health` 版本检查失败时，自动恢复旧二进制并尝试恢复原服务；回滚本身失败会保留备份并明确报错。

- Linux/macOS：在安装目录所在文件系统暂存完整文件，然后用 `rename` 原子替换路径，并同步目录。已运行进程继续使用旧文件，重启后使用新文件；这不是进程热升级，也不保证突然断电时整套服务操作具有事务性。
- Windows：把替换交给隐藏的本地助手，等待原 CLI 退出后操作。命令输出助手日志路径；只有日志中的 `SUCCESS` 才表示完成，启动助手本身不代表更新成功。更新失败详情也写在该日志中。
- 每次更新的 `.sudoserver-update-*` 恢复目录保留 `previous` 旧二进制；Windows 还保留助手和日志。确认新版本稳定后，可在没有更新进行时手动清理对应目录。不会自动覆盖已有备份。
- 二进制及上级目录必须由 root/Administrators/SYSTEM 等受信主体控制，不能位于普通用户可写的源码目录、下载目录或 Homebrew 用户目录。Windows 建议放在权限受保护的 `C:\Program Files\SudoServer`；Unix 可使用 root 拥有且不可被普通用户写入的 `/opt/sudoserver`。更新器不会自动放宽 ACL、修改所有者或移动已安装服务。
- 请从**独立管理员终端**运行，不要通过即将被停止的 SudoServer 会话自我更新。新会话带有 `SUDOSERVER_SESSION` 环境标记，更新器会据此拒绝实际更新（仍允许 `--check`）；这是防误操作提示，不是权限边界。手工 `serve` 前台实例不由更新器管理，需要自行停止/重启。自定义 systemd drop-in、非标准服务命令或处于过渡状态的服务会被拒绝，需手动更新。

正式版和 RC 统一提供 Windows ZIP、Linux/macOS tar.gz 与 `SHA256SUMS`。CI 把完整 Release tag 和 commit 写入二进制，`--version`、MCP 初始化和 `/health` 使用同一版本；本地构建默认显示 `<Cargo版本>-dev`。早期 RC 没有嵌入完整标签，版本检查会拒绝安装它们；首次使用自更新需要先手动安装包含本功能的新 Release。

安全边界：HTTPS、固定仓库与 SHA-256 用于传输/产物完整性验证，目前**没有独立发布签名**；校验值同样来自 GitHub，不能防御仓库或发布账户被攻陷。网络失败、API 限流、缺失校验值、校验不符、版本不符都会在停服前失败。

## 接入 AI Agent

将 Agent 的 MCP 客户端连接到：

```text
http://127.0.0.1:32119/mcp
```

以常见的 MCP 配置形式表示：

```json
{
  "mcpServers": {
    "sudoserver": {
      "url": "http://127.0.0.1:32119/mcp"
    }
  }
}
```

具体配置文件位置取决于所使用的 Agent。连接成功后应能看到 `sudo_enter`、`sudo_run`、`sudo_destroy_session` 和 `sudo_revoke_token` 四个工具。

MCP 工具说明会明确当前平台和 shell。Agent 应按 `sudo_enter` 返回的 `shell`、`platform` 使用对应语法；Windows PowerShell 脚本不能直接用于 Linux/macOS Bash 会话。

## API 概览

所有写操作使用 `POST application/json`，避免把 token 或 handle 写入访问日志。完整示例见 [docs/API.md](docs/API.md)。

| 路径 | 请求核心字段 | 用途 |
|---|---|---|
| `/v1/sessions/enter` | `token` | 建立或复用令牌的会话 |
| `/v1/commands/run` | `handle`, `command` | 在持久化 PowerShell/Bash 中执行 |
| `/v1/sessions/destroy` | `handle` | 终止会话 |
| `/v1/tokens/revoke` | `token` | 撤销令牌并终止会话 |
| `/v1/admin/tokens/issue` | `credential`, duration | 签发令牌 |
| `/v1/admin/tokens/list` | `credential` | 列出当前运行期元数据 |
| `/v1/admin/tokens/revoke` | `credential`, `id` | 由用户撤销指定令牌 |

## 配置

默认配置由平台配置目录决定。`init`、`serve`、`install` 可显式传 `--config`；`update` 从已安装服务的注册信息读取配置路径。主要字段：

```toml
bind = "127.0.0.1:32119"
shell = "pwsh" # Windows；Linux/macOS 默认为 "/bin/bash"
max_output_bytes = 8388608
```

`shell` 可使用本平台 shell 的完整路径，但不支持跨 shell 切换。旧配置中的 `max_command_seconds` 被忽略，新配置不再生成该字段。Linux/macOS 的旧默认 `shell = "pwsh"` 会在加载时迁移为 `/bin/bash` 并记录提示，不改写原文件；旧自定义 PowerShell 路径需手动改为 Bash 路径。

非 loopback 地址会被拒绝。若确实需要跨主机使用，应另行设计带双向认证和 TLS 的传输层；不要简单转发本端口。

## 安全模型与已知边界

- 信任边界与原始需求一致：正确提供 Master Password/TOTP 的主体视为用户本人；正确提供 token/handle 的主体拥有相应运行期权限。
- 管理凭据不会写入日志或明文存储，但会在验证时短暂存在于服务内存。拥有本机 root/Administrator 的攻击者本来就位于本组件保护边界之外，也能读取进程或 seal key。
- PowerShell 使用 `-NoProfile -NonInteractive`；Bash 使用 `--noprofile --norc`，同时移除 `BASH_ENV` 等启动注入变量。二者继承系统服务身份和环境，不加载桌面用户 profile。
- 响应在命令完成后返回，不是流式接口；超过 `max_output_bytes` 会截断并继续排空输出，保证后续命令不串包。命令默认无限时，但销毁会话、撤销令牌和服务关闭可中断正在执行的命令。Linux/macOS 会将 shell 放入独立进程组，终止时向整个进程组发信号，一并回收命令启动的子进程和后台任务；主动 `setsid` 或新建进程组脱离的进程仍可能存活。
- 会话非交互式，不支持终端输入；Bash 命令的 stdin 为 `/dev/null`。`exit`、`exec` 或导致 shell 退出的选项（例如 Bash `set -e` 后失败）会结束会话，但本次调用仍返回已产生的输出与退出码，并置 `session_ended=true`。命令中的 NUL 字节会被拒绝而非静默截断。令牌过期会阻止后续调用，不额外为已启动的命令添加计时器。
- 本项目不声称抵抗已经取得本机高权限的恶意软件，也不替代操作系统审计、备份和最小权限策略。

更详细的可行性与设计取舍见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 验证

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

集成测试调用本平台 shell，验证管道、通配符、多行、Unicode、错误流、退出码、状态继承、截断后同步、可选超时、无限时命令取消，以及 HTTP 签发/复用/执行/撤销生命周期。所需 shell 缺失会让测试失败。CI 覆盖 Windows x86_64、Linux x86_64、macOS Apple Silicon 和 Intel，macOS 使用系统 Bash 3.2。

`main` 分支 push 触发 `CI` 后，只有全部平台测试、构建并上传成品成功，`Release Candidate` 才会接续运行。它按平台分别下载该次 CI 成品（不重复构建），打包为 Windows ZIP、Linux/macOS tar.gz，生成 `SHA256SUMS`，并以 `v<项目版本>-rc.<CI序号>.<重试序号>` 创建 GitHub prerelease。PR 检查不会发布 RC；正式版 `Release` 工作流也明确排除 `-rc.*` tag。重试发布用的 CI 时需重跑全部平台；打包阶段会拒绝不同重试序号的版本混装。

## License

MIT

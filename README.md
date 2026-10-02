# localshelld

> 你的设备，由你掌控。localshelld 帮助你将执行权限临时授权给 AI Agent。

localshelld 是面向有经验的设备所有者和维护人员个人自用的开源项目。项目的出发点是：用户自然拥有对自己合法所有设备的终极掌控权，也可以决定将其中的执行权限临时交给 AI Agent。用户决定任务、执行身份、授权时长与何时收回授权，工具负责实现这份委托。

项目由使用者自行部署和维护，不面向普通终端用户分发，也不提供公用服务器或托管授权服务。代码、构建和版本流程开放，供有经验的维护人员在自己的设备上使用。

唯一的行为约定：**尊重用户的个人隐私。**

## 为什么给 AI 使用

当 Agent 的运行环境或沙箱妨碍用户完成自己的任务时，localshelld 提供现成的本机执行通道。用户态 daemon 负责普通命令，系统 daemon 负责管理员/root 命令；Agent 通过同一个 MCP 入口和 `localshelld_run.sudo` 选择执行身份。

整个过程由用户掌控：

- **临时委托**：用户签发令牌交给 Agent，决定授权时长，并可随时撤销。
- **直接执行**：Agent 使用 localshelld 完成用户交代的工作，无需反复处理沙箱权限限制。
- **原生脚本体验**：Windows 命令交给持久化 `pwsh`，Linux/macOS 命令交给持久化 `/bin/bash`，由原生 shell 解析。
- **少打扰**：一个 token 自动复用一个会话，变量、工作目录和环境可以跨命令保持，不必每执行一步都重新授权。
- **随时收回**：撤销令牌会结束关联会话；daemon 重启后，该实例签发的令牌失效。

典型工作流只有四步：

```text
Agent 判断任务需要本机执行能力
    → 通过 Ask 请求 localshelld 令牌
    → 用户在本地页面签发并粘贴令牌
    → Agent 进入会话、完成任务并销毁会话
```

一次授权对应一段任务。签发和管理在本地页面完成，执行过程中无需逐条命令重复审批。

## 核心能力

- 同一个 Rust 二进制支持两种 daemon：系统 daemon 要求 Administrator/root；`--user` daemon 拒绝以 root/管理员身份运行。
- 令牌是 22 位纯字母数字随机串，约 131 bit 熵；服务端只在内存中保存 SHA-256 哈希和授权元数据。
- Master Password 使用 Argon2id 保存为不可逆 verifier；TOTP 使用 RFC 6238 SHA-1/6 位/30 秒配置，兼容 Proton Authenticator。
- TOTP secret 以 AES-256-GCM 加密，配置和 seal key 独立保存并受 ACL 保护：Windows 允许当前账户及 SYSTEM/Administrators，Unix 仅 owner 可访问。
- 默认令牌有效期 24 小时，支持自定义有效期与“永久”（仍随服务重启失效）。
- 每个 daemon 对同一令牌复用一个 handle；双权限 handle 关联两套独立 shell。handle 为 256 bit CSPRNG 随机值。
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
./target/release/localshelld init --totp
```

初始化会提示输入并确认至少 12 字符的 Master Password。使用 `--totp` 时会显示 `otpauth://` URI 和手动 secret，并要求输入当前动态码确认绑定；配置确认成功前不会落盘。

开发运行（非管理员，仅用于本地验证）：

```powershell
./target/release/localshelld serve --allow-unelevated
```

系统 daemon 在 Administrator/root 终端中安装：

```powershell
./target/release/localshelld install
```

Windows 注册为 `localshelld` 自启动服务并以 LocalSystem 运行；Linux 写入并启用 `localshelld.service`；macOS 写入 `/Library/LaunchDaemons/dev.localshelld.plist`，通过 launchd 以 root 自动运行。若初始化和安装使用不同账户，请在两条命令中都传入同一个绝对配置路径：`--config <path>`。二进制应放在稳定路径中，安装后不要移动它。

macOS 安装示例（先把二进制放到 `/usr/local/bin/localshelld`）：

```bash
sudo /usr/local/bin/localshelld init --config /Library/localshelld/config.toml --totp
sudo /usr/local/bin/localshelld install --config /Library/localshelld/config.toml
# 查看服务状态
sudo launchctl print system/dev.localshelld
```

卸载系统服务需要 Administrator/root 权限。该操作会停止并注销服务，但保留配置文件和 `seal.key`：

```powershell
./target/release/localshelld uninstall
```

系统 daemon 默认监听 `127.0.0.1:32119`，在此签发的令牌允许高权限操作：

- 管理 UI：`http://127.0.0.1:32119/`
- 系统 MCP：`http://127.0.0.1:32119/mcp`（仅接受 `sudo=true`）
- 健康检查：`http://127.0.0.1:32119/health`

## 用户态 daemon

用户态 daemon 在普通用户终端中初始化并安装：

```powershell
localshelld init --user --totp
localshelld install --user
# 也可前台运行，便于调试
# localshelld serve --user
# 停止并移除当前用户的自启动项
# localshelld uninstall --user
```

用户态配置使用独立的 `localshelld-user` 平台配置目录，默认监听 `127.0.0.1:32120`；所有命令仍可传 `--config`。Linux 安装为 `systemctl --user` 的 `localshelld-user.service`；macOS 安装为当前 GUI 登录会话的 `dev.localshelld.user` LaunchAgent；Windows 安装为当前用户 SID 对应的登录计划任务，使用交互用户令牌和最低权限。它随用户登录启动，不自动启用 Linux linger。多用户同时运行时需为各自的用户 daemon 配置不同端口。

Agent 连接 `http://127.0.0.1:32120/mcp`：

- 在用户页面 `http://127.0.0.1:32120/` 签发的令牌，只允许 `sudo=false`。系统 daemon 未运行时也可使用。
- 在系统页面 `http://127.0.0.1:32119/` 签发的令牌，通过用户态 MCP 进入后同时允许 `sudo=false` 和 `sudo=true`。`localshelld_enter` 返回 `sudo_available`，说明当前授权是否允许高权限操作。
- `sudo=false` 继承用户 daemon 的账户和环境，`sudo=true` 由系统 daemon 的账户执行。两个 shell 的变量、函数、工作目录和环境分别保持，不在权限之间复制。参数必填，失败时不会自动提权或换身份重试。
- 销毁双权限会话会终止两个 shell。高权限令牌撤销、到期、系统 daemon 关闭或通信失败会关闭其关联的用户 shell；正在运行的命令也会取消。用户态独立令牌不受系统 daemon 重启影响。

用户 daemon 向系统 daemon 传递用户交给它的令牌与命令。Master Password 和 TOTP 用于各自本地页面的签发与管理；执行接口使用 token 和 handle。两种身份的可访问资源由操作系统账户权限决定。

## 从旧名称迁移

本项目已从 SudoServer 更名为 `localshelld`。新版本使用新的服务名和默认配置目录，不会自动接管旧服务。已有安装请先使用旧二进制执行 `sudoserver uninstall`，再用新二进制执行 `localshelld install --config <原配置文件的绝对路径>`；保留原配置文件及同目录的 `seal.key`，即可继续使用原 Master Password 和 TOTP，无需重新 `init`。如需迁移配置目录，请将这两个文件一起迁移，并保留原有访问权限。卸载/重启会结束会话，原令牌需要重新签发。

MCP 配置中的服务键名改为 `localshelld`，推荐连接用户态端口 `32120`。旧 `sudo_*` 工具已替换为 `localshelld_*`，客户端需要刷新工具列表，每次运行显式传入 `sudo: true/false`；HTTP run 接口同样要求此字段。构建和会话环境变量统一使用 `LOCALSHELLD_*` 前缀。新版本自更新仅识别 `localshelld-*` 产物，首次更名升级需手动安装；发布前需将 GitHub 仓库同步更名为 `hatsune-miku/localshelld`。

## 命令行自更新

```powershell
localshelld update --check                 # 只查询 GitHub，不需要提权
localshelld update                         # 最新稳定版
localshelld update --prerelease            # 包含 RC，仍按语义版本选择最新版
localshelld update --tag v0.1.0-rc.8.1      # 指定标签（示例）
# 确认需要降级时，同时指定 --tag 和 --allow-downgrade
```

实际更新需要 Administrator/root，来源固定为 `hatsune-miku/localshelld` 的 GitHub Releases，不需要 GitHub 登录。`--check` 不下载二进制、不修改文件、不停止服务。稳定通道同时排除 prerelease 标记和带预发布后缀的标签，不会把历史上误标为正式版的 RC 当成稳定版；没有稳定版时使用 `--prerelease`。

更新前先完成下载、SHA-256 校验、平台匹配和二进制版本检查，再备份旧程序并更新。已安装的系统服务只在原本运行时停止和恢复；不会改写服务注册、配置、Master Password 或 `seal.key`。重启会中断会话并使全部运行期 token 失效。新版本服务状态与 `/health` 版本检查失败时，自动恢复旧二进制并尝试恢复原服务；回滚本身失败会保留备份并明确报错。

更新器管理的是系统服务，不会跨用户会话控制用户 daemon。若两种 daemon 共用同一个二进制，更新前请在普通用户终端执行 `localshelld uninstall --user`，更新后再执行 `localshelld install --user`。Windows 上仍运行的用户 daemon 可能占用二进制；Unix 上未重启的进程仍运行旧版本。

- Linux/macOS：在安装目录所在文件系统暂存完整文件，然后用 `rename` 原子替换路径，并同步目录。已运行进程继续使用旧文件，重启后使用新文件；这不是进程热升级，也不保证突然断电时整套服务操作具有事务性。
- Windows：把替换交给隐藏的本地助手，等待原 CLI 退出后操作。命令输出助手日志路径；只有日志中的 `SUCCESS` 才表示完成，启动助手本身不代表更新成功。更新失败详情也写在该日志中。
- 每次更新的 `.localshelld-update-*` 恢复目录保留 `previous` 旧二进制；Windows 还保留助手和日志。确认新版本稳定后，可在没有更新进行时手动清理对应目录。不会自动覆盖已有备份。
- 二进制及上级目录必须由 root/Administrators/SYSTEM 等受信主体控制，不能位于普通用户可写的源码目录、下载目录或 Homebrew 用户目录。Windows 建议放在权限受保护的 `C:\Program Files\localshelld`；Unix 可使用 root 拥有且不可被普通用户写入的 `/opt/localshelld`。更新器不会自动放宽 ACL、修改所有者或移动已安装服务。
- 自更新在独立管理员终端中运行。`LOCALSHELLD_SESSION` 标记用于识别 daemon 创建的会话，该环境中支持 `--check`，实际更新在会话之外执行。手工 `serve` 前台实例需要自行停止/重启；自定义 systemd drop-in、非标准服务命令或处于过渡状态的服务采用手动更新。

正式版和 RC 统一提供 Windows ZIP、Linux/macOS tar.gz 与 `SHA256SUMS`。CI 把完整 Release tag 和 commit 写入二进制，`--version`、MCP 初始化和 `/health` 使用同一版本；本地构建默认显示 `<Cargo版本>-dev`。早期 RC 没有嵌入完整标签，版本检查会拒绝安装它们；首次使用自更新需要先手动安装包含本功能的新 Release。

更新使用 HTTPS、固定仓库与 SHA-256 校验，二进制和校验值均来自该仓库的 Release，目前未配置独立发布签名。网络、API 限流、校验或版本检查失败时，在停服前结束更新。

## 接入 AI Agent

将 Agent 的 MCP 客户端连接到：

```text
http://127.0.0.1:32120/mcp
```

以常见的 MCP 配置形式表示：

```json
{
  "mcpServers": {
    "localshelld": {
      "url": "http://127.0.0.1:32120/mcp"
    }
  }
}
```

具体配置文件位置取决于所使用的 Agent。连接成功后应能看到 `localshelld_enter`、`localshelld_run`、`localshelld_destroy_session` 和 `localshelld_revoke_token` 四个工具。

MCP 工具说明会明确当前平台和 shell。Agent 应按 `localshelld_enter` 返回的 `shell`、`platform` 使用对应语法；Windows PowerShell 脚本不能直接用于 Linux/macOS Bash 会话。

例如普通用户执行：`localshelld_run({"handle":"…","command":"whoami","sudo":false})`。使用管理员/root 身份执行时传 `sudo:true`，对应会话的 `sudo_available` 为 `true`。

## API 概览

所有写操作使用 `POST application/json`，避免把 token 或 handle 写入访问日志。完整示例见 [docs/API.md](docs/API.md)。

| 路径 | 请求核心字段 | 用途 |
|---|---|---|
| `/v1/sessions/enter` | `token` | 建立或复用令牌的会话 |
| `/v1/commands/run` | `handle`, `command`, `sudo` | 选择用户或高权限 shell 执行 |
| `/v1/sessions/destroy` | `handle` | 终止会话 |
| `/v1/tokens/revoke` | `token` | 撤销令牌并终止会话 |
| `/v1/admin/tokens/issue` | `credential`, duration | 签发令牌 |
| `/v1/admin/tokens/list` | `credential` | 列出当前运行期元数据 |
| `/v1/admin/tokens/revoke` | `credential`, `id` | 由用户撤销指定令牌 |

## 配置

默认配置由平台配置目录决定。`init`、`serve`、`install` 可显式传 `--config`；`update` 从已安装服务的注册信息读取配置路径。主要字段：

```toml
bind = "127.0.0.1:32120" # 用户 daemon；系统 daemon 默认 32119
privileged_daemon = "127.0.0.1:32119" # 仅用户 daemon 使用
shell = "pwsh" # Windows；Linux/macOS 默认为 "/bin/bash"
max_output_bytes = 8388608
```

`shell` 可使用本平台 shell 的完整路径，但不支持跨 shell 切换。旧配置中的 `max_command_seconds` 被忽略，新配置不再生成该字段。Linux/macOS 的旧默认 `shell = "pwsh"` 会在加载时迁移为 `/bin/bash` 并记录提示，不改写原文件；旧自定义 PowerShell 路径需手动改为 Bash 路径。

HTTP 与 MCP 均为本机 loopback 接口，配置不支持远程监听地址。

## 授权与运行方式

- 正确提供 Master Password/TOTP 的主体视为用户本人；token/handle 表达用户授予的运行期权限。
- 管理凭据仅在验证时使用；日志不记录凭据和命令内容。
- PowerShell 使用 `-NoProfile -NonInteractive`；Bash 使用 `--noprofile --norc`，同时移除 `BASH_ENV` 等启动注入变量。shell 继承所属 daemon 的身份和环境，不加载 shell profile。
- 响应在命令完成后返回，不是流式接口；超过 `max_output_bytes` 会截断并继续排空输出，保证后续命令不串包。命令默认无限时，但销毁会话、撤销令牌和服务关闭可中断正在执行的命令。Linux/macOS 会将 shell 放入独立进程组，终止时向整个进程组发信号，一并回收命令启动的子进程和后台任务；主动 `setsid` 或新建进程组脱离的进程仍可能存活。
- 会话非交互式，不支持终端输入；Bash 命令的 stdin 为 `/dev/null`。`exit`、`exec` 或导致 shell 退出的选项（例如 Bash `set -e` 后失败）会结束会话，但本次调用仍返回已产生的输出与退出码，并置 `session_ended=true`。命令中的 NUL 字节会被拒绝而非静默截断。单 daemon 令牌过期阻止后续调用；跨 daemon 会话还会在高权限授权到期时取消两端正在执行的命令。

更详细的可行性与设计取舍见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 验证

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

集成测试调用本平台 shell，验证管道、通配符、多行、Unicode、错误流、退出码、状态继承、截断后同步、可选超时、无限时命令取消，以及 HTTP 签发/复用/执行/撤销生命周期。所需 shell 缺失会让测试失败。CI 覆盖 Windows x86_64、Linux x86_64、macOS Apple Silicon 和 Intel，macOS 使用系统 Bash 3.2。

双 daemon 测试使用真实 loopback HTTP 验证路由、独立状态、令牌权限、到期、撤销和关闭级联。Linux/macOS CI 另用 `scripts/test-dual-daemon.py` 启动不同 UID 的真实进程，检查两种 `sudo` 模式的 `id -u` 输出；它不安装系统服务。

`main` 分支 push 触发 `CI` 后，只有全部平台测试、构建并上传成品成功，`Release Candidate` 才会接续运行。它按平台分别下载该次 CI 成品（不重复构建），打包为 Windows ZIP、Linux/macOS tar.gz，生成 `SHA256SUMS`，并以 `v<项目版本>-rc.<CI序号>.<重试序号>` 创建 GitHub prerelease。PR 检查不会发布 RC；正式版 `Release` 工作流也明确排除 `-rc.*` tag。重试发布用的 CI 时需重跑全部平台；打包阶段会拒绝不同重试序号的版本混装。

## License

MIT

# 可行性分析与架构

## 结论

Windows 使用 PowerShell 7 (`pwsh`)，Linux/macOS 使用 `/bin/bash`（兼容 macOS Bash 3.2）。认证、令牌和协议层使用安全 Rust，共享持久会话抽象；平台差异集中在 shell 后端、服务生命周期、文件 ACL 和执行身份。服务适配分别为 Windows SCM、Linux systemd、macOS launchd。

## 组件

```text
Browser / Agent
  │ loopback HTTP JSON or MCP
  ▼
Axum transport ── admin authentication ── Argon2id / RFC 6238
  │
  ├─ in-memory opaque token registry + authorization metadata
  │
  └─ token → strong handle → persistent PowerShell / Bash process
                              (native parser and session state)
```

管理 UI 与 server 打包为同一二进制，减少安装面和跨进程机密传递。逻辑模块仍分为 transport/UI、auth、session/shell 和平台服务适配。

## 关键取舍

### 命令执行

不自行解析或重写用户命令。Windows 启动 `pwsh -NoProfile -NonInteractive -EncodedCommand` bootstrap，命令通过 UTF-8→Base64 编码传输，由 `[ScriptBlock]::Create` 原生解析并在当前作用域执行。Unix 启动 `/bin/bash --noprofile --norc -c` bootstrap，移除 `BASH_ENV` 等启动变量；命令按字节编码传输（可打印 ASCII 直传、其余转义为八进制），由 Bash 内建 `printf -v` 无外部依赖地还原，再在父 shell 中 `eval`，不使用丢失状态的命令替换或子 shell。因变量无法承载 NUL，含 NUL 的命令在入口即被拒绝，不会静默截断。

bootstrap 用 `builtin read`/`printf`/`eval` 读取协议，命令即便重定义同名函数也不影响读循环；命令的 stdout/stderr 经一个私有的原始 stdout 副本（fd 4）传出，完成帧也走 fd 4，因此命令内的 `exec >…` 只改写自身 fd 1、不会静音后续命令，也无法伪造或破坏帧。

随机 144-bit marker 和控制字符将每个请求的完成帧定界；原始输出通过管道持续读取，仅保存配置容量内的部分，并在截断后继续排空。PowerShell 对象使用 `Out-String -Stream` 转成文本。handle 自身为独立的 256-bit 随机秘密。

这比“每次调用启动一个 shell”多一些 framing 复杂度，但保留了变量、环境和当前目录，符合会话语义。比自行实现 shell grammar 可靠得多。命令本身拥有 root 权限，因此刻意伪造 framing 不构成额外权限提升。

每个会话由独立 worker 持有进程和输入输出，队列串行执行命令；取消信号不依赖执行锁，因此无限时命令也可以被销毁、撤销或服务关闭中断。读循环同时监听 shell 进程退出，因此 shell 因 `exit`/`exec`/`set -e` 失败而退出、或后台任务仍占着输出管道时，本次调用不会挂起，而是返回已产生的输出与 shell 的实际退出码并标记 `session_ended`。Unix 下 shell 以 `process_group(0)` 独占进程组，中断时对整个进程组发 `SIGKILL`（通过安全的 `rustix`，不引入 `unsafe`），回收命令启动的子进程；进程组 id 在 spawn 时记录，即使先回收 leader 取退出码也能可靠发信号。HTTP 调用方断开后，worker 仍消费完整响应，避免后续命令串包。服务关闭时拒绝新会话并取消全部已有会话，再等待 HTTP 请求退出。

默认不设命令或会话运行时长上限，删除 `max_command_seconds` 配置；调用方仍可显式指定正整数 `timeout_seconds`。令牌有效期保持独立，只对授权及后续调用做检查。旧 Unix 默认 `shell = "pwsh"` 在加载配置时迁移为 `/bin/bash`，旧自定义路径需手动修改。

### 短期令牌

令牌由 CSPRNG 生成，使用 22 位纯 ASCII 字母数字 Base62 编码，约有 131 bit 熵。原始令牌只在签发时返回一次，服务端仅在内存中保存 SHA-256 哈希、管理 ID、签发时间、到期时间和撤销状态。服务重启后内存记录消失，因此即使声明永久的令牌也会自然失效。

### 凭据存储

Master Password 只保存 Argon2id PHC verifier。TOTP 验证在数学上必须持有可恢复的共享 secret；它使用 AES-256-GCM 加密，seal key 单独保存并受操作系统 ACL/权限保护。这满足静态存储不出现明文关键凭据，但无法也不试图抵御已经拥有 SYSTEM/root 的攻击者。

### 网络边界

纯 HTTP 只适合 loopback。配置验证硬性拒绝非 loopback bind，避免用户误把 Master Password、token 或 handle 发送到明文网络。远程版本需要不同的威胁模型（至少 TLS、服务器身份验证、推荐 mTLS），不应通过一个 `allow_remote` 开关草率实现。

### 显式自更新

`update` 是独立 CLI 工作流，不通过 HTTP/MCP 暴露，不在服务启动时后台自动下载。版本发现固定使用官方 GitHub 仓库；稳定通道同时检查语义版本后缀和 prerelease 标记。各平台附件统一打包，构建时嵌入 Release 版本和 Git commit；打包前检查每个平台的版本清单，避免 CI 部分重跑造成不同 RC 版本混装。

先下载、校验 SHA-256、只提取预期二进制并检查其 `--version`，再进入停服/替换阶段。安装目录和暂存目录必须受操作系统权限保护，文件锁排除并发更新。Unix 通过同一文件系统内的 rename 原子替换文件名；Windows 由旧程序的隐藏副本在原 CLI 退出后替换文件。两者都保留旧二进制，并对原本运行的服务做状态和版本健康检查，失败时尝试回滚。配置及 seal key 不参与替换；原本停止的服务不被启动。

这不是零停机热更新，重启会撤销全部内存令牌和会话；文件名的原子替换也不是服务生命周期的断电事务。Windows 助手异步完成，日志中的 SUCCESS 才确认成功。SHA-256 校验数据仍来自 GitHub，目前不提供独立签名验证。

## 需求覆盖

| 原始需求 | 实现 |
|---|---|
| Windows Administrator / Linux/macOS root | 启动身份检查；SCM LocalSystem / systemd root / launchd root |
| 每次运行令牌自然失效 | opaque token 元数据只保存在进程内存中 |
| 用户亲自签发 token | 本地 UI + Argon2id Master / TOTP |
| 默认 24h、可永久 | issue API 和 UI presets |
| 一个 token 一个 session | 双向 token-id/handle map，明确 reused 响应 |
| handle 是强密码 | CSPRNG 256 bit base64url |
| 平台原生 shell 语义 | 持久化 `pwsh` 或 Bash 原生解析，平台集成测试 |
| 销毁 session/token | 立即移除映射并 kill shell；撤销级联 |
| HTTP + MCP | Axum JSON API + MCP JSON-RPC Streamable HTTP |
| MCP shell 识别 | 平台相关说明与 enter 的 shell/platform 字段 |
| 多平台二进制 CI | Windows/Linux/macOS ARM64 与 x86_64 matrix + release artifacts |

## 剩余工程边界

- 当前输出为有大小上限的聚合响应，不支持 stdin 交互或实时流；长时间任务可运行至完成，但 HTTP/MCP 客户端可能有自己的超时。
- Windows、Linux、macOS 服务安装路径均指向当前二进制；升级时应先停止服务并替换已安装位置。macOS 使用 `/Library/LaunchDaemons/dev.sudoserver.plist`，`bootstrap system` 安装，`bootout` 卸载；配置和 seal key 保留。
- 取消会话向 shell 进程组发 `SIGKILL`，回收命令启动的普通子进程和后台任务，但主动 `setsid`/新建进程组脱离者或已 daemon 化的进程仍可能存活；这不是进程容器或作业调度器。命令若刻意改写协议内部使用的 `__ss_`-前缀变量，只会破坏其自身会话（该会话以 root 运行，不构成额外提权）。
- 审计日志有意不记录命令和 secret，避免产生第二份敏感数据。组织环境若需要审计，应设计带访问控制与脱敏策略的独立 sink。

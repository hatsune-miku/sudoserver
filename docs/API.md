# HTTP 与 MCP API

推荐 base URL：用户 daemon 的 `http://127.0.0.1:32120`。系统 daemon 默认在 `http://127.0.0.1:32119`。授权值通过 JSON body 传递，以下示例使用占位符。

## 普通授权接口

`GET /health` 无需凭据，返回 `status`、`service`、`daemon`（`user` 或 `privileged`）、`version` 和 `commit`。版本为构建时嵌入的 Release 版本（不带 `v` 前缀），本地构建为 `<Cargo版本>-dev`。命令行更新器使用此接口确认服务运行的是预期版本。HTTP/MCP 不提供更新或下载执行接口。

进入会话：

```http
POST /v1/sessions/enter
Content-Type: application/json

{"token":"<LOCALSHELLD_TOKEN>"}
```

返回 `{ "handle": "...", "reused": false, "shell": "powershell", "platform": "windows", "daemon": "user", "sudo_available": true, "expires_at": 1800000000, "message": "..." }`。Linux/macOS 返回 `shell: "bash"`，`platform` 分别为 `"linux"` / `"macos"`。同一 token 存在会话时，`reused` 为 `true` 且 handle 不变。永久令牌的 `expires_at` 为 `null`。

用户 daemon 接受其自身签发的令牌（`sudo_available=false`），也接受系统 daemon 签发的令牌（验证后 `sudo_available=true`）。后一种 handle 关联用户 shell 和高权限 shell。两端的变量、目录、函数和环境完全独立；单一 shell 内串行执行，不同身份的命令可以并行。令牌、Master Password 和 TOTP 不在不同 daemon 的配置文件间共享。

执行命令：

```http
POST /v1/commands/run
Content-Type: application/json

{"handle":"<HANDLE>","command":"Get-Process | Sort-Object CPU -Descending | Select-Object -First 5","sudo":false,"timeout_seconds":30}
```

返回：

```json
{"output":"...","exit_code":0,"success":true,"truncated":false,"session_ended":false}
```

示例命令使用 Windows PowerShell 语法。Linux/macOS 应使用 Bash，例如 `ps -eo pid,comm | head -n 6`。命令中不得包含 NUL 字节，否则返回 400 且会话保持可用。

`sudo` 是必填 boolean，不接受省略、null、字符串或数字。`false` 仅在用户 daemon 本地运行，`true` 通过高权限 daemon 运行。用户态令牌请求 `sudo=true` 返回 403；直接向系统 daemon 请求 `sudo=false` 也返回 403。不会回退到其他身份，也不会重试可能已经执行的命令。HTTP 类型错误返回 422；MCP 参数错误返回 JSON-RPC error。

`timeout_seconds` 省略或为 `null` 时，命令没有执行时间上限；显式传入时必须是正整数，不受原先 300 秒的限制。超时会销毁整个 handle。单 daemon 会话的令牌过期禁止后续调用；跨 daemon 会话还会监听高权限授权到期并终止两端执行。

PowerShell 的 success/error/warning/verbose/debug/information 流通过 `*>&1` 合并为文本。`exit_code` 优先采用原生进程的 `$LASTEXITCODE`；非终止 PowerShell 错误返回 1。Bash 合并 stdout/stderr，返回最后一条命令的退出码（管道遵从当前 `pipefail` 设置）。返回的文本最多保留 `max_output_bytes` 字节，非 UTF-8 字节以替换字符解码。

同一会话的命令串行执行，变量、函数、环境和目录持续保留；调用方断开连接不会遗弃未读响应或自动取消执行。销毁会话、撤销令牌及服务关闭均可取消正在执行及排队中的命令，并向 shell 所在进程组发送信号，一并终止命令启动的子进程和后台任务（主动 `setsid`/新建进程组脱离者除外）。命令不支持交互 stdin；Bash stdin 为 `/dev/null`。

`exit`、`exec` 或 `set -e` 下的失败等使 shell 退出的操作会结束会话。此时本次调用仍返回已产生的输出和 shell 的实际退出码，并将 `session_ended` 置为 `true`；该 handle 之后的调用将失败。正常命令的 `session_ended` 为 `false`。

销毁会话：`POST /v1/sessions/destroy`，body 为 `{ "handle": "<HANDLE>" }`。

撤销令牌：`POST /v1/tokens/revoke`，body 为 `{ "token": "<LOCALSHELLD_TOKEN>" }`。服务仍持有记录的过期 token 可以用于撤销自身。

系统 daemon 还提供两个供用户 daemon 使用的带 handle 认证接口：`POST /v1/sessions/validate` 立即验证；`POST /v1/sessions/watch` 最多等待 15 秒或提前响应会话结束，两者 body 均为 `{"handle":"..."}`。用户 daemon 在普通命令前验证上游授权，并持续长轮询；撤销、到期、上游关闭或通信失败都会取消关联用户 shell。客户端不需要直接调用这些接口。控制请求限时，命令请求沿用显式的 `timeout_seconds`；丢失响应后不会自动重试。

## 管理接口

credential 格式为：

```json
{"type":"password","value":"..."}
```

或：

```json
{"type":"totp","value":"123456"}
```

- `POST /v1/admin/tokens/issue`：`{"credential":...,"ttl_seconds":86400}`。省略有效期默认为 24 小时。永久令牌使用 `{"credential":...,"permanent":true}`。
- `POST /v1/admin/tokens/list`：`{"credential":...}`。只返回 id、签发/过期时间和撤销状态，不返回令牌。
- `POST /v1/admin/tokens/revoke`：`{"credential":...,"id":"..."}`。

Master/TOTP 失败在每个进程实例内限制为 5 次/分钟；成功验证会清除失败计数。

管理接口只管理当前 daemon 的令牌，不转发 Master/TOTP。用户态 UI 签发的令牌永远不允许 `sudo=true`。跨 daemon 令牌可经用户 daemon 的 `/v1/tokens/revoke` 转交签发端撤销。

## MCP

`POST /mcp` 实现 JSON-RPC 2.0 和 MCP Streamable HTTP 的 JSON 响应，协议版本 `2025-06-18`。支持：

- `initialize`
- `notifications/initialized`（notification 返回 204）
- `ping`
- `tools/list`
- `tools/call`

工具为 `localshelld_enter`、`localshelld_run`、`localshelld_destroy_session`、`localshelld_revoke_token`。工具说明和 `initialize.instructions` 根据当前平台展示 PowerShell 或 Bash。字段与普通授权接口对应；`localshelld_enter` 的 `confirm_text: "OK"` 仅确认“尊重用户的个人隐私”。服务无 MCP transport session 状态；权限会话由强随机 handle 标识。

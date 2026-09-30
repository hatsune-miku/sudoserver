# HTTP 与 MCP API

默认 base URL：`http://127.0.0.1:32119`。以下示例中的值应通过 JSON 客户端内存传递，不要放进 shell history 或日志。

## 普通授权接口

进入会话：

```http
POST /v1/sessions/enter
Content-Type: application/json

{"token":"<SUDOSERVER_TOKEN>"}
```

返回 `{ "handle": "...", "reused": false, "shell": "powershell", "platform": "windows", "message": "..." }`。Linux/macOS 返回 `shell: "bash"`，`platform` 分别为 `"linux"` / `"macos"`。同一 token 存在会话时，`reused` 为 `true` 且 handle 不变。

执行命令：

```http
POST /v1/commands/run
Content-Type: application/json

{"handle":"<HANDLE>","command":"Get-Process | Sort-Object CPU -Descending | Select-Object -First 5","timeout_seconds":30}
```

返回：

```json
{"output":"...","exit_code":0,"success":true,"truncated":false}
```

示例命令使用 Windows PowerShell 语法。Linux/macOS 应使用 Bash，例如 `ps -eo pid,comm | head -n 6`。

`timeout_seconds` 省略或为 `null` 时，命令没有执行时间上限；显式传入时必须是正整数，不受原先 300 秒的限制。超时会销毁会话。令牌有效期是独立的授权规则：过期后禁止后续调用，不为执行中的命令增加截止时间。

PowerShell 的 success/error/warning/verbose/debug/information 流通过 `*>&1` 合并为文本。`exit_code` 优先采用原生进程的 `$LASTEXITCODE`；非终止 PowerShell 错误返回 1。Bash 合并 stdout/stderr，返回最后一条命令的退出码（管道遵从当前 `pipefail` 设置）。返回的文本最多保留 `max_output_bytes` 字节，非 UTF-8 字节以替换字符解码。

同一会话的命令串行执行，变量、函数、环境和目录持续保留；调用方断开连接不会遗弃未读响应或自动取消执行。销毁会话、撤销令牌及服务关闭均可取消正在执行及排队中的命令。命令不支持交互 stdin；Bash stdin 为 `/dev/null`。`exit`、`exec` 等导致 shell 退出的操作会使会话失效。

销毁会话：`POST /v1/sessions/destroy`，body 为 `{ "handle": "<HANDLE>" }`。

撤销令牌：`POST /v1/tokens/revoke`，body 为 `{ "token": "<SUDOSERVER_TOKEN>" }`。服务仍持有记录的过期 token 可以用于撤销自身。

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

## MCP

`POST /mcp` 实现 JSON-RPC 2.0 和 MCP Streamable HTTP 的 JSON 响应，协议版本 `2025-06-18`。支持：

- `initialize`
- `notifications/initialized`（notification 返回 204）
- `ping`
- `tools/list`
- `tools/call`

工具为 `sudo_enter`、`sudo_run`、`sudo_destroy_session`、`sudo_revoke_token`。工具说明和 `initialize.instructions` 根据当前平台展示 PowerShell 或 Bash。字段与普通授权接口对应，但 MCP 的 `sudo_enter` 还要求阅读工具说明后传入 `confirm_text: "OK"`。服务无 MCP transport session 状态；权限会话由强随机 handle 标识。

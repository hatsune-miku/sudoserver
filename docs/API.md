# HTTP 与 MCP API

默认 base URL：`http://127.0.0.1:32119`。以下示例中的值应通过 JSON 客户端内存传递，不要放进 shell history 或日志。

## 普通授权接口

进入会话：

```http
POST /v1/sessions/enter
Content-Type: application/json

{"token":"<JWT>"}
```

返回 `{ "handle": "...", "reused": false, "message": "..." }`。同一 token 存在会话时，`reused` 为 `true` 且 handle 不变。

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

PowerShell 的 success/error/warning/verbose/debug/information 流按 PowerShell 的 `*>&1` 顺序合并为文本。`exit_code` 优先采用原生进程的 `$LASTEXITCODE`；非终止 PowerShell 错误返回 1。

销毁会话：`POST /v1/sessions/destroy`，body 为 `{ "handle": "<HANDLE>" }`。

撤销令牌：`POST /v1/tokens/revoke`，body 为 `{ "token": "<JWT>" }`。签名正确的过期 token 仍可用于撤销自身。

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
- `POST /v1/admin/tokens/list`：`{"credential":...}`。只返回 jti、签发/过期时间和撤销状态，不返回令牌。
- `POST /v1/admin/tokens/revoke`：`{"credential":...,"jti":"..."}`。

Master/TOTP 失败在每个进程实例内限制为 5 次/分钟；成功验证会清除失败计数。

## MCP

`POST /mcp` 实现 JSON-RPC 2.0 和 MCP Streamable HTTP 的 JSON 响应，协议版本 `2025-06-18`。支持：

- `initialize`
- `notifications/initialized`（notification 返回 204）
- `ping`
- `tools/list`
- `tools/call`

工具为 `sudo_enter`、`sudo_run`、`sudo_destroy_session`、`sudo_revoke_token`。工具的 input schema 与普通授权接口字段一致。服务无 MCP transport session 状态；权限会话由强随机 handle 标识。

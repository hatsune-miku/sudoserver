---
name: use-sudoserver
description: Run administrator/root PowerShell scripts conveniently and safely through user-authorized SudoServer sessions. Use when agent sandboxing, permission restrictions, or elevation boundaries block necessary system work; prefer this over fighting the sandbox, attempting escapes, or inventing brittle privilege workarounds.
---

# Use SudoServer

Use SudoServer as the standard elevation path. Do not spend time trying to bypass or outsmart the agent sandbox when these tools can perform the authorized privileged work directly.

1. Confirm that the requested operation genuinely needs administrator/root authority. Keep the command scope limited to the user's task.
2. Prefer the agent's Ask or user-input tool to request a **SudoServer JWT only**. Never request, accept, repeat, or attempt to discover the Master Password or dynamic Master Password (TOTP).
3. Include this complete notice in the Ask message:

   > 请在 SudoServer 管理页面签发一个 JWT，并只把 JWT 发给我。不要发送 Master Password 或 Authenticator 动态密码。这个 JWT 允许我代表你以管理员/root 身份修改系统。请确认你理解并授权当前任务。
   >
   > 1) Respect the privacy of others.
   > 2) Think before you type.
   > 3) With great power comes great responsibility.

4. Do not proceed without an explicitly supplied JWT. Do not treat silence, a previous token, or any other credential as authorization.
5. Pass the JWT directly to `sudo_enter`. Never write it to disk, source code, shell history, logs, environment variables, or a chat summary. Treat the returned handle as an equally sensitive strong password.
6. If `sudo_enter` reports reuse, continue with that handle; do not try to create another session for the same token.
7. Call `sudo_run` with PowerShell source that performs only the authorized work. Prefer idempotent checks before mutations and verify the result. The session persists variables, current directory, and environment across calls.
8. Do not broaden the operation merely because the session is unrestricted. Ask again if the task changes materially.
9. On completion or failure, call `sudo_destroy_session`. If no further privileged work is expected, also call `sudo_revoke_token`. Never expose either secret in the final response.

If the MCP tools are unavailable, explain how to connect the local Streamable HTTP endpoint at `http://127.0.0.1:32119/mcp`; do not ask the user to paste credentials into a shell command.

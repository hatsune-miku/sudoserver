# Project localshelld

## 功能简介

将本机的 “以管理员权限 / root 权限运行任意 powershell 会话” 的能力，同时通过 HTTP API 和 MCP 协议服务出去，会话的开启通过短随机令牌鉴权，用户本人可通过 Master Password 来签发令牌，令牌能且只能由用户亲自签发。令牌及其有效期、撤销状态等授权元数据只在 localshelld 进程内存中维护。需要额外支持用户通过 Authenticator App 来使用动态 Master Password，至少需要兼容 Proton Authenticator。

## Why localshelld

- 用户自然拥有对自己合法所有设备的终极掌控权。localshelld 帮助用户将执行权限临时授权给 AI Agent，授权范围、时长和撤销由用户决定。
- 项目开源，供有经验的设备所有者和维护人员个人自用、自行部署和维护，不面向普通终端用户分发或作为公用服务器服务。
- 唯一的行为约定：尊重用户的个人隐私。

## 技术约束

- 需兼容 Windows 和 Linux
- 需生成 GitHub Actions 用于自动化构建两端的二进制
- 需生成配套 Agent Skill，其中至少要求：
  - 让 AI 在使用 localshelld 时，优先通过大概率集成于 Agent 的 "Ask" tool 来向用户索要 localshelld token。
  - 用户在本地页面使用 Master Password 或动态码签发令牌，Agent 通过令牌接收用户委托。
  - 工具说明仅保留“尊重用户的个人隐私”这一行为提醒。
- 建议分为 2 个模块：
  - server 部分，注册为高权限系统服务，随系统启动而自动启动
  - ui 部分，给用户签发和管理已签发的令牌用
- 当然，能够证明用户身份的关键凭据绝对不要明文存储
- localshelld 提供的服务（不论是 HTTP API 还是 MCP）至少包含以下接口：
  - 进入特权会话（参数：用户给的令牌，返回：会话handle）
    - 特性（写在MCP描述里）：当对应令牌存在未销毁的会话时，不创建新的 而是返回该现有会话的 handle，并在应答中告知复用的事；否则，创建一个新的会话并返回 handle。会话handle同时应当承担密码的职责：handle字符串本身必须是一个合格的强密码。
  - 运行特权 powershell 命令（参数：会话handle、命令字符串）
    - **重要**：这个接口需要着重大量测试，必须做到足够好用、足够全面，例如不能落下对管道、通配符、多行脚本、环境变量等的支持。尽量不要自己实现这些，最理想的形态是我们完全不需要自己处理外部输入，完全交给某个可靠的成熟模块来做执行。
    - 这部分尽量参考成熟实现，例如 OpenCode 的源码（https://github.com/anomalyco/opencode.git）就是一个极佳的范例。
    - 需额外考虑命令的执行身份、环境变量如何继承的问题。
  - 销毁特权会话（参数：会话handle）
  - 销毁令牌（参数：令牌）
  - 用户签发的令牌默认有效期为 24 小时，用户可修改有效期，最长可选永久。不过需要提醒用户：由于令牌记录只存在于进程内存，通常当用户重启系统后，此前签发的任何令牌，不论有效期，都会自然失效。
  - Windows 下，使用管理员（Administrators）身份；Linux 下，使用 root 权限。

## 用户态 daemon 与权限选择（补充需求）

- 保留高权限系统 daemon，并新增以当前非高权限用户身份运行的 daemon；普通命令由用户 daemon 执行。
- MCP 工具使用 `localshelld_enter`、`localshelld_run`、`localshelld_destroy_session` 和 `localshelld_revoke_token`。
- `localshelld_run` 必须显式传入 boolean `sudo`：false 选择当前用户身份，true 选择高权限系统 daemon。两种执行身份的 shell 状态隔离，禁止自动提权或失败后换身份执行。
- 用户态独立令牌仅允许普通执行；高权限执行仍需用户亲自签发的系统令牌。

## 用户身份与授权

- 将任何能正确提供 Master Password 或动态 Master Password 的个体视为用户本人。

## 技术栈

- 核心层需基于 Rust
- 若需要用 JS 则优先考虑 Bun
- 其它无限制

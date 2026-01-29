# OAuth2 Proxy 身份验证流程解析

本文档详细介绍了 OAuth2 Proxy 从启动服务到处理请求、进行身份验证以及处理回调的完整流程。

## 1. 服务启动阶段

服务的启动主要涉及 `main.go` 和 `oauthproxy.go`。

1.  **入口点 (`main.go`: `main`)**:
    *   加载配置 (`loadConfiguration`)。
    *   验证配置 (`validation.Validate`)。
    *   初始化 `OAuthProxy` 实例 (`NewOAuthProxy`)。
    *   调用 `oauthproxy.Start()` 启动服务器。

2.  **初始化 (`oauthproxy.go`: `NewOAuthProxy`)**:
    *   初始化会话存储 (`sessions.NewSessionStore`)。
    *   初始化身份提供者 (`providers.NewProvider`)。
    *   初始化页面渲染器 (`pagewriter.NewWriter`)。
    *   初始化上游代理 (`upstream.NewProxy`)。
    *   构建中间件链 (`buildPreAuthChain`, `buildSessionChain`, `buildHeadersChain`)。
    *   构建路由处理器 (`buildServeMux`)。

3.  **运行服务器 (`oauthproxy.go`: `Start`)**:
    *   调用 `p.server.Start(ctx)`，在配置的地址上监听 HTTP/HTTPS 请求。

---

## 2. 接收请求与身份验证校验

当一个请求到达时，它会经过一系列中间件，最后到达核心处理器。

1.  **中间件处理**:
    *   `preAuthChain`: 处理日志、健康检查、指标等。
    *   `sessionChain`: 尝试从请求中加载会话。
        *   `StoredSessionLoader`: 从 Cookie 中加载并刷新会话。
        *   `JwtSessionLoader` (可选): 从 Bearer 令牌中加载。

2.  **核心路由选择 (`oauthproxy.go`: `buildServeMux`)**:
    *   如果是内部路径（如 `/oauth2/callback`），由特定函数处理。
    *   对于普通请求，由 `p.Proxy` 处理。

3.  **身份验证校验 (`oauthproxy.go`: `Proxy` -> `getAuthenticatedSession`)**:
    *   `getAuthenticatedSession` 检查 `middlewareapi.GetRequestScope(req).Session` 是否存在且有效。
    *   调用 `p.provider.Authorize` 进行提供者特定的授权检查。
    *   **已认证**:
        *   调用 `p.addHeadersForProxying` 添加认证标头（如 `GAP-Auth`）。
        *   通过 `p.upstreamProxy` 将请求转发给上游服务。
    *   **未认证**:
        *   返回 `ErrNeedsLogin`。
        *   如果配置了 `SkipProviderButton`，直接调用 `doOAuthStart` 启动 OAuth 流程。
        *   否则，调用 `SignInPage` 返回登录页面，引导用户点击登录。

---

## 3. OAuth2 流程启动 (未认证时)

1.  **启动流程 (`oauthproxy.go`: `OAuthStart` / `doOAuthStart`)**:
    *   生成 CSRF 令牌。
    *   调用 `p.provider.GetLoginURL` 生成指向身份提供者（如 Google, GitHub）的登录地址。
    *   设置 CSRF Cookie。
    *   重定向用户到认证地址。

---

## 4. 接收回调与获取令牌

用户在提供者端完成认证后，会被重定向回 `/oauth2/callback`。

1.  **处理回调 (`oauthproxy.go`: `OAuthCallback`)**:
    *   验证 CSRF 令牌和 state 参数。
    *   调用 `p.redeemCode` 获取令牌。

2.  **兑换令牌 (`oauthproxy.go`: `redeemCode` -> `provider.Redeem`)**:
    *   从回调请求中提取 `code`。
    *   调用上游提供者的 `Redeem` 方法，发送 `code` 交换 `access_token` 和 `id_token`。

3.  **获取用户信息 (`oauthproxy.go`: `enrichSessionState`)**:
    *   调用 `p.provider.EnrichSession`，利用获取到的令牌请求提供者的 API（如 `/userinfo`）以获取电子邮件、分组等详细信息。

4.  **保存会话 (`oauthproxy.go`: `SaveSession`)**:
    *   验证用户信息。
    *   将 `SessionState` 序列化并存储（通常是加密后存入 Cookie）。

5.  **完成认证并重定向**:
    *   重定向用户回到最初请求的页面 (`appRedirect`)。

---

## 关键函数概览

*   `main.go: main`: 启动入口。
*   `oauthproxy.go: NewOAuthProxy`: 核心对象初始化。
*   `oauthproxy.go: Proxy`: 处理受保护请求的主要入口。
*   `oauthproxy.go: getAuthenticatedSession`: 核心身份验证逻辑。
*   `oauthproxy.go: OAuthStart`: 启动 OAuth 流程。
*   `oauthproxy.go: OAuthCallback`: 处理提供者回调。
*   `providers/providers.go: Provider.Redeem`: 授权码兑换令牌（由具体提供者实现，如 `oidc.go`）。
*   `providers/providers.go: Provider.EnrichSession`: 获取更多用户声明。

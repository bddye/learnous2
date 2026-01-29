# OAuth2 Proxy 项目解析文档

## 项目简介
OAuth2 Proxy 是一个反向代理和身份验证库，旨在为现有的 Web 应用程序提供 OAuth2 和 OpenID Connect (OIDC) 身份验证。它可以作为独立服务运行，也可以集成到现有的架构中（如 Nginx auth_request 模式）。

## 核心功能
- 支持多种 OAuth2 提供者（Google, GitHub, Azure, OIDC 等）。
- 自动处理登录流程、令牌交换和刷新。
- 支持基于电子邮件域名、白名单或组的授权。
- 提供会话管理（Cookie 或 Redis）。

## 目录结构解析

### 根目录
- `main.go`: 程序的入口点，负责加载配置、初始化日志和启动代理服务器。
- `oauthproxy.go`: 项目的核心逻辑，定义了 `OAuthProxy` 结构体及其处理请求的方法（如 `ServeHTTP`, `SignIn`, `OAuthCallback` 等）。
- `validator.go`: 负责验证用户电子邮件地址是否符合配置的允许域名或白名单。
- `go.mod`, `go.sum`: Go 依赖管理文件。

### `pkg/` 目录
`pkg/` 文件夹包含了项目的内部库和模块。

- `apis/`: 定义了核心接口和配置选项结构体（如 `options`, `sessions`）。
- `app/`:
    - `pagewriter/`: 负责渲染和写入 HTML 模板（登录页、错误页）。
    - `redirect/`: 处理身份验证后的重定向逻辑。
- `authentication/`: 包含基本的身份验证方法（如 HTPasswd, HMAC 签名）。
- `cookies/`: 统一处理 Cookie 的创建、解析和验证。
- `encryption/`: 包含加解密工具，用于保护 Cookie 和会话数据。
- `header/`: 负责在请求或响应中注入 HTTP 标头（如将用户信息传递给后端）。
- `ip/`: 处理客户端 IP 地址解析和受信任 IP 验证。
- `logger/`: 自定义日志记录器。
- `middleware/`: HTTP 中间件，用于处理会话加载、JWT 验证、健康检查、指标等。
- `providers/`: 包含 OIDC 特有的逻辑。
- `proxyhttp/`: 封装了 HTTP 和 HTTPS 服务器的启动和优雅关闭。
- `requests/`: 封装了内部发起的 HTTP 请求工具。
- `sessions/`: 会话存储实现（支持 Cookie 和 Redis）。
- `upstream/`: 负责将请求转发到后端上游服务器。
- `util/`: 通用实用程序函数。
- `validation/`: 负责在启动时验证配置选项的合法性。
- `version/`: 版本信息。
- `watcher/`: 文件监控，用于在不重启的情况下重载配置文件（如已验证邮箱列表）。

### `providers/` 目录
该目录包含了所有支持的 OAuth2/OIDC 提供者的具体实现。
- `google.go`, `github.go`, `azure.go` 等：每个文件对应一个特定的身份提供者。
- `providers.go`: 提供者的核心接口定义和实例化工厂。
- `provider_data.go`: 定义了所有提供者共享的基础数据结构。
- `provider_default.go`: 提供了提供者接口的默认实现。

## 关键流程解析

关于更详细的身份验证时序和函数调用流，请参阅：[AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md)

1. **启动流程**: `main.go` 加载配置 -> `validation` 验证配置 -> `NewOAuthProxy` 初始化核心组件 -> `oauthproxy.Start()` 启动监听。
2. **身份验证流程**:
    - 用户访问受保护资源。
    - `OAuthProxy` 检查是否存在有效会话。
    - 若无会话，重定向到 `/oauth2/start` (由 `OAuthStart` 处理)。
    - 重定向用户到第三方 OAuth2 提供者。
    - 用户登录后，提供者重定向回 `/oauth2/callback` (由 `OAuthCallback` 处理)。
    - `OAuthProxy` 验证授权码并交换令牌，保存会话。
    - 最后重定向用户回原始请求的页面。

## 开发者提示
如果您尝试用 Spring Boot 实现类似功能，建议重点关注以下部分：
- **中间件机制**: 对应 Spring Security 的 Filter Chain。
- **提供者适配**: 学习 `providers/` 目录下的接口抽象。
- **会话保护**: 参考 `encryption/` 目录如何对 Cookie 进行签名和加密。

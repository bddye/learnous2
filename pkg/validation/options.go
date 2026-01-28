package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

// Validate 检查是否设置了必需的选项，并验证这些选项的格式是否正确
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateSessionCookieMinimal(o)...)
	msgs = append(msgs, validateRedisSessionStore(o)...)
	msgs = append(msgs, prefixValues("injectRequestHeaders: ", validateHeaders(o.InjectRequestHeaders)...)...)
	msgs = append(msgs, prefixValues("injectResponseHeaders: ", validateHeaders(o.InjectResponseHeaders)...)...)
	msgs = append(msgs, validateProviders(o)...)
	msgs = append(msgs, validateAPIRoutes(o)...)
	msgs = configureLogger(o.Logging, msgs)
	msgs = parseSignatureKey(o, msgs)

	if o.SSLInsecureSkipVerify {
		transport := requests.DefaultTransport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- InsecureSkipVerify is a configurable option we allow
	} else if len(o.Providers[0].CAFiles) > 0 {
		pool, err := util.GetCertPool(o.Providers[0].CAFiles, ptr.Deref(o.Providers[0].UseSystemTrustStore, options.DefaultUseSystemTrustStore))
		if err == nil {
			transport := requests.DefaultTransport.(*http.Transport)
			transport.TLSClientConfig = &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}
		} else {
			msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
		}
	}

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.SkipJwtBearerTokens {
		// 配置额外的发行者
		if len(o.ExtraJwtIssuers) > 0 {
			var jwtIssuers []jwtIssuer
			jwtIssuers, msgs = parseJwtIssuers(o.ExtraJwtIssuers, msgs)
			for _, jwtIssuer := range jwtIssuers {
				verifier, err := newVerifierFromJwtIssuer(
					o.Providers[0].OIDCConfig.AudienceClaims,
					o.Providers[0].OIDCConfig.ExtraAudiences,
					jwtIssuer,
				)
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("error building verifiers: %s", err))
				}
				o.SetJWTBearerVerifiers(append(o.GetJWTBearerVerifiers(), verifier))
			}
		}
	}

	var redirectURL *url.URL
	redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
	o.SetRedirectURL(redirectURL)
	if o.RawRedirectURL == "" && !o.Cookie.Secure && !o.ReverseProxy {
		logger.Print("WARNING: no explicit redirect URL: redirects will default to insecure HTTP")
	}

	msgs = append(msgs, validateUpstreams(o.UpstreamServers)...)

	if o.ReverseProxy {
		parser, err := ip.GetRealClientIPParser(o.RealClientIPHeader)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("real_client_ip_header (%s) not accepted parameter value: %v", o.RealClientIPHeader, err))
		}
		o.SetRealClientIPParser(parser)

		// 允许记录器获取客户端 IP
		logger.SetGetClientFunc(func(r *http.Request) string {
			return ip.GetClientString(o.GetRealClientIPParser(), r, false)
		})
	}

	// 在 ReverseProxy 验证之后执行此操作，以便进行 TrustedIP 协调检查
	msgs = append(msgs, validateAllowlists(o)...)

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseSignatureKey(o *options.Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	logger.Print("WARNING: `--signature-key` is deprecated. It will be removed in a future release")

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+o.SignatureKey)
	}
	o.SetSignatureData(&options.SignatureData{Hash: hash, Key: secretKey})
	return msgs
}

// parseJwtIssuers 接收 issuer=audience 形式的字符串数组，并解析为 jwtIssuer 结构体数组。
func parseJwtIssuers(issuers []string, msgs []string) ([]jwtIssuer, []string) {
	parsedIssuers := make([]jwtIssuer, 0, len(issuers))
	for _, jwtVerifier := range issuers {
		components := strings.Split(jwtVerifier, "=")
		if len(components) < 2 {
			msgs = append(msgs, fmt.Sprintf("invalid jwt verifier uri=audience spec: %s", jwtVerifier))
			continue
		}
		uri, audience := components[0], strings.Join(components[1:], "=")
		parsedIssuers = append(parsedIssuers, jwtIssuer{issuerURI: uri, audience: audience})
	}
	return parsedIssuers, msgs
}

// newVerifierFromJwtIssuer 接收 jwtIssuer 中的发行者信息并返回该发行者的验证器。
func newVerifierFromJwtIssuer(audienceClaims []string, extraAudiences []string, jwtIssuer jwtIssuer) (internaloidc.IDTokenVerifier, error) {
	pvOpts := internaloidc.ProviderVerifierOptions{
		AudienceClaims: audienceClaims,
		ClientID:       jwtIssuer.audience,
		ExtraAudiences: extraAudiences,
		IssuerURL:      jwtIssuer.issuerURI,
	}

	pv, err := internaloidc.NewProviderVerifier(context.TODO(), pvOpts)
	if err != nil {
		// 如果发现机制不起作用，请在没有发现的情况下重试
		pvOpts.JWKsURL = strings.TrimSuffix(jwtIssuer.issuerURI, "/") + "/.well-known/jwks.json"
		pvOpts.SkipDiscovery = true

		pv, err = internaloidc.NewProviderVerifier(context.TODO(), pvOpts)
		if err != nil {
			return nil, fmt.Errorf("could not construct provider verifier for JWT Issuer: %v", err)
		}
	}

	return pv.Verifier(), nil
}

// jwtIssuer 保存用于构造验证器的解析后的 JWT 发行者信息。
type jwtIssuer struct {
	issuerURI string
	audience  string
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}

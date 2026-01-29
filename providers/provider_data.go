package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/util"
	"golang.org/x/oauth2"
)

const (
	// This is not exported as it's not currently user configurable
	oidcUserClaim = "sub"
)

// ProviderData 包含配置所有 OAuth2 提供者实现所需的信息。
type ProviderData struct {
	ProviderName      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	ClientID          string
	ClientSecret      string
	ClientSecretFile  string
	Scope             string
	// The response mode requested from the provider or empty for default ("query")
	AuthRequestResponseMode string
	// The picked CodeChallenge Method or empty if none.
	CodeChallengeMethod string
	// Code challenge methods supported by the Provider
	SupportedCodeChallengeMethods []string `json:"code_challenge_methods_supported,omitempty"`

	// Common OIDC options for any OIDC-based providers to consume
	AllowUnverifiedEmail     bool
	UserClaim                string
	EmailClaim               string
	GroupsClaim              string
	Verifier                 internaloidc.IDTokenVerifier
	SkipClaimsFromProfileURL bool

	// Universal Group authorization data structure
	// any provider can set to consume
	AllowedGroups map[string]struct{}

	getAuthorizationHeaderFunc func(string) http.Header
	loginURLParameterDefaults  url.Values
	loginURLParameterOverrides map[string]*regexp.Regexp

	BackendLogoutURL string
}

// Data 返回 ProviderData。
func (p *ProviderData) Data() *ProviderData { return p }

// GetClientSecret 获取提供者的客户端密钥。
func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := os.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Errorf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}

// LoginURLParams 返回应传递给 IdP 登录 URL 的参数值。
// 这是为此提供者配置的默认参数集，
// 可根据为此提供者配置的规则通过给定的覆盖（通常来自 /oauth2/start 请求的 URL）进行可选覆盖。
func (p *ProviderData) LoginURLParams(overrides url.Values) url.Values {
	// the returned url.Values may be modified later in the request handling process
	// so shallow clone the default map
	params := url.Values{}
	for k, v := range p.loginURLParameterDefaults {
		params[k] = v
	}
	if len(overrides) > 0 {
		for param, re := range p.loginURLParameterOverrides {
			if reqValues, ok := overrides[param]; ok {
				actualValues := make([]string, 0, len(reqValues))
				for _, val := range reqValues {
					if re.MatchString(val) {
						actualValues = append(actualValues, val)
					}
				}
				if len(actualValues) > 0 {
					params.Del(param)
					params[param] = actualValues
				}
			}
		}
	}
	return params
}

// compileLoginParams 将给定的一组 LoginURLParameter 选项编译为内部默认值和用于验证任何覆盖的正则表达式。
func (p *ProviderData) compileLoginParams(paramConfig []options.LoginURLParameter) []error {
	var errs []error
	p.loginURLParameterDefaults = url.Values{}
	p.loginURLParameterOverrides = make(map[string]*regexp.Regexp)

	for _, param := range paramConfig {
		if p.seenParameter(param.Name) {
			errs = append(errs, fmt.Errorf("parameter %s provided more than once in loginURLParameters", param.Name))
		} else {
			// record default if parameter declares one
			if len(param.Default) > 0 {
				p.loginURLParameterDefaults[param.Name] = param.Default
			}
			// record allow rules if any
			if len(param.Allow) > 0 {
				errs = p.convertAllowRules(errs, param)
			}
		}
	}
	return errs
}

// convertAllowRules 将给定参数的允许规则列表转换为正则表达式，并存储它以便在运行时验证该参数的覆盖。
func (p *ProviderData) convertAllowRules(errs []error, param options.LoginURLParameter) []error {
	var allowREs []string
	for idx, rule := range param.Allow {
		if (rule.Value == nil) == (rule.Pattern == nil) {
			errs = append(errs, fmt.Errorf("rule %d in LoginURLParameter %s must have exactly one of value or pattern", idx, param.Name))
		} else {
			allowREs = append(allowREs, regexpForRule(rule))
		}
	}
	if re, err := regexp.Compile(strings.Join(allowREs, "|")); err != nil {
		errs = append(errs, err)
	} else {
		p.loginURLParameterOverrides[param.Name] = re
	}
	return errs
}

// seenParameter 检查我们是否已经处理了给定参数名称的配置。
func (p *ProviderData) seenParameter(name string) bool {
	_, seenDefault := p.loginURLParameterDefaults[name]
	_, seenOverride := p.loginURLParameterOverrides[name]
	return seenDefault || seenOverride
}

// regexpForRule 为给定的 URLParameterRule 生成验证正则表达式模式。
// 如果规则是固定值，则返回精确匹配该值的正则表达式，如果规则本身是正则表达式，则按原样使用。
func regexpForRule(rule options.URLParameterRule) string {
	if rule.Value != nil {
		// convert literal value into an equivalent regexp,
		// anchored at start and end
		return "^" + regexp.QuoteMeta(*rule.Value) + "$"
	}
	// just use the pattern as-is, but wrap in a non-capture group
	// to avoid any possibility of confusing the outer disjunction.
	return "(?:" + *rule.Pattern + ")"
}

// setAllowedGroups 将分组列表组织到 AllowedGroups 映射中，供 Authorize 实现使用。
func (p *ProviderData) setAllowedGroups(groups []string) {
	p.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		p.AllowedGroups[group] = struct{}{}
	}
}

type providerDefaults struct {
	name        string
	loginURL    *url.URL
	redeemURL   *url.URL
	profileURL  *url.URL
	validateURL *url.URL
	scope       string
}

// setProviderDefaults 设置提供者的默认值。
func (p *ProviderData) setProviderDefaults(defaults providerDefaults) {
	p.ProviderName = defaults.name
	p.LoginURL = defaultURL(p.LoginURL, defaults.loginURL)
	p.RedeemURL = defaultURL(p.RedeemURL, defaults.redeemURL)
	p.ProfileURL = defaultURL(p.ProfileURL, defaults.profileURL)
	p.ValidateURL = defaultURL(p.ValidateURL, defaults.validateURL)

	if p.Scope == "" {
		p.Scope = defaults.scope
	}

	if p.UserClaim == "" {
		p.UserClaim = oidcUserClaim
	}
}

// defaultURL 如果未设置给定值，则返回默认值。
func defaultURL(u *url.URL, d *url.URL) *url.URL {
	if u != nil && u.String() != "" {
		// The value is already set
		return u
	}

	// If the default is given, return that
	if d != nil {
		return d
	}
	return &url.URL{}
}

// ****************************************************************************
// These private OIDC helper methods are available to any providers that are
// OIDC compliant
// ****************************************************************************

// verifyIDToken 使用提供者的验证器验证 ID 令牌。
func (p *ProviderData) verifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken := getIDToken(token)
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, ErrMissingIDToken
	}
	if p.Verifier == nil {
		return nil, ErrMissingOIDCVerifier
	}
	return p.Verifier.Verify(ctx, rawIDToken)
}

// buildSessionFromClaims 使用 IDToken 声明填充一个新的 SessionState，包含与令牌无关的字段。
func (p *ProviderData) buildSessionFromClaims(rawIDToken, accessToken string) (*sessions.SessionState, error) {
	ss := &sessions.SessionState{}

	if rawIDToken == "" {
		return ss, nil
	}

	extractor, err := p.getClaimExtractor(rawIDToken, accessToken)
	if err != nil {
		return nil, err
	}

	// Use a slice of a struct (vs map) here in case the same claim is used twice
	for _, c := range []struct {
		claim string
		dst   interface{}
	}{
		{p.UserClaim, &ss.User},
		{p.EmailClaim, &ss.Email},
		{p.GroupsClaim, &ss.Groups},
		// TODO (@NickMeves) Deprecate for dynamic claim to session mapping
		{"preferred_username", &ss.PreferredUsername},
	} {
		if _, err := extractor.GetClaimInto(c.claim, c.dst); err != nil {
			return nil, err
		}
	}

	// `email_verified` must be present and explicitly set to `false` to be
	// considered unverified.
	verifyEmail := (p.EmailClaim == options.OIDCEmailClaim) && !p.AllowUnverifiedEmail

	if verifyEmail {
		var verified bool
		exists, err := extractor.GetClaimInto("email_verified", &verified)
		if err != nil {
			return nil, err
		}

		if exists && !verified {
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", ss.Email)
		}
	}

	return ss, nil
}

// getClaimExtractor 获取一个声明提取器。
func (p *ProviderData) getClaimExtractor(rawIDToken, accessToken string) (util.ClaimExtractor, error) {
	profileURL := p.ProfileURL
	if p.SkipClaimsFromProfileURL {
		profileURL = &url.URL{}
	}

	extractor, err := util.NewClaimExtractor(context.TODO(), rawIDToken, profileURL, p.getAuthorizationHeader(accessToken))
	if err != nil {
		return nil, fmt.Errorf("could not initialise claim extractor: %v", err)
	}

	return extractor, nil
}

// checkNonce 将会话的 nonce 与 IDToken 的 nonce 声明进行比较。
func (p *ProviderData) checkNonce(s *sessions.SessionState) error {
	extractor, err := p.getClaimExtractor(s.IDToken, "")
	if err != nil {
		return fmt.Errorf("id_token claims extraction failed: %v", err)
	}
	var nonce string
	if _, err := extractor.GetClaimInto("nonce", &nonce); err != nil {
		return fmt.Errorf("could not extract nonce from ID Token: %v", err)
	}

	if !s.CheckNonce(nonce) {
		return errors.New("id_token nonce claim does not match the session nonce")
	}
	return nil
}

// getAuthorizationHeader 返回授权标头。
func (p *ProviderData) getAuthorizationHeader(accessToken string) http.Header {
	if p.getAuthorizationHeaderFunc != nil && accessToken != "" {
		return p.getAuthorizationHeaderFunc(accessToken)
	}
	return nil
}

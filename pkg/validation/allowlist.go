package validation

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

// validateAllowlists 验证所有允许列表配置（路由、正则、受信任 IP）。
func validateAllowlists(o *options.Options) []string {
	//nolint:prealloc
	msgs := []string{}

	msgs = append(msgs, validateAuthRoutes(o)...)
	msgs = append(msgs, validateAuthRegexes(o)...)
	msgs = append(msgs, validateTrustedIPs(o)...)

	if len(o.TrustedIPs) > 0 && o.ReverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: mixing --trusted-ip with --reverse-proxy is a potential security vulnerability. An attacker can inject a trusted IP into an X-Real-IP or X-Forwarded-For header if they aren't properly protected outside of oauth2-proxy")
		if err != nil {
			panic(err)
		}
	}

	return msgs
}

// validateAuthRoutes 验证通过 options.SkipAuthRoutes 传递的 method=path 路由。
func validateAuthRoutes(o *options.Options) []string {
	msgs := []string{}
	for _, route := range o.SkipAuthRoutes {
		var regex string
		parts := strings.SplitN(route, "=", 2)
		if len(parts) == 1 {
			regex = parts[0]
		} else {
			regex = parts[1]
		}
		_, err := regexp.Compile(regex)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex /%s/: %v", regex, err))
		}
	}
	return msgs
}

// validateAuthRegexes 验证通过 options.SkipAuthRegex 传递的正则表达式路径。
func validateAuthRegexes(o *options.Options) []string {
	return validateRegexes(o.SkipAuthRegex)
}

// validateTrustedIPs 验证基于 IP 的允许列表的 IP/CIDR。
func validateTrustedIPs(o *options.Options) []string {
	msgs := []string{}
	for i, ipStr := range o.TrustedIPs {
		if nil == ip.ParseIPNet(ipStr) {
			msgs = append(msgs, fmt.Sprintf("trusted_ips[%d] (%s) could not be recognized", i, ipStr))
		}
	}
	return msgs
}

// validateAPIRoutes 验证通过 options.ApiRoutes 传递的正则表达式路径。
func validateAPIRoutes(o *options.Options) []string {
	return validateRegexes(o.APIRoutes)
}

// validateRegexes 验证所有正则表达式，并在出错时返回消息列表。
func validateRegexes(regexes []string) []string {
	msgs := []string{}
	for _, regex := range regexes {
		_, err := regexp.Compile(regex)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex /%s/: %v", regex, err))
		}
	}
	return msgs
}

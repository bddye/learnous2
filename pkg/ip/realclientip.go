package ip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
)

// GetRealClientIPParser 根据给定的标头键返回一个 RealClientIPParser。
func GetRealClientIPParser(headerKey string) (ipapi.RealClientIPParser, error) {
	headerKey = http.CanonicalHeaderKey(headerKey)

	switch headerKey {
	case http.CanonicalHeaderKey("X-Forwarded-For"),
		http.CanonicalHeaderKey("X-Real-IP"),
		http.CanonicalHeaderKey("X-ProxyUser-IP"),
		http.CanonicalHeaderKey("X-Envoy-External-Address"),
		// Cloudflare specific Real-IP header
		http.CanonicalHeaderKey("CF-Connecting-IP"):
		return &xForwardedForClientIPParser{header: headerKey}, nil
	}

	// TODO: implement the more standardized but more complex `Forwarded` header.
	return nil, fmt.Errorf("the http header key (%s) is either invalid or unsupported", headerKey)
}

// xForwardedForClientIPParser 实现了 RealClientIPParser 接口，用于解析 X-Forwarded-For 类型的标头。
type xForwardedForClientIPParser struct {
	header string
}

// GetRealClientIP 获取最终用户的 IP 地址（非代理）。
// 解析格式如以下文档指定的标头：
// * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For。
// 返回上述文档中指定的 `<client>` 部分。
// 此外，能够解析包含端口的 IP，对于 v4 格式为 "<ip>:<port>"，对于 v6 格式为 "[<ip>]:<port>"。
// 同时无缝支持有端口和无端口格式。
func (p xForwardedForClientIPParser) GetRealClientIP(h http.Header) (net.IP, error) {
	var ipStr string
	if realIP := h.Get(p.header); realIP != "" {
		ipStr = realIP
	} else {
		return nil, nil
	}

	// Each successive proxy may append itself, comma separated, to the end of the X-Forwarded-for header.
	// Select only the first IP listed, as it is the client IP recorded by the first proxy.
	if commaIndex := strings.IndexRune(ipStr, ','); commaIndex != -1 {
		ipStr = ipStr[:commaIndex]
	}
	ipStr = strings.TrimSpace(ipStr)

	if ipHost, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = ipHost
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("unable to parse ip (%s) from %s header", ipStr, http.CanonicalHeaderKey(p.header))
	}

	return ip, nil
}

// GetClientIP 如果 p != nil，则从标头中获取感知到的最终用户 IP 地址，否则从 req.RemoteAddr 获取。
func GetClientIP(p ipapi.RealClientIPParser, req *http.Request) (net.IP, error) {
	if p != nil {
		return p.GetRealClientIP(req.Header)
	}
	return getRemoteIP(req)
}

// getRemoteIP 获取底层连接网络主机的 IP。
func getRemoteIP(req *http.Request) (net.IP, error) {
	//revive:disable:indent-error-flow
	if ipStr, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
		return nil, fmt.Errorf("unable to get ip and port from http.RemoteAddr (%s)", req.RemoteAddr)
	} else if ip := net.ParseIP(ipStr); ip != nil {
		return ip, nil
	} else {
		return nil, fmt.Errorf("unable to parse ip (%s)", ipStr)
	}
	//revive:enable:indent-error-flow
}

// GetClientString 获取远程 IP 的人类可读字符串，如果可用，还可以选择获取真实客户端 IP。
func GetClientString(p ipapi.RealClientIPParser, req *http.Request, full bool) (s string) {
	var realClientIPStr string
	if p != nil {
		if realClientIP, err := p.GetRealClientIP(req.Header); err == nil && realClientIP != nil {
			realClientIPStr = realClientIP.String()
		}
	}

	var remoteIPStr string
	if remoteIP, err := getRemoteIP(req); err == nil {
		remoteIPStr = remoteIP.String()
	}

	if !full && realClientIPStr != "" {
		return realClientIPStr
	}
	if full && realClientIPStr != "" {
		return fmt.Sprintf("%s (%s)", remoteIPStr, realClientIPStr)
	}
	return remoteIPStr
}

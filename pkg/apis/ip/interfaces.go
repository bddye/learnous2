package ip

import (
	"net"
	"net/http"
)

// RealClientIPParser 是用于获取客户端真实 IP 以用于日志记录的接口。
type RealClientIPParser interface {
	GetRealClientIP(http.Header) (net.IP, error)
}

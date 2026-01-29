package ip

import (
	"net"
	"strings"
)

// ParseIPNet 将字符串解析为 net.IPNet 指针。
// 它支持 CIDR 表示法和普通的 IP 地址表示法。
func ParseIPNet(s string) *net.IPNet {
	if !strings.ContainsRune(s, '/') {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}

		var mask net.IPMask
		switch {
		case ip.To4() != nil:
			mask = net.CIDRMask(32, 32)
		case ip.To16() != nil:
			mask = net.CIDRMask(128, 128)
		default:
			return nil
		}

		return &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
	}

	switch ip, ipNet, err := net.ParseCIDR(s); {
	case err != nil:
		return nil
	case !ipNet.IP.Equal(ip):
		return nil
	default:
		return ipNet
	}
}

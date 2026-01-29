package ip

import (
	"fmt"
	"net"
)

// NetSet 是用于在 CIDR 网络集合中快速查找单个 IP 地址是否相交的查找表。
//
// 支持 4 字节（IPv4）和 16 字节（IPv6）网络。
//
// 提供最佳情况 O(1)，最坏情况 O(log(n)) 的性能。
// 实际上，包含的网络掩码通常只有标准长度：
// - IPv4 的 /8, /16, /24 和 /32
// - IPv6 的 /64 和 /128。
// 因此，即使包含了大部分互联网，典型的查找时间也会更接近最佳情况而不是最坏情况。
type NetSet struct {
	ip4NetMaps []ipNetMap
	ip6NetMaps []ipNetMap
}

// NewNetSet 使用所有提供的网络创建一个新的 NetSet。
func NewNetSet() *NetSet {
	return &NetSet{
		ip4NetMaps: make([]ipNetMap, 0),
		ip6NetMaps: make([]ipNetMap, 0),
	}
}

// Has 检查 `ip` 是否在集合中，如果在集合中则为 true，否则为 false。
func (w *NetSet) Has(ip net.IP) bool {
	netMaps := w.getNetMaps(ip)

	// Check all ipNetMaps for intersection with `ip`.
	for _, netMap := range *netMaps {
		if netMap.has(ip) {
			return true
		}
	}
	return false
}

// AddIPNet 向集合中添加一个 CIDR 网络。
func (w *NetSet) AddIPNet(ipNet net.IPNet) {
	netMaps := w.getNetMaps(ipNet.IP)

	// Determine the size / number of ones in the CIDR network mask.
	ones, _ := ipNet.Mask.Size()

	var netMap *ipNetMap

	// Search for the ipNetMap containing networks with the same number of ones.
	for i := 0; len(*netMaps) > i; i++ {
		if netMapOnes, _ := (*netMaps)[i].mask.Size(); netMapOnes == ones {
			netMap = &(*netMaps)[i]
			break
		}
	}

	// Create a new ipNetMap if none with this number of ones have been created yet.
	if netMap == nil {
		netMap = &ipNetMap{
			mask: ipNet.Mask,
			ips:  make(map[string]bool),
		}
		*netMaps = append(*netMaps, *netMap)
		// Recurse once now that there exists an netMap.
		w.AddIPNet(ipNet)
		return
	}

	// Add the IP to the ipNetMap.
	netMap.ips[ipNet.IP.String()] = true
}

// getNetMaps 获取给定 IP 版本的适当网络数组。
func (w *NetSet) getNetMaps(ip net.IP) (netMaps *[]ipNetMap) {
	switch {
	case ip.To4() != nil:
		netMaps = &w.ip4NetMaps
	case ip.To16() != nil:
		netMaps = &w.ip6NetMaps
	default:
		panic(fmt.Sprintf("IP (%s) is neither 4-byte nor 16-byte?", ip.String()))
	}

	return netMaps
}

// ipNetMap 具有相同掩码大小的 CIDR 网络的哈希集。
type ipNetMap struct {
	mask net.IPMask
	ips  map[string]bool
}

// has 检查 IP 是否在此映射包含的任何 CIDR 网络中。
func (m ipNetMap) has(ip net.IP) bool {
	// Apply the mask to the IP to remove any irrelevant bits in the IP.
	ipMasked := ip.Mask(m.mask)
	if ipMasked == nil {
		panic(fmt.Sprintf(
			"Mismatch in net.IPMask and net.IP protocol version, cannot apply mask %s to %s",
			m.mask.String(), ip.String()))
	}

	// Check if the masked IP is the same as any of the networks.
	if _, ok := m.ips[ipMasked.String()]; ok {
		return true
	}
	return false
}

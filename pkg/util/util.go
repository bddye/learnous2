package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// GetCertPool 根据路径列表加载证书池，并可以选择是否使用系统证书池。
func GetCertPool(paths []string, useSystemPool bool) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}

	var pool *x509.CertPool
	if useSystemPool {
		rootPool, err := getSystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to get SystemCertPool when append is true - #{err}")
		}
		pool = rootPool
	} else {
		pool = x509.NewCertPool()
	}

	return loadCertsFromPaths(paths, pool)

}

// getSystemCertPool 获取系统证书池。
func getSystemCertPool() (*x509.CertPool, error) {
	rootPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if rootPool == nil {
		return nil, fmt.Errorf("SystemCertPool is empty")
	}

	return rootPool, nil
}

// loadCertsFromPaths 从指定路径列表加载证书并将其添加到证书池中。
func loadCertsFromPaths(paths []string, pool *x509.CertPool) (*x509.CertPool, error) {
	for _, path := range paths {
		// Cert paths are a configurable option
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

// GenerateCert 为给定的 IP 地址生成自签名证书和私钥。
// 参考：https://golang.org/src/crypto/tls/generate_cert.go
func GenerateCert(ipaddr string) ([]byte, []byte, error) {
	var err error

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, keyBytes, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, keyBytes, err
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OAuth2 Proxy Test Suite"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IPAddresses: []net.IP{net.ParseIP(ipaddr)},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	return certBytes, keyBytes, err
}

// SplitHostPort 分离主机名和端口。如果端口无效，它将整个输入作为主机名返回。
// 它不检查主机名的有效性。
// 与 net.SplitHostPort 不同，它遵循 RFC 3986，要求端口为数字。
// 摘自 net/url，并修改了 validOptionalPort() 以接受 ":*"。
func SplitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort 报告端口是否为空字符串或匹配 /^:\d*$/。
// 摘自 net/url，并修改为接受 ":*"。
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsEndpointAllowed 根据允许的域名列表检查端点 URL 是否被允许。
func IsEndpointAllowed(endpoint *url.URL, allowedDomains []string) bool {
	hostname := endpoint.Hostname()

	for _, allowedDomain := range allowedDomains {
		allowedHost, allowedPort := SplitHostPort(allowedDomain)
		if allowedHost == "" {
			continue
		}

		if isHostnameAllowed(hostname, allowedHost) {
			// the domain names match, now validate the ports
			// if the allowed domain's port is '*', allow all ports
			// if the allowed domain contains a specific port, only allow that port
			// if the allowed domain doesn't contain a port at all, only allow empty redirect ports ie http and https
			redirectPort := endpoint.Port()
			if allowedPort == "*" ||
				allowedPort == redirectPort ||
				(allowedPort == "" && redirectPort == "") {
				return true
			}
		}
	}

	return false
}

// isHostnameAllowed 检查主机名是否符合允许的主机名模式。
func isHostnameAllowed(hostname, allowedHost string) bool {
	// check if we have a perfect match between hostname and allowedHost
	if hostname == strings.TrimPrefix(allowedHost, ".") ||
		hostname == strings.TrimPrefix(allowedHost, "*.") {
		return true
	}

	// check if hostname is a sub domain of the allowedHost
	if (strings.HasPrefix(allowedHost, ".") && strings.HasSuffix(hostname, allowedHost)) ||
		(strings.HasPrefix(allowedHost, "*.") && strings.HasSuffix(hostname, allowedHost[1:])) {
		return true
	}

	return false
}

// RemoveDuplicateStr 从字符串切片中移除重复项。
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]struct{})
	var list []string
	for _, item := range strSlice {
		if _, ok := allKeys[item]; !ok {
			allKeys[item] = struct{}{}
			list = append(list, item)
		}
	}
	return list
}

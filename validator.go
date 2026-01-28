package main

import (
	"encoding/csv"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
)

// UserMap 保存来自已验证电子邮件文件的信息
type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

// NewUserMap 将已验证的电子邮件文件解析为新的 UserMap。
//
// TODO (@NickMeves): 审计 `unsafe.Pointer` 的使用并可能进行重构。
func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m)) // #nosec G103
	if usersFile != "" {
		logger.Printf("using authenticated emails file %s", usersFile)
		watcher.WatchFileForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedEmailsFile()
			onUpdate()
		})
		um.LoadAuthenticatedEmailsFile()
	}
	return um
}

// IsValid 检查电子邮件是否被允许。
func (um *UserMap) IsValid(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

// LoadAuthenticatedEmailsFile 从磁盘加载已验证的电子邮件文件，并将内容解析为 CSV。
func (um *UserMap) LoadAuthenticatedEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		logger.Fatalf("failed opening authenticated-emails-file=%q, %s", um.usersFile, err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("Error closing authenticated emails file: %s", cerr)
		}
	}(r)
	csvReader := csv.NewReader(r)
	csvReader.Comma = ','
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true
	records, err := csvReader.ReadAll()
	if err != nil {
		logger.Errorf("error reading authenticated-emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated)) // #nosec G103
}

// newValidatorImpl 内部实现，构建一个验证电子邮件地址的函数。
func newValidatorImpl(domains []string, usersFile string,
	done <-chan bool, onUpdate func()) func(string) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = strings.ToLower(domain)
	}

	validator := func(email string) (valid bool) {
		if email == "" {
			return
		}
		email = strings.ToLower(email)
		valid = isEmailValidWithDomains(email, domains)
		if !valid {
			valid = validUsers.IsValid(email)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

// NewValidator 构建一个用于验证电子邮件地址的函数。
func NewValidator(domains []string, usersFile string) func(string) bool {
	return newValidatorImpl(domains, usersFile, nil, func() {})
}

// isEmailValidWithDomains 检查已验证的电子邮件是否针对提供的域名进行了验证。
func isEmailValidWithDomains(email string, allowedDomains []string) bool {
	for _, domain := range allowedDomains {
		// 如果域名与电子邮件完美后缀匹配，则允许
		if strings.HasSuffix(email, "@"+domain) {
			return true
		}

		// 如果域名以 . 或 *. 为前缀，且最后一个元素（以 @ 分割）以该域名为后缀，则允许
		atoms := strings.Split(email, "@")

		if (strings.HasPrefix(domain, ".") && strings.HasSuffix(atoms[len(atoms)-1], domain)) ||
			(strings.HasPrefix(domain, "*.") && strings.HasSuffix(atoms[len(atoms)-1], domain[1:])) {
			return true
		}
	}

	return false
}

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/redis/go-redis/v9"
)

// SessionStore 是 persistence.Store 接口的一个实现，它在 Redis 中存储会话
type SessionStore struct {
	Client Client
}

// NewRedisSessionStore 初始化 SessionStore 的新实例，并将其包装在 persistence.Manager 中
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	client, err := NewRedisClient(opts.Redis)
	if err != nil {
		return nil, fmt.Errorf("error constructing redis client: %v", err)
	}

	rs := &SessionStore{
		Client: client,
	}
	return persistence.NewManager(rs, cookieOpts), nil
}

// Save 获取 sessions.SessionState 并将其中的信息存储到 Redis 中，并在 HTTP 响应写入器上添加一个新的持久化 Cookie
func (store *SessionStore) Save(ctx context.Context, key string, value []byte, exp time.Duration) error {
	err := store.Client.Set(ctx, key, value, exp)
	if err != nil {
		return fmt.Errorf("error saving redis session: %v", err)
	}
	return nil
}

// Load 从 HTTP 请求对象中的持久化 Cookie 中读取 sessions.SessionState 信息
func (store *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	value, err := store.Client.Get(ctx, key)
	if err == redis.Nil {
		return nil, fmt.Errorf("session does not exist")
	} else if err != nil {
		return nil, fmt.Errorf("error loading redis session: %v", err)
	}

	return value, nil
}

// Clear 从 Redis 中清除给定持久化 Cookie 的任何已保存会话信息，然后清除该会话
func (store *SessionStore) Clear(ctx context.Context, key string) error {
	err := store.Client.Del(ctx, key)
	if err != nil {
		return fmt.Errorf("error clearing the session from redis: %v", err)
	}
	return nil
}

// Lock 为 sessions.SessionState 创建一个锁对象
func (store *SessionStore) Lock(key string) sessions.Lock {
	return store.Client.Lock(key)
}

// VerifyConnection 验证 Redis 连接是否有效且服务器是否有响应
func (store *SessionStore) VerifyConnection(ctx context.Context) error {
	return store.Client.Ping(ctx)
}

// NewRedisClient 创建一个 redis.Client（独立运行、哨兵模式或 Redis 集群）
func NewRedisClient(opts options.RedisStoreOptions) (Client, error) {
	if opts.UseSentinel && opts.UseCluster {
		return nil, fmt.Errorf("options redis-use-sentinel and redis-use-cluster are mutually exclusive")
	}
	if opts.UseSentinel {
		return buildSentinelClient(opts)
	}
	if opts.UseCluster {
		return buildClusterClient(opts)
	}

	return buildStandaloneClient(opts)
}

// buildSentinelClient 创建一个连接到 Redis 哨兵以进行主从 Redis 节点协调的 redis.Client
func buildSentinelClient(opts options.RedisStoreOptions) (Client, error) {
	addrs, opt, err := parseRedisURLs(opts.SentinelConnectionURLs)
	if err != nil {
		return nil, fmt.Errorf("could not parse redis urls: %v", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       opts.SentinelMasterName,
		SentinelAddrs:    addrs,
		SentinelPassword: opts.SentinelPassword,
		Username:         opts.Username,
		Password:         opts.Password,
		TLSConfig:        opt.TLSConfig,
		ConnMaxIdleTime:  time.Duration(opts.IdleTimeout) * time.Second,
	})
	return newClient(client), nil
}

// buildClusterClient 创建一个支持 Redis 集群的 redis.Client
func buildClusterClient(opts options.RedisStoreOptions) (Client, error) {
	addrs, opt, err := parseRedisURLs(opts.ClusterConnectionURLs)
	if err != nil {
		return nil, fmt.Errorf("could not parse redis urls: %v", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:           addrs,
		Username:        opts.Username,
		Password:        opts.Password,
		TLSConfig:       opt.TLSConfig,
		ConnMaxIdleTime: time.Duration(opts.IdleTimeout) * time.Second,
	})
	return newClusterClient(client), nil
}

// buildStandaloneClient 创建一个连接到简单 Redis 节点的 redis.Client
func buildStandaloneClient(opts options.RedisStoreOptions) (Client, error) {
	opt, err := redis.ParseURL(opts.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse redis url: %s", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	opt.ConnMaxIdleTime = time.Duration(opts.IdleTimeout) * time.Second

	client := redis.NewClient(opt)
	return newClient(client), nil
}

// setupTLSConfig 如果在 redis.Options 中提供了 TLS 选项，则设置 TLSConfig
func setupTLSConfig(opts options.RedisStoreOptions, opt *redis.Options) error {
	if opts.InsecureSkipTLSVerify {
		if opt.TLSConfig == nil {
			/* #nosec */
			opt.TLSConfig = &tls.Config{}
		}

		opt.TLSConfig.InsecureSkipVerify = true
	}

	if opts.CAPath != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			logger.Errorf("failed to load system cert pool for redis connection, falling back to empty cert pool")
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certs, err := os.ReadFile(opts.CAPath)
		if err != nil {
			return fmt.Errorf("failed to load %q, %v", opts.CAPath, err)
		}

		// 将我们的证书追加到系统池中
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logger.Errorf("未追加任何证书，仅使用系统证书")
		}

		if opt.TLSConfig == nil {
			/* #nosec */
			opt.TLSConfig = &tls.Config{}
		}

		opt.TLSConfig.RootCAs = rootCAs
	}
	return nil
}

// parseRedisURLs 解析 Redis URL 列表并返回 host:port 形式的地址列表以及可用于连接 Redis 的 redis.Options
func parseRedisURLs(urls []string) ([]string, *redis.Options, error) {
	if len(urls) == 0 {
		return nil, nil, fmt.Errorf("unable to parse redis urls: no redis urls provided")
	}

	addrs := []string{}
	var redisOptions *redis.Options
	for _, u := range urls {
		parsedURL, err := redis.ParseURL(u)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse redis url: %v", err)
		}
		addrs = append(addrs, parsedURL.Addr)
		redisOptions = parsedURL
	}
	return addrs, redisOptions, nil
}

var _ persistence.Store = (*SessionStore)(nil)

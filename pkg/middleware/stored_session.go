package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

const (
	// 尝试获取锁时，如果在此超时之前未完成，则退出并使刷新尝试失败。
	// TODO: 这可能应该由最终用户配置。
	sessionRefreshObtainTimeout = 5 * time.Second

	// 会话刷新尝试允许的最大时间。
	// 如果刷新请求未在此时间内完成，锁将被释放。
	// TODO: 这可能应该由最终用户配置。
	sessionRefreshLockDuration = 2 * time.Second

	// 获取锁失败后重试之前的等待时间。
	// TODO: 这可能应该由最终用户配置。
	sessionRefreshRetryPeriod = 10 * time.Millisecond
)

// StoredSessionLoaderOptions 包含构造存储会话加载器的所有要求。
// 必须提供所有选项。
type StoredSessionLoaderOptions struct {
	// 会话存储后端
	SessionStore sessionsapi.SessionStore

	// 会话应多久刷新一次
	RefreshPeriod time.Duration

	// 基于提供者的会话刷新
	RefreshSession func(context.Context, *sessionsapi.SessionState) (bool, error)

	// 基于提供者的会话验证。
	// 如果会话比 `RefreshPeriod` 旧，但提供者没有刷新它，我们必须使用此验证进行重新验证。
	ValidateSession func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader 创建一个新的 storedSessionLoader，用于从会话存储中加载会话。
// 如果未找到会话，请求将传递给下一个处理器。
// 如果会话是由先前的处理器加载的，它将不会被替换。
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:            opts.SessionStore,
		refreshPeriod:    opts.RefreshPeriod,
		sessionRefresher: opts.RefreshSession,
		sessionValidator: opts.ValidateSession,
	}
	return ss.loadSession
}

// storedSessionLoader 负责从会话存储中加载由 Cookie 标识的会话。
type storedSessionLoader struct {
	store            sessionsapi.SessionStore
	refreshPeriod    time.Duration
	sessionRefresher func(context.Context, *sessionsapi.SessionState) (bool, error)
	sessionValidator func(context.Context, *sessionsapi.SessionState) bool
}

// loadSession 尝试加载由请求 Cookie 标识的会话。
// 如果未找到会话，请求将传递给下一个处理器。
// 如果会话是由先前的处理器加载的，它将不会被替换。
func (s *storedSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// 如果 scope 为 nil，这将引发 panic。
		// 在调用此处理程序之前，应始终注入 scope。
		if scope.Session != nil {
			// 会话已加载，传递给下一个处理程序
			next.ServeHTTP(rw, req)
			return
		}

		session, err := s.getValidatedSession(rw, req)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// 如果加载会话时出错，我们应该清除会话
			logger.Errorf("Error loading cookied session: %v, removing session", err)
			err = s.store.Clear(rw, req)
			if err != nil {
				logger.Errorf("Error removing session: %v", err)
			}
		}

		// 如果找到了会话，将其添加到 scope
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getValidatedSession 负责加载会话并确保其有效。
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, err
	}

	err = s.refreshSessionIfNeeded(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// refreshSessionIfNeeded 如果会话比刷新周期旧，将尝试刷新会话。
// 无论成功或失败，我们随后都会验证会话。
func (s *storedSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	if !needsRefresh(s.refreshPeriod, session) {
		// 刷新已禁用或会话不够旧，不执行任何操作
		return nil
	}

	var lockObtained bool
	ctx, cancel := context.WithTimeout(context.Background(), sessionRefreshObtainTimeout)
	defer cancel()

	for !lockObtained {
		select {
		case <-ctx.Done():
			return errors.New("timeout obtaining session lock")
		default:
			err := session.ObtainLock(req.Context(), sessionRefreshLockDuration)
			if err != nil && !errors.Is(err, sessionsapi.ErrLockNotObtained) {
				return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
			} else if errors.Is(err, sessionsapi.ErrLockNotObtained) {
				time.Sleep(sessionRefreshRetryPeriod)
				continue
			}
			// 无错误意味着我们获得了锁
			lockObtained = true
		}
	}

	// 此函数的其余部分在锁下执行，但我们必须在从此函数退出的任何地方释放它。
	defer func() {
		if session == nil {
			return
		}
		if err := session.ReleaseLock(req.Context()); err != nil {
			logger.Errorf("unable to release lock: %v", err)
		}
	}()

	// 重新加载会话，以防它在我们不知情的情况下被更改。
	freshSession, err := s.store.Load(req)
	if err != nil {
		return fmt.Errorf("could not load session: %v", err)
	}
	if freshSession == nil {
		return errors.New("session no longer exists, it may have been removed by another request")
	}
	// 将新会话的状态恢复到原始指针中。
	// 这很重要，这样更改才能传递给父 scope。
	lock := session.Lock
	*session = *freshSession

	// 确保在我们刷新会话后保持会话锁。
	// 从会话存储加载会在会话中创建一个新锁。
	session.Lock = lock

	if !needsRefresh(s.refreshPeriod, session) {
		// 在我们等待获取锁时，会话一定已经被刷新了。
		return nil
	}

	// 我们持有锁，且会话需要刷新
	logger.Printf("Refreshing session - User: %s; SessionAge: %s", session.User, session.Age())
	if err := s.refreshSession(rw, req, session); err != nil {
		// 如果抢占式刷新失败，如果 validateSession 成功，我们仍保留会话。
		logger.Errorf("Unable to refresh session: %v", err)
	}

	// 在任何赎回/刷新操作（无论失败或成功）之后验证所有会话
	return s.validateSession(req.Context(), session)
}

// needsRefresh 确定我们是否应该尝试刷新会话。
func needsRefresh(refreshPeriod time.Duration, session *sessionsapi.SessionState) bool {
	return refreshPeriod > time.Duration(0) && session.Age() > refreshPeriod
}

// refreshSession 尝试向提供者刷新会话，并在会话更新后保存它。
func (s *storedSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	refreshed, err := s.sessionRefresher(req.Context(), session)
	if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
		return fmt.Errorf("error refreshing tokens: %v", err)
	}

	// HACK:
	// Providers that don't implement `RefreshSession` use the default
	// implementation which returns `ErrNotImplemented`.
	// Pretend it refreshed to reset the refresh timer so that `ValidateSession`
	// isn't triggered every subsequent request and is only called once during
	// this request.
	if errors.Is(err, providers.ErrNotImplemented) {
		refreshed = true
	}

	// 会话未刷新，无需持久化。
	if !refreshed {
		return nil
	}

	// 如果我们刷新了，更新 `CreatedAt` 时间以重置刷新计时器
	// （以防底层提供者实现忘记更新）
	session.CreatedAtNow()

	// 因为会话已刷新，确保保存它
	err = s.store.Save(rw, req, session)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthError, "error saving session: %v", err)
		return fmt.Errorf("error saving session: %v", err)
	}
	return nil
}

// validateSession 检查会话是否已过期，并对会话执行提供者验证。
// 错误意味着会话不再有效。
func (s *storedSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.sessionValidator(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}

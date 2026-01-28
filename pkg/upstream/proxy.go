package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

// ProxyErrorHandler 是一个函数，当 HTTP 代理无法连接到上游服务器时，将用于渲染错误页面。
type ProxyErrorHandler func(http.ResponseWriter, *http.Request, error)

// NewProxy creates a new multiUpstreamProxy that can serve requests directed to
// multiple upstreams.
func NewProxy(upstreams options.UpstreamConfig, sigData *options.SignatureData, writer pagewriter.Writer) (http.Handler, error) {
	m := &multiUpstreamProxy{
		serveMux: mux.NewRouter(),
	}

	if ptr.Deref(upstreams.ProxyRawPath, options.DefaultUpstreamProxyRawPath) {
		m.serveMux.UseEncodedPath()
	}

	for _, upstream := range sortByPathLongest(upstreams.Upstreams) {
		if ptr.Deref(upstream.Static, options.DefaultUpstreamStatic) {
			if err := m.registerStaticResponseHandler(upstream, writer); err != nil {
				return nil, fmt.Errorf("could not register static upstream %q: %v", upstream.ID, err)
			}
			continue
		}

		u, err := url.Parse(upstream.URI)
		if err != nil {
			return nil, fmt.Errorf("error parsing URI for upstream %q: %w", upstream.ID, err)
		}
		switch u.Scheme {
		case fileScheme:
			if err := m.registerFileServer(upstream, u, writer); err != nil {
				return nil, fmt.Errorf("could not register file upstream %q: %v", upstream.ID, err)
			}
		case httpScheme, httpsScheme, unixScheme:
			if err := m.registerHTTPUpstreamProxy(upstream, u, sigData, writer); err != nil {
				return nil, fmt.Errorf("could not register %s upstream %q: %v", u.Scheme, upstream.ID, err)
			}
		default:
			return nil, fmt.Errorf("unknown scheme for upstream %q: %q", upstream.ID, u.Scheme)
		}
	}

	registerTrailingSlashHandler(m.serveMux)
	return m, nil
}

// multiUpstreamProxy 将处理导向在 serverMux 中注册的多个上游服务器的请求。
type multiUpstreamProxy struct {
	serveMux *mux.Router
}

// ServerHTTP handles HTTP requests.
func (m *multiUpstreamProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.serveMux.ServeHTTP(rw, req)
}

// registerStaticResponseHandler registers a static response handler with at the given path.
func (m *multiUpstreamProxy) registerStaticResponseHandler(upstream options.Upstream, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => static response %d", upstream.Path, ptr.Deref(upstream.StaticCode, options.DefaultUpstreamStaticCode))
	return m.registerHandler(upstream, newStaticResponseHandler(upstream.ID, upstream.StaticCode), writer)
}

// registerFileServer registers a new fileServer based on the configuration given.
func (m *multiUpstreamProxy) registerFileServer(upstream options.Upstream, u *url.URL, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => file system %q", upstream.Path, u.Path)
	return m.registerHandler(upstream, newFileServer(upstream, u.Path), writer)
}

// registerHTTPUpstreamProxy registers a new httpUpstreamProxy based on the configuration given.
func (m *multiUpstreamProxy) registerHTTPUpstreamProxy(upstream options.Upstream, u *url.URL, sigData *options.SignatureData, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => upstream %q", upstream.Path, upstream.URI)
	return m.registerHandler(upstream, newHTTPUpstreamProxy(upstream, u, sigData, writer.ProxyErrorHandler), writer)
}

// registerHandler 确保给定的处理程序已在 serveMux 中注册。
func (m *multiUpstreamProxy) registerHandler(upstream options.Upstream, handler http.Handler, writer pagewriter.Writer) error {
	if upstream.RewriteTarget == "" {
		m.registerSimpleHandler(upstream.Path, handler)
		return nil
	}

	return m.registerRewriteHandler(upstream, handler, writer)
}

// registerSimpleHandler maintains the behaviour of the go standard serveMux
// by ensuring any path with a trailing `/` matches all paths under that prefix.
func (m *multiUpstreamProxy) registerSimpleHandler(path string, handler http.Handler) {
	if strings.HasSuffix(path, "/") {
		m.serveMux.PathPrefix(path).Handler(handler)
	} else {
		m.serveMux.Path(path).Handler(handler)
	}
}

// registerRewriteHandler 确保处理程序为匹配 Path 中定义的正则表达式的所有路径注册。
// 在向下一个处理程序发出请求之前，请求路径将被重写。
func (m *multiUpstreamProxy) registerRewriteHandler(upstream options.Upstream, handler http.Handler, writer pagewriter.Writer) error {
	rewriteRegExp, err := regexp.Compile(upstream.Path)
	if err != nil {
		return fmt.Errorf("invalid path %q for upstream: %v", upstream.Path, err)
	}

	rewrite := newRewritePath(rewriteRegExp, upstream.RewriteTarget, writer)
	h := alice.New(rewrite).Then(handler)
	m.serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		return rewriteRegExp.MatchString(req.URL.Path)
	}).Handler(h)

	return nil
}

// registerTrailingSlashHandler creates a new matcher that will check if the
// requested path would match if it had a trailing slash appended.
// If the path matches with a trailing slash, we send back a redirect.
// This allows us to be consistent with the built in go servemux implementation.
func registerTrailingSlashHandler(serveMux *mux.Router) {
	serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		if strings.HasSuffix(req.URL.Path, "/") {
			return false
		}

		// 使用单独的 RouteMatch，以便我们可以重定向到路径 + /。
		// 如果我们通过匹配，那么将提供匹配的后端而不是重定向处理程序。
		m := &mux.RouteMatch{}
		slashReq := req.Clone(context.Background())
		slashReq.URL.Path += "/"
		return serveMux.Match(slashReq, m)
	}).Handler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, req.URL.String()+"/", http.StatusMovedPermanently)
	}))
}

// sortByPathLongest 确保上游服务器按最长路径排序。
// 如果涉及重写，重写优先于非重写。
// 当两个上游都定义了重写时，路径较长者优先（注意这是重写逻辑的输入）。
// 这没有考虑重写实际上使路径变短的情况。
// 这应保持标准 Go serve mux 的排序行为。
func sortByPathLongest(in []options.Upstream) []options.Upstream {
	sort.Slice(in, func(i, j int) bool {
		iRW := in[i].RewriteTarget
		jRW := in[j].RewriteTarget

		switch {
		case iRW != "" && jRW != "":
			// 如果两者都有重写目标，则模式最长者优先
			return len(in[i].Path) > len(in[j].Path)
		case iRW != "" && jRW == "":
			// 只有一个有重写，它优先
			return true
		case iRW == "" && jRW != "":
			// 只有一个有重写，它优先
			return false
		default:
			// 默认为最长路径获胜
			return len(in[i].Path) > len(in[j].Path)
		}
	})
	return in
}

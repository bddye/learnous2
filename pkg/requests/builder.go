package requests

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Builder 允许用户构造一个请求，然后通过 Do() 执行该请求。
// Do 返回一个 Result，允许用户获取主体、将主体反序列化为接口或 simplejson.Json。
type Builder interface {
	WithContext(context.Context) Builder
	WithBody(io.Reader) Builder
	WithMethod(string) Builder
	WithHeaders(http.Header) Builder
	SetHeader(key, value string) Builder
	Do() Result
}

type builder struct {
	context  context.Context
	method   string
	endpoint string
	body     io.Reader
	header   http.Header
	result   *result
}

// New 为给定的端点提供一个新的 Builder。
func New(endpoint string) Builder {
	return &builder{
		endpoint: endpoint,
		method:   "GET",
	}
}

// WithContext 为请求添加上下文。
// 如果未提供上下文，则使用 context.Background()。
func (r *builder) WithContext(ctx context.Context) Builder {
	r.context = ctx
	return r
}

// WithBody 为请求添加主体。
func (r *builder) WithBody(body io.Reader) Builder {
	r.body = body
	return r
}

// WithMethod 设置请求方法。默认为 "GET"。
func (r *builder) WithMethod(method string) Builder {
	r.method = method
	return r
}

// WithHeaders 将请求标头映射替换为给定的标头映射。
func (r *builder) WithHeaders(header http.Header) Builder {
	r.header = header.Clone()
	return r
}

// SetHeader 将单个标头设置为给定的值。
// 可用于添加多个标头。
func (r *builder) SetHeader(key, value string) Builder {
	if r.header == nil {
		r.header = make(http.Header)
	}
	r.header.Set(key, value)
	return r
}

// Do 执行请求并以原始形式返回响应。
// 如果请求已经执行，则返回之前的结果。
// 这不允许你重复请求。
func (r *builder) Do() Result {
	if r.result != nil {
		// Request has already been done
		return r.result
	}

	// Must provide a non-nil context to NewRequestWithContext
	if r.context == nil {
		r.context = context.Background()
	}

	return r.do()
}

// do 创建请求，使用默认客户端执行它，并将主体提取到响应中
func (r *builder) do() Result {
	req, err := http.NewRequestWithContext(r.context, r.method, r.endpoint, r.body)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error creating request: %v", err)}
		return r.result
	}
	req.Header = r.header

	resp, err := DefaultHTTPClient.Do(req)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error performing request: %v", err)}
		return r.result
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error reading response body: %v", err)}
		return r.result
	}

	r.result = &result{response: resp, body: body}
	return r.result
}

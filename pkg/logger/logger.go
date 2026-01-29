package logger

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"text/template"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// AuthStatus 定义了发生的各种不同类型的身份验证日志记录。
type AuthStatus string

// Level 表示日志消息的日志级别。
type Level int

const (
	// DefaultStandardLoggingFormat defines the default standard log format
	DefaultStandardLoggingFormat = "[{{.Timestamp}}] [{{.File}}] {{.Message}}"
	// DefaultAuthLoggingFormat defines the default auth log format
	DefaultAuthLoggingFormat = "{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}"
	// DefaultRequestLoggingFormat defines the default request log format
	DefaultRequestLoggingFormat = "{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

	// AuthSuccess indicates that an auth attempt has succeeded explicitly
	AuthSuccess AuthStatus = "AuthSuccess"
	// AuthFailure indicates that an auth attempt has failed explicitly
	AuthFailure AuthStatus = "AuthFailure"
	// AuthError indicates that an auth attempt has failed due to an error
	AuthError AuthStatus = "AuthError"

	// Llongfile flag to log full file name and line number: /a/b/c/d.go:23
	Llongfile = 1 << iota
	// Lshortfile flag to log final file name element and line number: d.go:23. overrides Llongfile
	Lshortfile
	// LUTC flag to log UTC datetime rather than the local time zone
	LUTC
	// LstdFlags flag for initial values for the logger
	LstdFlags = Lshortfile

	// DEFAULT is the default log level (effectively INFO)
	DEFAULT Level = iota
	// ERROR is for error-level logging
	ERROR
)

// These are the containers for all values that are available as variables in the logging formats.
// All values are pre-formatted strings so it is easy to use them in the format string.
type stdLogMessageData struct {
	Timestamp,
	File,
	Message string
}

type authLogMessageData struct {
	Client,
	Host,
	Protocol,
	RequestID,
	RequestMethod,
	Timestamp,
	UserAgent,
	Username,
	Status,
	Message string
}

type reqLogMessageData struct {
	Client,
	Host,
	Protocol,
	RequestID,
	RequestDuration,
	RequestMethod,
	RequestURI,
	ResponseSize,
	StatusCode,
	Timestamp,
	Upstream,
	UserAgent,
	Username string
}

// GetClientFunc 以字符串形式返回明显的“真实客户端 IP”。
type GetClientFunc = func(r *http.Request) string

// Logger 表示一个活动的日志记录对象，它通过格式化程序向 io.Writer 生成多行输出。
// 每次日志记录操作都会对 Writer 的 Write 方法进行一次调用。
// Logger 可以在多个 goroutine 中同时使用；它保证对 Writer 的访问是串行化的。
type Logger struct {
	mu             sync.Mutex
	flag           int
	writer         io.Writer
	errWriter      io.Writer
	stdEnabled     bool
	authEnabled    bool
	reqEnabled     bool
	getClientFunc  GetClientFunc
	excludePaths   map[string]struct{}
	stdLogTemplate *template.Template
	authTemplate   *template.Template
	reqTemplate    *template.Template
}

// New 创建一个新的标准错误 Logger。
func New(flag int) *Logger {
	return &Logger{
		writer:         os.Stdout,
		errWriter:      os.Stderr,
		flag:           flag,
		stdEnabled:     true,
		authEnabled:    true,
		reqEnabled:     true,
		getClientFunc:  func(r *http.Request) string { return r.RemoteAddr },
		excludePaths:   nil,
		stdLogTemplate: template.Must(template.New("std-log").Parse(DefaultStandardLoggingFormat)),
		authTemplate:   template.Must(template.New("auth-log").Parse(DefaultAuthLoggingFormat)),
		reqTemplate:    template.Must(template.New("req-log").Parse(DefaultRequestLoggingFormat)),
	}
}

var std = New(LstdFlags)

func (l *Logger) formatLogMessage(calldepth int, message string) []byte {
	now := time.Now()
	file := "???:0"

	if l.flag&(Lshortfile|Llongfile) != 0 {
		file = l.GetFileLineString(calldepth + 1)
	}

	var logBuff = new(bytes.Buffer)
	err := l.stdLogTemplate.Execute(logBuff, stdLogMessageData{
		Timestamp: FormatTimestamp(now),
		File:      file,
		Message:   message,
	})
	if err != nil {
		panic(err)
	}

	_, err = logBuff.Write([]byte("\n"))
	if err != nil {
		panic(err)
	}

	return logBuff.Bytes()
}

// Output 向默认输出通道输出一个包含简单消息的标准日志模板。
// 在每条消息末尾写入一个换行符。
func (l *Logger) Output(lvl Level, calldepth int, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.stdEnabled {
		return
	}
	msg := l.formatLogMessage(calldepth+1, message)

	var err error
	switch lvl {
	case ERROR:
		_, err = l.errWriter.Write(msg)
	default:
		_, err = l.writer.Write(msg)
	}
	if err != nil {
		panic(err)
	}
}

// PrintAuthf 将身份验证信息写入日志记录器。需要一个 http.Request 来记录请求详情。
// 其余参数的处理方式与 fmt.Sprintf 相同。在每条消息末尾写入一个换行符。
func (l *Logger) PrintAuthf(username string, req *http.Request, status AuthStatus, format string, a ...interface{}) {
	if !l.authEnabled {
		return
	}

	now := time.Now()

	if username == "" {
		username = "-"
	}

	client := l.getClientFunc(req)

	l.mu.Lock()
	defer l.mu.Unlock()

	scope := middlewareapi.GetRequestScope(req)
	err := l.authTemplate.Execute(l.writer, authLogMessageData{
		Client:        client,
		Host:          requestutil.GetRequestHost(req),
		Protocol:      req.Proto,
		RequestID:     scope.RequestID,
		RequestMethod: req.Method,
		Timestamp:     FormatTimestamp(now),
		UserAgent:     fmt.Sprintf("%q", req.UserAgent()),
		Username:      username,
		Status:        string(status),
		Message:       fmt.Sprintf(format, a...),
	})
	if err != nil {
		panic(err)
	}

	_, err = l.writer.Write([]byte("\n"))
	if err != nil {
		panic(err)
	}
}

// PrintReq 使用请求的 http.Request、URL 和时间戳将请求详细信息写入 Logger。
// 在每条消息末尾写入一个换行符。
func (l *Logger) PrintReq(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
	if !l.reqEnabled {
		return
	}

	if _, ok := l.excludePaths[url.Path]; ok {
		return
	}

	duration := float64(time.Since(ts)) / float64(time.Second)

	if username == "" {
		username = "-"
	}

	if upstream == "" {
		upstream = "-"
	}

	if url.User != nil && username == "-" {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}

	client := l.getClientFunc(req)

	l.mu.Lock()
	defer l.mu.Unlock()

	scope := middlewareapi.GetRequestScope(req)
	err := l.reqTemplate.Execute(l.writer, reqLogMessageData{
		Client:          client,
		Host:            requestutil.GetRequestHost(req),
		Protocol:        req.Proto,
		RequestID:       scope.RequestID,
		RequestDuration: fmt.Sprintf("%0.3f", duration),
		RequestMethod:   req.Method,
		RequestURI:      fmt.Sprintf("%q", url.RequestURI()),
		ResponseSize:    fmt.Sprintf("%d", size),
		StatusCode:      fmt.Sprintf("%d", status),
		Timestamp:       FormatTimestamp(ts),
		Upstream:        upstream,
		UserAgent:       fmt.Sprintf("%q", req.UserAgent()),
		Username:        username,
	})
	if err != nil {
		panic(err)
	}

	_, err = l.writer.Write([]byte("\n"))
	if err != nil {
		panic(err)
	}
}

// GetFileLineString 将找到调用者的文件和行号，并考虑到调用深度以在堆栈中向上迭代，从而找到非日志记录调用位置。
func (l *Logger) GetFileLineString(calldepth int) string {
	var file string
	var line int
	var ok bool

	_, file, line, ok = runtime.Caller(calldepth)
	if !ok {
		file = "???"
		line = 0
	}

	if l.flag&Lshortfile != 0 {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
	}

	return fmt.Sprintf("%s:%d", file, line)
}

// FormatTimestamp 返回格式化后的时间戳。
func (l *Logger) FormatTimestamp(ts time.Time) string {
	if l.flag&LUTC != 0 {
		ts = ts.UTC()
	}

	return ts.Format("2006/01/02 15:04:05")
}

// Flags 返回日志记录器的输出标志。
func (l *Logger) Flags() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flag
}

// SetFlags 设置日志记录器的输出标志。
func (l *Logger) SetFlags(flag int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flag = flag
}

// SetStandardEnabled 启用或禁用标准日志记录。
func (l *Logger) SetStandardEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdEnabled = e
}

// SetErrToInfo 启用或禁用向错误写入器而不是默认写入器的错误日志记录。
func (l *Logger) SetErrToInfo(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e {
		l.errWriter = l.writer
	} else {
		l.errWriter = os.Stderr
	}
}

// SetAuthEnabled 启用或禁用身份验证日志记录。
func (l *Logger) SetAuthEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authEnabled = e
}

// SetReqEnabled 启用或禁用请求日志记录。
func (l *Logger) SetReqEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqEnabled = e
}

// SetGetClientFunc 设置用于确定明显“真实客户端 IP”的函数。
func (l *Logger) SetGetClientFunc(f GetClientFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.getClientFunc = f
}

// SetExcludePaths 设置要从日志记录中排除的路径。
func (l *Logger) SetExcludePaths(s []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.excludePaths = make(map[string]struct{})
	for _, p := range s {
		l.excludePaths[p] = struct{}{}
	}
}

// SetStandardTemplate 设置标准日志记录的模板。
func (l *Logger) SetStandardTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdLogTemplate = template.Must(template.New("std-log").Parse(t))
}

// SetAuthTemplate 设置身份验证日志记录的模板。
func (l *Logger) SetAuthTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authTemplate = template.Must(template.New("auth-log").Parse(t))
}

// SetReqTemplate 设置请求日志记录的模板。
func (l *Logger) SetReqTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqTemplate = template.Must(template.New("req-log").Parse(t))
}

// These functions utilize the standard logger.

// FormatTimestamp 为标准日志记录器返回格式化后的时间戳。
func FormatTimestamp(ts time.Time) string {
	return std.FormatTimestamp(ts)
}

// Flags 返回标准日志记录器的输出标志。
func Flags() int {
	return std.Flags()
}

// SetFlags 设置标准日志记录器的输出标志。
func SetFlags(flag int) {
	std.SetFlags(flag)
}

// SetOutput 设置标准日志记录器默认通道的输出目标。
func SetOutput(w io.Writer) {
	std.mu.Lock()
	defer std.mu.Unlock()
	std.writer = w
}

// SetErrOutput 设置标准日志记录器错误通道的输出目标。
func SetErrOutput(w io.Writer) {
	std.mu.Lock()
	defer std.mu.Unlock()
	std.errWriter = w
}

// SetStandardEnabled 启用或禁用标准日志记录器的标准日志记录。
func SetStandardEnabled(e bool) {
	std.SetStandardEnabled(e)
}

// SetErrToInfo 启用或禁用向输出写入器而不是错误写入器的错误日志记录。
func SetErrToInfo(e bool) {
	std.SetErrToInfo(e)
}

// SetAuthEnabled 启用或禁用标准日志记录器的身份验证日志记录。
func SetAuthEnabled(e bool) {
	std.SetAuthEnabled(e)
}

// SetReqEnabled 启用或禁用标准日志记录器的请求日志记录。
func SetReqEnabled(e bool) {
	std.SetReqEnabled(e)
}

// SetGetClientFunc 为标准日志记录器设置用于确定由反向代理设置的明显 IP 地址的函数。
func SetGetClientFunc(f GetClientFunc) {
	std.SetGetClientFunc(f)
}

// SetExcludePaths 设置要从日志记录中排除的路径，例如：健康检查。
func SetExcludePaths(s []string) {
	std.SetExcludePaths(s)
}

// SetStandardTemplate 为标准日志记录器设置标准日志记录的模板。
func SetStandardTemplate(t string) {
	std.SetStandardTemplate(t)
}

// SetAuthTemplate 为标准日志记录器设置身份验证日志记录的模板。
func SetAuthTemplate(t string) {
	std.SetAuthTemplate(t)
}

// SetReqTemplate 为标准日志记录器设置请求日志记录的模板。
func SetReqTemplate(t string) {
	std.SetReqTemplate(t)
}

// Print 调用 Output 以打印到标准日志记录器。
// 参数的处理方式与 fmt.Print 相同。
func Print(v ...interface{}) {
	std.Output(DEFAULT, 2, fmt.Sprint(v...))
}

// Printf 调用 Output 以打印到标准日志记录器。
// 参数的处理方式与 fmt.Printf 相同。
func Printf(format string, v ...interface{}) {
	std.Output(DEFAULT, 2, fmt.Sprintf(format, v...))
}

// Println 调用 Output 以打印到标准日志记录器。
// 参数的处理方式与 fmt.Println 相同。
func Println(v ...interface{}) {
	std.Output(DEFAULT, 2, fmt.Sprintln(v...))
}

// Error 调用 Output 以打印到标准日志记录器的错误通道。
// 参数的处理方式与 fmt.Print 相同。
func Error(v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprint(v...))
}

// Errorf 调用 Output 以打印到标准日志记录器的错误通道。
// 参数的处理方式与 fmt.Printf 相同。
func Errorf(format string, v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprintf(format, v...))
}

// Errorln 调用 Output 以打印到标准日志记录器的错误通道。
// 参数的处理方式与 fmt.Println 相同。
func Errorln(v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprintln(v...))
}

// Fatal 等同于 Print() 之后调用 os.Exit(1)。
func Fatal(v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf 等同于 Printf() 之后调用 os.Exit(1)。
func Fatalf(format string, v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Fatalln 等同于 Println() 之后调用 os.Exit(1)。
func Fatalln(v ...interface{}) {
	std.Output(ERROR, 2, fmt.Sprintln(v...))
	os.Exit(1)
}

// Panic 等同于 Print() 之后调用 panic()。
func Panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	std.Output(ERROR, 2, s)
	panic(s)
}

// Panicf 等同于 Printf() 之后调用 panic()。
func Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	std.Output(ERROR, 2, s)
	panic(s)
}

// Panicln 等同于 Println() 之后调用 panic()。
func Panicln(v ...interface{}) {
	s := fmt.Sprintln(v...)
	std.Output(ERROR, 2, s)
	panic(s)
}

// PrintAuthf 将身份验证详情写入标准日志记录器。
// 参数的处理方式与 fmt.Printf 相同。
func PrintAuthf(username string, req *http.Request, status AuthStatus, format string, a ...interface{}) {
	std.PrintAuthf(username, req, status, format, a...)
}

// PrintReq 将请求详情写入标准日志记录器。
func PrintReq(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
	std.PrintReq(username, upstream, req, url, ts, status, size)
}

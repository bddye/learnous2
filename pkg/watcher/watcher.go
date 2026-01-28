package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// WatchFileForUpdates 在磁盘上的文件更新时执行操作
func WatchFileForUpdates(filename string, done <-chan bool, action func()) error {
	filename = filepath.Clean(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher for '%s': %s", filename, err)
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case <-done:
				logger.Printf("shutting down watcher for: %s", filename)
				return
			case event := <-watcher.Events:
				filterEvent(watcher, event, filename, action)
			case err = <-watcher.Errors:
				logger.Errorf("error watching '%s': %s", filename, err)
			}
		}
	}()
	if err := watcher.Add(filename); err != nil {
		return fmt.Errorf("failed to add '%s' to watcher: %v", filename, err)
	}
	logger.Printf("watching '%s' for updates", filename)

	return nil
}

// Filter file operations based on the events sent by the watcher.
// 当满足以下条件时执行 action() 函数：
//   - 文件的真实路径已更改（如 Kubernetes ConfigMap/Secret）
//   - 文件被修改或创建
func filterEvent(watcher *fsnotify.Watcher, event fsnotify.Event, filename string, action func()) {
	switch filepath.Clean(event.Name) == filename {
	// 在 Kubernetes 中，文件路径是一个符号链接，因此当 ConfigMap/Secret 被替换时，我们应该采取行动。
	case event.Op&fsnotify.Remove != 0:
		logger.Printf("watching interrupted on event: %s", event)
		WaitForReplacement(filename, event.Op, watcher)
		action()
	case event.Op&(fsnotify.Create|fsnotify.Write) != 0:
		logger.Printf("reloading after event: %s", event)
		action()
	}
}

// WaitForReplacement 等待文件在磁盘上存在，然后开始监听该文件
func WaitForReplacement(filename string, op fsnotify.Op, watcher *fsnotify.Watcher) {
	const sleepInterval = 50 * time.Millisecond

	// 避免在 fsnotify.Remove 之前发生 fsnotify.Chmod 时出现竞争。
	if op&fsnotify.Chmod != 0 {
		time.Sleep(sleepInterval)
	}
	for {
		if _, err := os.Stat(filename); err == nil {
			if err := watcher.Add(filename); err == nil {
				logger.Printf("watching resumed for '%s'", filename)
				return
			}
		}
		time.Sleep(sleepInterval)
	}
}

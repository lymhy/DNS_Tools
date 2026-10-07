//go:build windows

package main

import (
	"os"
	"syscall"
)

// init 把控制台输出码页切到 UTF-8，避免双击运行时中文乱码。
func init() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)
}

// isTerminalIn 报告 stdin 是否为控制台（区分双击/交互运行与管道重定向）。
func isTerminalIn() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

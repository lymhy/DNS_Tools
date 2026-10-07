//go:build windows

package main

import (
	"os"
	"syscall"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleOutputCP = kernel32.NewProc("GetConsoleOutputCP")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

// origOutputCP 记录启动时的控制台输出码页，退出时还原。
// 不还原的话，调用方（例如 dnspick.bat）会被留在 UTF-8 码页下，
// 它随后用 GBK 写的中文就会被当成 UTF-8 显示成乱码。
var origOutputCP uint32

// init 把控制台输出码页切到 UTF-8，避免双击运行时中文乱码。
func init() {
	r, _, _ := procGetConsoleOutputCP.Call()
	origOutputCP = uint32(r)
	procSetConsoleOutputCP.Call(65001)
}

// restoreConsoleOutputCP 把控制台输出码页还原为启动时的值。
// 必须在所有中文输出（含"按 Enter 键退出"提示）之后调用。
// 取不到原码页时（0 表示当前进程没有控制台，如管道/重定向）不做任何事。
func restoreConsoleOutputCP() {
	if origOutputCP != 0 {
		procSetConsoleOutputCP.Call(uintptr(origOutputCP))
	}
}

// isTerminalIn 报告 stdin 是否为控制台（区分双击/交互运行与管道重定向）。
func isTerminalIn() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
//go:build !windows

package main

import "os"

// restoreConsoleOutputCP 在非 Windows 上没有控制台输出码页，空实现。
func restoreConsoleOutputCP() {}

func isTerminalIn() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

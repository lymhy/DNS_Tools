//go:build !windows

package report

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func runtimeName() string { return runtime.GOOS }

// serviceNameFor 把 BSD 接口名（如 en0）换成 networksetup 需要的网络服务名（如 Wi-Fi）。
// 直接拿 en0 当服务名，networksetup 会报 "The parameters were not valid"。
func serviceNameFor(ifName string) string {
	if runtime.GOOS != "darwin" {
		return ifName
	}
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return ifName
	}
	port := ""
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "Hardware Port:"); ok {
			port = strings.TrimSpace(v)
			continue
		}
		if v, ok := strings.CutPrefix(line, "Device:"); ok {
			if strings.TrimSpace(v) == ifName && port != "" {
				return port
			}
		}
	}
	return ifName
}

// apply 写入系统 DNS：macOS 走 networksetup，Linux 直接改 /etc/resolv.conf（先备份）。
func apply(servers []string, ifName string) error {
	if len(servers) == 0 {
		return fmt.Errorf("没有可写入的 DNS 服务器地址")
	}
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("networksetup", append([]string{"-setdnsservers", serviceNameFor(ifName)}, servers...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}

	// Linux：resolv.conf 常常是 systemd-resolved 的符号链接，直接 Create 会顺着链接
	// 截断它指向的文件，所以符号链接一律拒绝并提示正确做法。
	fi, err := os.Lstat("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("读取 /etc/resolv.conf 失败: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink("/etc/resolv.conf")
		return fmt.Errorf("/etc/resolv.conf 是指向 %s 的符号链接（通常由 systemd-resolved 管理），本工具不改写它；请用上面打印的 nmcli 命令或 resolvectl", target)
	}
	old, err := os.ReadFile("/etc/resolv.conf")
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取 /etc/resolv.conf 失败: %w", err)
	}
	backup := "/etc/resolv.conf.dnspick.bak"
	if err := os.WriteFile(backup, old, 0o644); err != nil {
		return fmt.Errorf("备份到 %s 失败，已中止（未修改 /etc/resolv.conf）: %w", backup, err)
	}

	var sb strings.Builder
	for _, s := range servers {
		fmt.Fprintf(&sb, "nameserver %s\n", s)
	}
	// 同目录临时文件 + rename：写到一半失败也不会留下半个 resolv.conf。
	tmp, err := os.CreateTemp(filepath.Dir("/etc/resolv.conf"), ".resolv.conf.dnspick-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败（写 /etc 需要 root）: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), "/etc/resolv.conf"); err != nil {
		return fmt.Errorf("写入 /etc/resolv.conf 失败（需要 root）: %w", err)
	}
	fmt.Printf("已备份原配置到 %s\n", backup)
	return nil
}

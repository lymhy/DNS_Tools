//go:build windows

package report

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func runtimeName() string { return runtime.GOOS }

// serviceNameFor 在 Windows 上接口别名本身就是网络服务名，原样返回。
func serviceNameFor(ifName string) string { return ifName }

// apply 实际写入 Windows 系统 DNS（先备份当前配置）。
func apply(servers []string, ifName string) error {
	if len(servers) == 0 {
		return fmt.Errorf("没有可写入的 DNS 服务器地址")
	}
	// 用 JSON 而不是 Format-Table 文本：表格会截断，而 ServerAddresses 本身是数组，
	// 截断后的"备份"根本没法还原。备份必须在改配置之前成功，否则用户失去回滚依据。
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4").Output()
	if err != nil {
		return fmt.Errorf("备份当前 DNS 失败，已中止（未修改任何配置）: %w", err)
	}
	backup := backupPath()
	if err := os.WriteFile(backup, out, 0o600); err != nil {
		return fmt.Errorf("写入备份文件 %s 失败，已中止（未修改任何配置）: %w", backup, err)
	}
	fmt.Printf("已备份当前 DNS 配置到 %s\n", backup)

	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses %s`, ifName, strings.Join(servers, ",")))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// backupPath 把备份写进用户配置目录并带时间戳：写在工作目录的固定文件名
// 会被下一次运行覆盖，用户在项目目录里跑一次就丢一次历史。
func backupPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "dnspick")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "dns-backup-"+time.Now().Format("20060102-150405")+".json")
}

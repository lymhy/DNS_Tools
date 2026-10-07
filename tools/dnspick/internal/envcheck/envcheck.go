// Package envcheck 实现阶段0环境自检：系统 DNS、IPv6、代理/TUN、公网 IP、出口网卡。
package envcheck

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Info 汇总环境自检结果。
type Info struct {
	InterfaceName string   // 默认出口网卡名
	InterfaceIP   net.IP   // 该网卡 IPv4（用于绑定）
	SystemDNS     []string // 系统/运营商 DNS（基线候选）
	SystemDNSFrom string   // 这些 DNS 是从哪个网卡读到的
	IPv6OK        bool
	PublicIP      string
	ProxyDetected bool
	TUNDetected   bool
	TUNIface      string // 命中且正在接管上网流量的虚拟网卡名（TUNDetected 为真时有值）
	Warnings      []string
}

// Check 执行全部自检；任何单项失败都不阻断（对应字段留空并记 warning）。
func Check() *Info {
	info := &Info{}
	info.InterfaceName, info.InterfaceIP = defaultInterface()
	info.SystemDNS, info.SystemDNSFrom = systemDNS(info.InterfaceName)
	info.IPv6OK = checkIPv6()
	info.PublicIP = publicIP()
	info.ProxyDetected = checkProxy()
	info.TUNDetected, info.TUNIface = checkTUN(info.InterfaceName)

	if info.ProxyDetected {
		info.Warnings = append(info.Warnings, "检测到系统代理已开启：所有测速结果可能失真，建议关闭代理后重测！")
	}
	if info.TUNDetected {
		info.Warnings = append(info.Warnings, fmt.Sprintf("检测到虚拟网卡 %s 正在接管上网流量（可能是代理的 tun 模式）：全部流量被接管，测速结果不可信，建议关闭后重测！", info.TUNIface))
	}
	if info.PublicIP == "" {
		info.Warnings = append(info.Warnings, "无法获取公网 IP，ECS 支持检测将跳过。")
	}
	if !info.IPv6OK {
		info.Warnings = append(info.Warnings, "IPv6 不可用，跳过 IPv6 DNS 测试。")
	}
	if len(info.SystemDNS) == 0 {
		info.Warnings = append(info.Warnings, "未能读取系统 DNS：缺少“本地运营商基线”对比行，就近性结论会弱一些。")
	}
	return info
}

// Interface 描述一块本机网卡，供 --list-interfaces 展示、也供用户按名字挑网卡。
type Interface struct {
	Name string
	Up   bool
	IPv4 []string
	IPv6 []string
}

// Interfaces 列出所有网卡及其地址，按名字排序。
func Interfaces() []Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		it := Interface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipn.IP.To4(); v4 != nil {
				it.IPv4 = append(it.IPv4, v4.String())
			} else if ipn.IP.To16() != nil {
				it.IPv6 = append(it.IPv6, ipn.IP.String())
			}
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// defaultInterface 通过拨号到公网地址探测默认路由网卡。
func defaultInterface() (string, net.IP) {
	conn, err := net.DialTimeout("udp", "223.5.5.5:53", 2*time.Second)
	if err != nil {
		return "", nil
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", nil
	}
	localIP := localAddr.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", localIP
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(localIP) {
				return ifc.Name, localIP
			}
		}
	}
	return "", localIP
}

// systemDNS 读取系统 DNS，并记录来源网卡。
// Windows 上优先取出**出口网卡**的 DNS：注册表里常留着 VPN/虚拟网卡的旧配置，
// 拿第一个"有 DNS 的适配器"很容易读到 singbox_tun(172.18.0.2) 这类残留。
func systemDNS(ifName string) ([]string, string) {
	switch runtime.GOOS {
	case "windows":
		if dns := windowsDNSForAlias(ifName); len(dns) > 0 {
			return dns, ifName
		}
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | Select-Object -First 1) | ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }").Output()
		if err != nil {
			return nil, ""
		}
		s := strings.TrimSpace(string(out))
		if i := strings.IndexByte(s, '|'); i >= 0 {
			return splitDNS(s[i+1:]), strings.TrimSpace(s[:i])
		}
		return splitDNS(s), ""
	case "darwin":
		out, err := exec.Command("scutil", "--dns").Output()
		if err != nil {
			return nil, ""
		}
		return parseScutilDNS(string(out)), "scutil --dns"
	default:
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return nil, ""
		}
		return parseResolvConf(string(data)), "/etc/resolv.conf"
	}
}

// placeholderDNS 判断是否是 Windows"DNS 自动获取"时填的占位地址
// （fec0:0:0:ffff::/48 站点本地默认值）。它们不是真的 DNS，列出来只会干扰判断。
func placeholderDNS(addr string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(addr)), "fec0:0:0:ffff::")
}

// filterDNS 去掉占位地址；全是占位地址时返回空，表示"这块网卡其实没配 DNS"。
func filterDNS(in []string) []string {
	var out []string
	for _, a := range in {
		if !placeholderDNS(a) {
			out = append(out, a)
		}
	}
	return out
}

// windowsDNSForAlias 读取指定适配器别名上的 IPv4 DNS（仅 Windows）。
// 别名来自网卡名，直接拼进 PowerShell 单引号字符串，故先把单引号转义。
func windowsDNSForAlias(alias string) []string {
	if alias == "" {
		return nil
	}
	q := strings.ReplaceAll(alias, "'", "''")
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses -and $_.InterfaceAlias -eq '"+q+"'} | Select-Object -First 1).ServerAddresses -join ','").Output()
	if err != nil {
		return nil
	}
	return filterDNS(splitDNS(string(out)))
}

// SystemDNSFor 读取指定网卡上的系统 DNS，用于 --interface 覆盖默认出口网卡的场景：
// 基线和 --apply 的目标都该跟着用户选的那块网卡走，否则读到的还是自动探测网卡的 DNS。
// Windows 上严格只认这块网卡（不回落"第一个有 DNS 的适配器"）；其他平台的系统 DNS
// 是全局配置，不存在"哪块网卡的 DNS"这回事，直接返回全局结果。
func SystemDNSFor(ifName string) ([]string, string) {
	if ifName == "" {
		return systemDNS("")
	}
	if runtime.GOOS != "windows" {
		return systemDNS(ifName)
	}
	if dns := windowsDNSForAlias(ifName); len(dns) > 0 {
		return dns, ifName
	}
	return nil, ifName
}

// InterfaceDNS 返回每块网卡上配置的 DNS（键为网卡名），供 --list-interfaces 展示。
// 只有 Windows 能按适配器分别读取；其他平台返回 nil，调用方自行回落到全局 DNS。
func InterfaceDNS() map[string][]string {
	if runtime.GOOS != "windows" {
		return nil
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Where-Object {$_.ServerAddresses} | ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }").Output()
	if err != nil {
		return nil
	}
	return parseAliasDNS(string(out))
}

// parseAliasDNS 解析 "网卡名|地址1,地址2" 行；同一网卡的 IPv4/IPv6 两行会合并去重，
// Windows 的占位 DNS 会被丢掉（否则每块网卡都显示一串 fec0:0:0:ffff::1）。
func parseAliasDNS(text string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		i := strings.IndexByte(line, '|')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		for _, a := range filterDNS(splitDNS(line[i+1:])) {
			dup := false
			for _, have := range out[name] {
				if have == a {
					dup = true
					break
				}
			}
			if !dup {
				out[name] = append(out[name], a)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitDNS(s string) []string {
	var out []string
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseResolvConf 解析 resolv.conf：字段分隔可能是空格也可能是 tab（strings.Fields 两种都吃），
// 并去掉行内注释。
func parseResolvConf(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// parseScutilDNS 解析 macOS `scutil --dns` 的行，形如：
//
//	nameserver[0] : 192.168.1.1
//
// 原来按 "nameserver[" 前缀切开再取第一个字段，会得到 "0]"。
func parseScutilDNS(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		i := strings.IndexByte(line, ']')
		if i < 0 {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[i+1:]), ":"))
		if f := strings.Fields(rest); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// checkIPv6 用一次真实的 TCP 连接判断 IPv6 出口是否可用。
// 只做 UDP dial 是不够的：UDP 是"无连接"的，只要有 IPv6 路由就会成功返回，
// 哪怕根本发不出去、也没有 IPv6 出口。
func checkIPv6() bool {
	for _, target := range []string{"[2402:4e00::]:53", "[2001:4860:4860::8888]:53"} {
		if conn, err := net.DialTimeout("tcp6", target, 2*time.Second); err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// publicIP 通过 myip 类接口获取（多源 fallback）。
func publicIP() string {
	urls := []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://myip.ipip.net",
	}
	// 显式不使用环境变量里的代理：走代理拿到的"公网 IP"是代理出口的地址，
	// 拿它做 ECS/归属判断会把结论带偏。
	hc := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	for _, u := range urls {
		resp, err := hc.Get(u)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		// 完整读完（并限长）：只 Read 一次拿到的可能是半截，解析不出 IP 就白跑一个源。
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if ip := extractIP(string(body)); ip != "" {
			return ip
		}
	}
	return ""
}

func extractIP(s string) string {
	for _, f := range strings.Fields(s) {
		if ip := net.ParseIP(strings.Trim(f, "\"")); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// checkProxy 检查常见代理环境变量与系统代理注册表项。
func checkProxy() bool {
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := os.Getenv(k); v != "" {
			return true
		}
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("reg", "query",
			"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable").Output()
		if err == nil && strings.Contains(string(out), "0x1") {
			return true
		}
	}
	return false
}

// tunTakesOver 判定命中的虚拟网卡是否真的接管了上网流量——依据它是不是默认路由出口网卡。
// exitIface 为空（公网拨号失败、拿不到默认路由）时无法排除，保守判真（宁可多提醒）。
// 这一点是必要的：Tailscale 这类虚拟网卡只要服务在跑就一直 Up，但不开 exit node 时
// 只接管 tailnet 内网，公网流量仍走物理网卡——只按网卡名报警会把这种情况误判成"全部流量被接管"。
func tunTakesOver(ifaceName, exitIface string) bool {
	if exitIface == "" {
		return true
	}
	return strings.EqualFold(ifaceName, exitIface)
}

// checkTUN 检测 TUN/TAP/utun/WireGuard 等虚拟网卡，返回（是否接管上网流量, 网卡名）。
// 只认"已启用"的网卡：残留的、已断开的适配器不影响实际流量，报出来会让用户去关一个
// 根本没在工作（或根本关不掉）的东西；再叠加 tunTakesOver 的默认路由校验，进一步过滤
// "网卡在、但没接管公网"的误报（如 Tailscale 未开 exit node）。
func checkTUN(exitIface string) (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		for _, kw := range []string{"tun", "tap", "wireguard", "wintun", "utun", "clash", "singbox", "sing-box", "mihomo", "tailscale"} {
			if !strings.Contains(name, kw) {
				continue
			}
			// 排除常见的非 TUN 误报
			if strings.Contains(name, "adapter") && kw == "tap" {
				continue
			}
			if !tunTakesOver(ifc.Name, exitIface) {
				fmt.Fprintf(os.Stderr, "[envcheck] 虚拟网卡 %s（%s）未接管默认路由（上网走 %s），不影响本次结果\n",
					ifc.Name, tunHint(ifc), exitIface)
				continue
			}
			fmt.Fprintf(os.Stderr, "[envcheck] 疑似虚拟网卡: %s（%s）\n", ifc.Name, tunHint(ifc))
			return true, ifc.Name
		}
	}
	return false, ""
}

// tunHint 给出网卡上第一个可用的地址，便于用户判断是哪一个网络。
func tunHint(ifc net.Interface) string {
	addrs, err := ifc.Addrs()
	if err != nil || len(addrs) == 0 {
		return "无地址"
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

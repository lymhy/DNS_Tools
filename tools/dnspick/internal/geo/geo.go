// Package geo 封装 ip2region 离线 IP 归属库（xdb，本地 vendor），提供省市查询；库缺失时优雅降级。
package geo

import (
	"net"
	"os"
	"strings"
	"sync"

	"dnspick/internal/geo/xdb"
)

// Locator 查询 IP 归属。
type Locator struct {
	mu    sync.Mutex
	s     *xdb.Searcher
	avail bool
}

// New 打开 xdb 文件；不存在或损坏时返回可用性为 false 的 Locator（不报错，方便降级）。
func New(xdbPath string) *Locator {
	l := &Locator{}
	if _, err := os.Stat(xdbPath); err != nil {
		return l
	}
	s, err := xdb.NewWithFileOnly(xdb.IPv4, xdbPath)
	if err != nil {
		return l
	}
	l.s = s
	l.avail = true
	return l
}

// Available 报告离线库是否可用。
func (l *Locator) Available() bool { return l.avail }

// Region 返回 "国家|区域|省份|城市|ISP" 原始串；不可用返回空。
func (l *Locator) Region(ip string) string {
	if !l.avail {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := l.s.Search(ip)
	if err != nil {
		return ""
	}
	return s
}

// Province 返回省份名（如 "广东省"）；解析失败返回 ""。
func (l *Locator) Province(ip string) string {
	s := l.Region(ip)
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "|")
	if len(parts) >= 3 && parts[2] != "0" {
		return parts[2]
	}
	return ""
}

// Describe 返回给报告用的简短归属描述，如 "中国 广东省 深圳 电信"。
// 私网/环回/保留地址在 ip2region 里只会得到 "Reserved" 之类的占位值（甚至重复两遍），
// 这里先按网段判成"内网/本机/保留地址"，比 "Reserved Reserved" 好懂。
func (l *Locator) Describe(ip string) string {
	if p := net.ParseIP(strings.TrimSpace(ip)); p != nil {
		switch {
		case p.IsLoopback():
			return "本机"
		case p.IsUnspecified() || p.IsMulticast():
			return "保留地址"
		case p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast():
			return "内网"
		}
	}
	s := l.Region(ip)
	if s == "" {
		return "未知"
	}
	parts := strings.SplitN(s, "|", 5)
	fields := []string{}
	for i, p := range parts {
		if p != "0" && i != 1 && strings.TrimSpace(p) != "" {
			fields = append(fields, p)
		}
	}
	if len(fields) == 0 {
		return "未知"
	}
	joined := strings.Join(fields, " ")
	if strings.Contains(strings.ToLower(joined), "reserved") {
		return "保留地址"
	}
	return joined
}

// Summary 打印库状态。
func (l *Locator) Summary() string {
	if l.avail {
		return "ip2region 离线库已加载"
	}
	return "ip2region 未找到（就近性按 TCP 延迟评分，无同省率）"
}

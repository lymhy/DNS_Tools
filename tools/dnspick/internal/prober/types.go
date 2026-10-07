// Package prober 封装各协议的 DNS 查询与交叉轮询调度。
package prober

import (
	"net"
	"sync"
	"time"
)

// Protocol 是候选 DNS 的接入协议。
type Protocol string

const (
	UDP  Protocol = "udp"  // IPv4 UDP 53
	UDP6 Protocol = "udp6" // IPv6 UDP 53
	DOH  Protocol = "doh"  // DoH 443
	DOT  Protocol = "dot"  // DoT 853
)

// Endpoint 是一次测评的最小单元：某个 DNS 的某个协议入口。
type Endpoint struct {
	Server   string // 展示名，如 "腾讯DNSPod"
	Address  string // udp: IP；doh: URL；dot: host:port
	Proto    Protocol
	Region   string // "境内"/"境外"/"本地基线"
	IsSystem bool   // 运营商/系统 DNS 基线
}

// Label 返回端点展示标签（IP 或精简 DoH 域名）。
func (e Endpoint) Label() string {
	if e.Proto == UDP || e.Proto == UDP6 {
		return e.Address
	}
	if e.Proto == DOH {
		return e.Address + " (DoH)"
	}
	return e.Address + " (DoT)"
}

// Metrics 汇总一个端点的全部测量结果（checker 各阶段往里填）。
type Metrics struct {
	CacheP50 float64 // ms，缓存延迟 P50
	CacheP95 float64 // ms
	RecP50   float64 // ms，递归延迟 P50（完整模式）
	Success  float64 // 0~1
	Queries  int
	Failed   int

	NXDomainHijack    bool
	TransparentHijack bool
	EchoIP            string

	PollutionHits     int
	PollutionTotal    int
	ConsistencyIssues int

	CDNIPs           []string
	SameProvinceRate float64 // 0~1，geo 不可用时为 -1
	TCPMedian        float64 // ms
	TTFBMedian       float64 // ms（完整模式）
	ECSSupported     bool

	SystemDNS string // 对基线端点记录

	// 原始样本（不导出，报告不需要）
	cache []float64
	rec   []float64
}

func newMetrics() *Metrics {
	return &Metrics{SameProvinceRate: -1}
}

// rateLimiter 保证对单个端点 QPS<=limit。
type rateLimiter struct {
	mu   sync.Mutex // 目前探测是串行的，加锁是为了将来并发探测时仍然安全
	last map[string]time.Time
	gap  time.Duration
}

func newRateLimiter(qps float64) *rateLimiter {
	return &rateLimiter{last: map[string]time.Time{}, gap: time.Duration(float64(time.Second) / qps)}
}

func (r *rateLimiter) wait(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[key]; ok {
		if d := time.Since(t); d < r.gap {
			time.Sleep(r.gap - d)
		}
	}
	r.last[key] = time.Now()
}

// Querier 是协议层的最小查询接口：向端点查询 name 的 A 记录，返回 IP 列表与 RTT。
type Querier interface {
	QueryA(ep Endpoint, name string, timeout time.Duration) (ips []string, rtt time.Duration, err error)
	QueryTXT(ep Endpoint, name string, timeout time.Duration) (txt []string, rtt time.Duration, err error)
	QueryNSViaTCP(name string, timeout time.Duration) (ips []string, err error) // 直接问权威 NS（TCP 53），用于污染比对
	QueryWithECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) (ips []string, rtt time.Duration, err error)
}

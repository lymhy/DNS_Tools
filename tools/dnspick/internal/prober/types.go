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

	// ── 统计口径（第 2 条）──
	SampleN     int     // 有效样本数（不含热身）
	CacheMean   float64 // ms，缓存延迟均值
	CacheStdDev float64 // ms，样本标准差（n-1）
	CacheCI95   float64 // ms，均值 95% 置信区间半宽
	RecCI95     float64 // ms，递归延迟均值 95% CI 半宽

	// ── 丢包率（第 7 条）──
	// 用"首次尝试"统计：QueryA 的失败重试会掩盖首次丢包。
	Attempts   int
	FirstFail  int
	PacketLoss float64 // 0~1 = FirstFail/Attempts

	NXDomainHijack    bool
	TransparentHijack bool
	EchoIP            string

	PollutionHits     int
	PollutionTotal    int
	PollutionSample   []string // 一次被判为污染的答案，作为证据留存
	ConsistencyIssues int

	CDNIPs           []string
	SameProvinceRate float64 // 0~1，geo 不可用时为 -1
	TCPMedian        float64 // ms
	TTFBMedian       float64 // ms（完整模式）
	ECSSupported     bool

	// ── DNSSEC（第 7 条）──
	DNSSECAD     bool // 应答 AD=1，解析器声称做了验证
	DNSSECRRSIG  bool // 应答含 RRSIG（上游有签名）
	DNSSECStrict bool // 对签名失效域名返回 SERVFAIL，说明真的在验证

	// ── NSID / CHAOS（第 7 条）──
	NSID         string // RFC 5001 NSID（hex 字符串），空 = 不支持
	NSIDShared   bool   // 与另一个"服务器名"返回同一 NSID → 很可能是同一解析器/代理
	ChaosVersion string // CHAOS version.bind / hostname.bind

	// ── 双栈（第 7 条）──
	SupportsAAAA bool    // 解析器正常应答 AAAA
	AAAAFailRate float64 // 0~1，AAAA 查询中 SERVFAIL/超时的比例
	PreferredV6  int     // -1 倾向 v4 / 0 相当 / 1 倾向 v6

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

// DNSSECReply 是一次带 DO 位查询的可判定结果。
type DNSSECReply struct {
	AD      bool     // 应答 AuthenticatedData 位
	RRSIG   bool     // 应答中含 RRSIG 记录
	RCode   int      // dns.Rcode*；SERVFAIL 表示 DNSSEC 验证失败
	Answers []string // A/AAAA 答案（便于排查）
}

// Querier 是协议层的最小查询接口：向端点查询各类记录，返回结果与 RTT。
type Querier interface {
	QueryA(ep Endpoint, name string, timeout time.Duration) (ips []string, rtt time.Duration, err error)
	QueryAAAA(ep Endpoint, name string, timeout time.Duration) (ips []string, rtt time.Duration, err error)
	QueryTXT(ep Endpoint, name string, timeout time.Duration) (txt []string, rtt time.Duration, err error)
	QueryNSViaTCP(name string, timeout time.Duration) (ips []string, err error) // 直接问权威 NS（TCP 53），用于污染比对
	QueryWithECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) (ips []string, rtt time.Duration, err error)

	// QueryWithDO 以 DO=1 查询，返回 AD / RRSIG / Rcode，用于 DNSSEC 判定（RFC 4035）。
	QueryWithDO(ep Endpoint, name string, timeout time.Duration) (*DNSSECReply, error)
	// QueryNSID 请求 EDNS0 NSID 选项，返回 hex 字符串（RFC 5001）；空串表示解析器不支持。
	QueryNSID(ep Endpoint, timeout time.Duration) (nsidHex string, err error)
	// QueryCHAOS 以 CH 类查询 version.bind / hostname.bind（RFC 4892 实践）。
	QueryCHAOS(ep Endpoint, name string, timeout time.Duration) (txt []string, err error)
}

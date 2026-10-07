package prober

import (
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"time"
)

// Runner 贯穿整个测评流水线：持有所有端点、限速器与结果，提供统一计数的查询入口。
type Runner struct {
	Q         Querier
	Endpoints []Endpoint
	Results   map[string]*Metrics
	Full      bool
	Progress  func(format string, args ...any)
	rl        *rateLimiter
}

// NewRunner 创建调度器；qps 限速默认 5。
func NewRunner(q Querier, eps []Endpoint, full bool, log func(string, ...any)) *Runner {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Runner{
		Q:         q,
		Endpoints: eps,
		Results:   map[string]*Metrics{},
		Full:      full,
		Progress:  log,
		rl:        newRateLimiter(5),
	}
}

// Metrics 返回（并按需初始化）端点的结果集，供 checker/score/report 读写。
func (r *Runner) Metrics(ep Endpoint) *Metrics {
	return r.metricsFor(ep)
}

func (r *Runner) metricsFor(ep Endpoint) *Metrics {
	key := ep.Label()
	m, ok := r.Results[key]
	if !ok {
		m = newMetrics()
		r.Results[key] = m
	}
	return m
}

// QueryA 带限速 + 超时重试 1 次（重试失败才算失败，但失败也记账）。
func (r *Runner) QueryA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	r.rl.wait(ep.Label())
	m := r.metricsFor(ep)
	m.Queries++
	ips, rtt, err := r.Q.QueryA(ep, name, timeout)
	if err != nil {
		// 重试 1 次，同样要过限速器：否则失败端点会被连续猛打，
		// 既不符合"对单个端点 QPS<=5"的承诺，也会让本机被当成攻击源。
		r.rl.wait(ep.Label())
		ips, rtt, err = r.Q.QueryA(ep, name, timeout)
	}
	if err != nil {
		m.Failed++
		return nil, 0, err
	}
	return ips, rtt, nil
}

// QueryTXT 同样限速与计数。
func (r *Runner) QueryTXT(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	r.rl.wait(ep.Label())
	m := r.metricsFor(ep)
	m.Queries++
	txt, rtt, err := r.Q.QueryTXT(ep, name, timeout)
	if err != nil {
		m.Failed++
		return nil, 0, err
	}
	return txt, rtt, nil
}

// QueryECS 带 EDNS Client Subnet 的 A 查询，同样限速与计数。
func (r *Runner) QueryECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) ([]string, time.Duration, error) {
	r.rl.wait(ep.Label())
	m := r.metricsFor(ep)
	m.Queries++
	ips, rtt, err := r.Q.QueryWithECS(ep, name, ecsNet, timeout)
	if err != nil {
		m.Failed++
		return nil, 0, err
	}
	return ips, rtt, nil
}

// Percentile 取分位数（ms）。
func Percentile(samples []float64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	idx := int(float64(len(s)-1) * p / 100)
	return s[idx]
}

// Median 取中位数（ms）。
func Median(samples []float64) float64 {
	return Percentile(samples, 50)
}

// RandomSubdomain 生成 {uuid}.probe.<base> 用于防缓存递归测速。
func RandomSubdomain(base string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 随机源失败（极罕见）：退回时间戳，保证每次仍是不同域名。
		// 若放任全零字节流，所有端点会查同一个"随机"域名而命中缓存，
		// 测出来的递归延迟就变成缓存延迟。
		return fmt.Sprintf("%d-%d.probe.%s", time.Now().UnixNano(), time.Now().UnixMicro(), base)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	u := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return u + ".probe." + base
}

// Phase1Latency 缓存延迟与成功率：同热门域名连查 10 次（前 2 次热身），取后 8 次 P50/P95；
// 阶段内部交叉轮询端点。
func (r *Runner) Phase1Latency(hot []string, timeout time.Duration) {
	r.Progress("阶段1/3 延迟与稳定性（缓存 P50/P95、成功率）…")
	if len(hot) == 0 {
		return
	}
	// 缓存延迟必须测"同一个域名重复查询"：10 轮固定用 hot[0]，前 2 次热身丢弃。
	// 若每轮轮换域名，每次都命中不同的冷域名，测出来的其实是混合冷热的递归延迟。
	name := hot[0]
	const rounds = 10
	for i := 0; i < rounds; i++ {
		for _, ep := range r.Endpoints {
			_, rtt, err := r.QueryA(ep, name, timeout)
			if err != nil {
				continue
			}
			if i >= 2 { // 热身 2 次不计入
				m := r.metricsFor(ep)
				m.cache = append(m.cache, float64(rtt.Microseconds())/1000)
			}
		}
	}
	for _, ep := range r.Endpoints {
		m := r.metricsFor(ep)
		m.CacheP50 = Percentile(m.cache, 50)
		m.CacheP95 = Percentile(m.cache, 95)
		if m.Queries > 0 {
			m.Success = float64(m.Queries-m.Failed) / float64(m.Queries)
		}
	}
}

// Phase2Recursion 随机子域名法测递归延迟（完整模式）。
func (r *Runner) Phase2Recursion(recBases []string, rounds int, timeout time.Duration) {
	r.Progress("阶段2/3 递归延迟（随机子域名法，防缓存）…")
	if len(recBases) == 0 || rounds <= 0 {
		return
	}
	for i := 0; i < rounds; i++ {
		for _, ep := range r.Endpoints {
			name := RandomSubdomain(recBases[i%len(recBases)])
			_, rtt, err := r.QueryA(ep, name, timeout)
			if err != nil {
				continue
			}
			m := r.metricsFor(ep)
			m.rec = append(m.rec, float64(rtt.Microseconds())/1000)
		}
	}
	for _, ep := range r.Endpoints {
		m := r.metricsFor(ep)
		m.RecP50 = Median(m.rec)
	}
}

// Phase3CDN 就近性：解析 CDN 域名集 → 收集结果 IP；geo/TCP/TTFB 由 checker 完成。
func (r *Runner) Phase3ResolveCDN(domains []string, timeout time.Duration) map[string]map[string][]string {
	// key: endpoint.Label() -> domain -> ips
	out := map[string]map[string][]string{}
	r.Progress("阶段3/3 就近性（解析 %d 个 CDN 域名）…", len(domains))
	if len(domains) == 0 {
		return out
	}
	for _, d := range domains {
		for _, ep := range r.Endpoints {
			ips, _, err := r.QueryA(ep, d, timeout)
			if err != nil || len(ips) == 0 {
				continue
			}
			m := r.metricsFor(ep)
			m.CDNIPs = append(m.CDNIPs, ips...)
			if out[ep.Label()] == nil {
				out[ep.Label()] = map[string][]string{}
			}
			out[ep.Label()][d] = ips
		}
	}
	return out
}

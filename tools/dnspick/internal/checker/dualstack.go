package checker

import (
	"math"

	"dnspick/internal/config"
	"dnspick/internal/prober"
)

// aaaaFailRate 计算 AAAA 查询失败率；无查询时返回 0（不是 0%，而是"无数据"）。
func aaaaFailRate(ok, fail int) float64 {
	total := ok + fail
	if total == 0 {
		return 0
	}
	return float64(fail) / float64(total)
}

// preferredFamily 依 RFC 8305 §8 的 ResolutionDelay 判定地址族倾向：
// 两族缓存延迟相当（差 <= delayMS）时不做倾向（0）；某族明显更快才给 1(v6)/-1(v4)。
// 任一族缺样本（<=0）时返回 0，避免"没测到 IPv6"被当成"IPv4 更快"。
func preferredFamily(v4, v6 float64, delayMS int) int {
	if v4 <= 0 || v6 <= 0 {
		return 0
	}
	if math.Abs(v4-v6) <= float64(delayMS) {
		return 0
	}
	if v6 < v4 {
		return 1
	}
	return -1
}

// CheckDualStack 双栈可用性检测：
// ① 用同一端点查 AAAA，记录是否正常应答（传输失败/超时计入 AAAAFailRate）；
// ② 同一服务器名同时存在 udp 与 udp6 端点时，比较两者最快缓存 P50，
//    按 RFC 8305 §8 给出 PreferredV6（-1 倾向 v4 / 0 相当 / 1 倾向 v6）。
// 局限：底层 QueryAAAA 只回传答案与传输错误、不暴露 Rcode，故 SERVFAIL 与
// "该域名确实没有 AAAA"无法区分——AAAFailRate 统计的是传输层面的失败。
func CheckDualStack(r *prober.Runner, domains []string, th *config.Thresholds) {
	r.Progress("干净度：双栈（AAAA）可用性检测…")
	if len(domains) > 0 {
		for _, ep := range r.Endpoints {
			m := r.Metrics(ep)
			ok, fail := 0, 0
			for _, d := range domains {
				if _, _, err := r.QueryAAAA(ep, d, th.Timeout()); err != nil {
					fail++
					continue
				}
				ok++
			}
			m.AAAAFailRate = aaaaFailRate(ok, fail)
			if ok > 0 && fail == 0 {
				m.SupportsAAAA = true
			}
		}
	}

	// 双栈倾向：按服务器名取两族最快的缓存 P50 再比较（同一服务器多个入口时取最快）。
	type fam struct{ v4, v6 float64 }
	perServer := map[string]*fam{}
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		f := perServer[ep.Server]
		if f == nil {
			f = &fam{}
			perServer[ep.Server] = f
		}
		switch ep.Proto {
		case prober.UDP:
			if m.CacheP50 > 0 && (f.v4 == 0 || m.CacheP50 < f.v4) {
				f.v4 = m.CacheP50
			}
		case prober.UDP6:
			if m.CacheP50 > 0 && (f.v6 == 0 || m.CacheP50 < f.v6) {
				f.v6 = m.CacheP50
			}
		}
	}
	for _, ep := range r.Endpoints {
		if f := perServer[ep.Server]; f != nil {
			r.Metrics(ep).PreferredV6 = preferredFamily(f.v4, f.v6, th.ResolutionDelayMS)
		}
	}
}
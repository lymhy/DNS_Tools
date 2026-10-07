package checker

import (
	"strings"

	"dnspick/internal/config"
	"dnspick/internal/prober"
)

// nsidDuplicates 返回"被多个端点共用"的 NSID 集合（归一化小写）。
// NSID 是 anycast 节点身份：不同服务器名返回同一 NSID，极可能是同一个解析器/代理，
// 与透明劫持互为佐证。空串（解析器未返回 NSID）不参与统计，避免把"都未返回"误判为重复。
func nsidDuplicates(byLabel map[string]string) map[string]bool {
	count := map[string]int{}
	for _, nsid := range byLabel {
		if nsid == "" {
			continue
		}
		count[strings.ToLower(nsid)]++
	}
	out := map[string]bool{}
	for k, n := range count {
		if n > 1 {
			out[k] = true
		}
	}
	return out
}

// CheckNSID 采集 NSID（RFC 5001）与 CHAOS version.bind / hostname.bind 版本信息，
// 并对重复 NSID 的端点置 NSIDShared（供 score 标注"NSID重复(可能代理)"）。
// "不支持"（空串）不算失败：多数公共 DNS 默认不开放 NSID/CHAOS。
func CheckNSID(r *prober.Runner, th *config.Thresholds) {
	r.Progress("干净度：NSID / CHAOS 版本信息采集…")
	byLabel := map[string]string{}
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		if nsid, err := r.QueryNSID(ep, th.Timeout()); err == nil && nsid != "" {
			m.NSID = nsid
			byLabel[ep.Label()] = nsid
		}
		for _, name := range []string{"version.bind", "hostname.bind"} {
			txt, err := r.QueryCHAOS(ep, name, th.Timeout())
			if err == nil && len(txt) > 0 {
				m.ChaosVersion = strings.Join(txt, " ")
				break
			}
		}
	}
	dups := nsidDuplicates(byLabel)
	if len(dups) == 0 {
		return
	}
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		if m.NSID != "" && dups[strings.ToLower(m.NSID)] {
			m.NSIDShared = true
		}
	}
}
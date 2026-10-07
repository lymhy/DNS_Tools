// Package score 实现指标归一化、加权总分与主用/备用推荐策略。
package score

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"dnspick/internal/config"
	"dnspick/internal/prober"
)

// Row 是一个端点的评分结果行。
type Row struct {
	Endpoint prober.Endpoint
	*prober.Metrics

	Geo string // 归属地描述（由 CLI 填充，可为空）

	LatencyScore  float64 // 0~100
	StableScore   float64
	Proximity     float64
	CleanScore    float64
	Total         float64
	Rank          int
	RecommendMain bool
	RecommendBack bool
	Flags         []string // ⚠ 标注，如 "NXDOMAIN重定向" "透明劫持"

	// Usable 为 false 表示该端点没有任何成功测量（全部超时/失败）。
	// 这类行不参与推荐，也不把"什么都没测到"当成"干净"：干净分记 0 并标注"无数据"。
	Usable bool
}

// Score 对所有端点评分排序。
func Score(r *prober.Runner, cfg *config.Weights, geoOK bool) []*Row {
	var rows []*Row
	for _, ep := range r.Endpoints {
		// 去重：同一地址可能同时作为系统 DNS 与内置候选出现，二者共享同一份
		// Metrics，报告中只保留先出现的一行，避免重复行与重复计数。
		dup := false
		for _, prev := range rows {
			if prev.Endpoint.Label() == ep.Label() {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		rows = append(rows, &Row{Endpoint: ep, Metrics: r.Metrics(ep)})
	}
	if len(rows) == 0 {
		return rows
	}

	// 归一化基准：候选集内最快缓存 P50 / 最快递归 P50 / 最快 TCP 中位。
	// 排除系统基线端点：网关 DNS 延迟天然极低（直连同一局域网），纳入基准会把
	// 所有公共 DNS 的延迟分压到 0 附近，失去区分度（对应方案 4.2 基线单独展示）。
	// 用 0 表示"没有样本"，不用哨兵值，避免"无基准"被当成"基准为 0"。
	bestCache, bestRec, bestTCP := 0.0, 0.0, 0.0
	for _, row := range rows {
		if row.Endpoint.IsSystem {
			continue
		}
		if row.CacheP50 > 0 && (bestCache == 0 || row.CacheP50 < bestCache) {
			bestCache = row.CacheP50
		}
		if row.RecP50 > 0 && (bestRec == 0 || row.RecP50 < bestRec) {
			bestRec = row.RecP50
		}
		if row.TCPMedian > 0 && (bestTCP == 0 || row.TCPMedian < bestTCP) {
			bestTCP = row.TCPMedian
		}
	}

	for _, row := range rows {
		row.Usable = row.Success > 0

		// 延迟分：缓存 0.6 + 递归 0.4；缺失的一项按剩余权重重新归一，
		// 而不是把该项直接算成 0 分。
		ls, wsum := 0.0, 0.0
		if row.CacheP50 > 0 && bestCache > 0 {
			ls += 0.6 * (100 * bestCache / row.CacheP50)
			wsum += 0.6
		}
		if row.RecP50 > 0 && bestRec > 0 {
			ls += 0.4 * (100 * bestRec / row.RecP50)
			wsum += 0.4
		}
		if wsum > 0 {
			ls /= wsum
		}
		row.LatencyScore = clamp(ls)

		row.StableScore = clamp(row.Success * 100)

		// 就近分：同省率×60 + TCP 相对分×40；省份未知（-1）或 geo 不可用时，
		// 只用 TCP 相对分，不把"未知"当成"同省率 0%"。
		tcpPart := 0.0
		if row.TCPMedian > 0 && bestTCP > 0 {
			tcpPart = 100 * bestTCP / row.TCPMedian
		}
		ps := tcpPart
		if geoOK && row.SameProvinceRate >= 0 {
			ps = row.SameProvinceRate*60 + tcpPart*0.4
		}
		row.Proximity = clamp(ps)

		// 干净分
		p := 100.0
		if row.NXDomainHijack {
			p -= 40
		}
		if row.TransparentHijack {
			p -= 30
		}
		if row.PollutionTotal > 0 {
			p -= 20 * float64(row.PollutionHits)
		}
		p -= 10 * float64(row.ConsistencyIssues)
		row.CleanScore = clamp(p)

		// ⚠ 标注
		if row.NXDomainHijack {
			row.Flags = append(row.Flags, "NXDOMAIN重定向")
		}
		if row.TransparentHijack {
			row.Flags = append(row.Flags, "透明劫持(53被代理)")
		}
		if row.PollutionHits > 0 {
			row.Flags = append(row.Flags, fmt.Sprintf("污染%d/%d", row.PollutionHits, row.PollutionTotal))
		}

		// 没有任何成功测量：各维度一律记 0，干净分也不保留默认满分，
		// 否则"没测到"会被当成"已验证干净"而白拿 0.15×100 = 15 分。
		if !row.Usable {
			row.LatencyScore, row.StableScore, row.Proximity, row.CleanScore = 0, 0, 0, 0
			row.Flags = append(row.Flags, "无数据")
		}

		row.Total = cfg.Latency*row.LatencyScore + cfg.Stable*row.StableScore +
			cfg.Prox*row.Proximity + cfg.Cleanness*row.CleanScore
	}

	// 排名：本地基线（系统 DNS）只作对照，不占名次，统一排在候选之后；
	// 没测到数据的端点同样不给名次（显示 "-"），"第 1 名"必须是可用的端点。
	sort.Slice(rows, func(i, j int) bool { return less(rows[i], rows[j]) })
	rank := 0
	for _, row := range rows {
		if row.Endpoint.IsSystem || !row.Usable {
			continue
		}
		rank++
		row.Rank = rank
	}

	recommend(rows)
	return rows
}

// less 定义排序：先按"有没有数据"，再按总分降序，并列时用成功率、缓存延迟、
// 端点标签依次打破，保证同一批输入每次得到同样的名次（sort.Slice 本身不稳定）。
func less(a, b *Row) bool {
	if a.Endpoint.IsSystem != b.Endpoint.IsSystem {
		return !a.Endpoint.IsSystem
	}
	if a.Usable != b.Usable {
		return a.Usable
	}
	if a.Total != b.Total {
		return a.Total > b.Total
	}
	if a.Success != b.Success {
		return a.Success > b.Success
	}
	aP, bP := a.CacheP50, b.CacheP50
	if (aP <= 0) != (bP <= 0) {
		return bP <= 0 // 有延迟样本的排前
	}
	if aP > 0 && bP > 0 && aP != bP {
		return aP < bP
	}
	return a.Endpoint.Label() < b.Endpoint.Label()
}

// recommend 按方案 4.2：主用 = 干净分满分者优先；备用与主用分属不同运营方。
// 只有真正测到数据的端点参与推荐（系统/运营商基线只展示，不参与主备）。
func recommend(rows []*Row) {
	var candidates []*Row
	for _, row := range rows {
		if !row.Endpoint.IsSystem && row.Usable {
			candidates = append(candidates, row)
		}
	}
	if len(candidates) == 0 {
		return
	}
	main := candidates[0]
	// 安全优先：若第一名干净分 < 100，在干净分满分者中取总分第一。
	if main.CleanScore < 100 {
		for _, row := range candidates[1:] {
			if row.CleanScore >= 100 {
				main = row
				break
			}
		}
	}
	main.RecommendMain = true

	for _, row := range candidates {
		if row == main {
			continue
		}
		if familyOf(row.Endpoint.Server) != familyOf(main.Endpoint.Server) {
			row.RecommendBack = true
			break
		}
	}
}

// familyOf 把候选 DNS 归到同一运营方，用于"主备不要同一家"的判断
// （方案 4.2 第 2 条：备用应与主用分属不同运营商）。
func familyOf(server string) string {
	s := strings.ToLower(server)
	switch {
	case strings.Contains(s, "腾讯"), strings.Contains(s, "dnspod"), strings.Contains(s, "tencent"):
		return "tencent"
	case strings.Contains(s, "阿里"), strings.Contains(s, "ali"):
		return "aliyun"
	case strings.Contains(s, "114"):
		return "114dns"
	case strings.Contains(s, "360"):
		return "360dns"
	case strings.Contains(s, "百度"), strings.Contains(s, "baidu"):
		return "baidu"
	case strings.Contains(s, "cnnic"), strings.Contains(s, "sdns"):
		return "cnnic"
	case strings.Contains(s, "google"):
		return "google"
	case strings.Contains(s, "cloudflare"):
		return "cloudflare"
	case strings.Contains(s, "quad9"):
		return "quad9"
	}
	return server
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return math.Round(v*10) / 10
}

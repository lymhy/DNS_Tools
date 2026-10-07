// Package checker 实现干净度与就近性检查：劫持、污染比对、CDN 就近性、ECS。
package checker

import (
	"net"
	"strings"
	"time"

	"dnspick/internal/geo"
	"dnspick/internal/prober"
)

const probeTimeout = 2 * time.Second

// CheckHijack NXDOMAIN 劫持 + 透明劫持（echo 回显）。
// sysDNS 是本机运营商 DNS 列表：回显 IP 为私网或命中运营商解析器时判定被透明代理。
// 注意不能简单用"回显 IP ≠ 目标"判定：anycast 公共 DNS 的回显本就是具体节点 IP。
func CheckHijack(r *prober.Runner, sysDNS []string) {
	r.Progress("干净度：NXDOMAIN 劫持 / 透明劫持检测…")
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)

		// ① NXDOMAIN：查询保证不存在的随机域名，返回 A 记录即劫持。
		name := prober.RandomSubdomain("nxdomain-test") + ".invalid"
		ips, _, err := r.QueryA(ep, name, probeTimeout)
		if err == nil && len(ips) > 0 {
			m.NXDomainHijack = true
		}

		// ② 透明劫持：向目标查询 Google 回显域名 TXT，回显是私网地址、
		// 或是别的运营商解析器（命中 sysDNS 但又不是被查端点自己）→ 被 53 端口代理。
		txts, _, err := r.QueryTXT(ep, "o-o.myaddr.l.google.com", probeTimeout)
		if err != nil {
			continue
		}
		self := net.ParseIP(ep.Address)
		for _, t := range txts {
			ip := net.ParseIP(strings.Trim(t, `"`))
			if ip == nil {
				continue
			}
			private := ip.IsPrivate() || ip.IsLoopback()
			isp := false
			for _, s := range sysDNS {
				if sIP := net.ParseIP(s); sIP != nil && sIP.Equal(ip) {
					// 解析器回显自己（运营商 DNS 或作为基线被查的网关）是正常现象，
					// 不算透明劫持；只有"问 A 却由 B 代答"才是。
					if self == nil || !self.Equal(ip) {
						isp = true
					}
				}
			}
			m.EchoIP = ip.String()
			if private || isp {
				m.TransparentHijack = true
			}
		}
	}
}

// CheckPollution 污染比对（完整模式）：查询样本域名，与权威 NS 的 TCP 答案比对；
// 答案明显不符且本地应答很快（<20ms 级别难以真递归）判为污染。
func CheckPollution(r *prober.Runner, samples []string, authoritative func(string) []string) {
	r.Progress("干净度：污染比对（%d 个样本域名）…", len(samples))
	// 基准答案与端点无关：先统一取一次并缓存。若放进端点循环里重算，
	// 每个端点会拿到不同时刻/不同权威 NS 的基准，且重复解析非常慢。
	baseline := make(map[string][]string, len(samples))
	for _, d := range samples {
		baseline[d] = authoritative(d)
	}
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		m.PollutionTotal = 0
		for _, d := range samples {
			clean := baseline[d]
			if len(clean) == 0 {
				continue // 拿不到干净基准的域名不计入分母
			}
			ips, rtt, err := r.QueryA(ep, d, probeTimeout)
			if err != nil || len(ips) == 0 {
				continue
			}
			m.PollutionTotal++
			if !overlap(ips, clean) && rtt < 20*time.Millisecond {
				m.PollutionHits++
			}
		}
	}
}

func overlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// CheckConsistency 结果一致性：同一域名查 3 次，出现私网 IP 或答案抖动记异常。
// 每个域名每类异常最多记一次，避免同一个问题被 3 轮查询放大成 3 倍扣分。
func CheckConsistency(r *prober.Runner, domains []string) {
	r.Progress("干净度：结果一致性检测…")
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		for _, d := range domains[:min(3, len(domains))] {
			var prev []string
			answered := false
			privateSeen, jitterSeen := false, false
			for i := 0; i < 3; i++ {
				ips, _, err := r.QueryA(ep, d, probeTimeout)
				if err != nil || len(ips) == 0 {
					continue // 本轮没答上来：保留上一轮答案，不重置抖动比较
				}
				for _, ip := range ips {
					if p := net.ParseIP(ip); p != nil && p.IsPrivate() {
						privateSeen = true
					}
				}
				if answered && !overlap(prev, ips) {
					jitterSeen = true
				}
				prev = ips
				answered = true
			}
			if privateSeen {
				m.ConsistencyIssues++
			}
			if jitterSeen {
				m.ConsistencyIssues++
			}
		}
	}
}

// CheckCDN 就近性端到端：对解析出的 IP 做 TCP 443 握手计时；完整模式加测 TTFB。
// ifIP 非空时 TCP/TTFB 也绑定该出口网卡，与 DNS 查询保持同一条路径。
func CheckCDN(r *prober.Runner, answers map[string]map[string][]string, loc *geo.Locator, myProvince string, full bool, ifIP net.IP) {
	r.Progress("就近性：TCP 443 握手计时 / 归属地统计…")
	tcpCache := map[string]float64{} // 同一 IP 常被多个 DNS 返回，握手只测一次
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		perDomain := answers[ep.Label()]
		var tcpSamples []float64
		sameProvince, total := 0, 0

		for _, domain := range sortedKeys(perDomain) {
			ips := perDomain[domain]
			// 每个域名最多测 3 个 IP 的 TCP，避免拖时间。
			for i, ip := range ips {
				if i >= 3 {
					break
				}
				if loc.Available() {
					// 只统计能查到省份的 IP：查不到归属的 IP 既不算同省也不算异省，
					// 否则会把库覆盖不到的空档算成"异省"而压低同省率。
					if prov := loc.Province(ip); prov != "" {
						total++
						if myProvince != "" && prov == myProvince {
							sameProvince++
						}
					}
				}
				d, ok := tcpCache[ip]
				if !ok {
					d = float64(tcpHandshake(ip, ifIP).Microseconds()) / 1000
					tcpCache[ip] = d
				}
				if d > 0 {
					tcpSamples = append(tcpSamples, d)
				}
			}
		}
		// 同省率只在能确定基准省份时给出，否则保持 -1（未知）。
		// 把"不知道本机省份"写成 0% 会让所有端点的就近分一起塌掉。
		if total > 0 && myProvince != "" {
			m.SameProvinceRate = float64(sameProvince) / float64(total)
		}
		m.TCPMedian = prober.Median(tcpSamples)

		if full {
			m.TTFBMedian = prober.Median(ttfbSamples(perDomain, 5, ifIP))
		}
	}
}

// tcpHandshake 对 IP:443 做 TCP 握手计时；失败返回 0（不计入样本，由成功率体现）。
func tcpHandshake(ip string, ifIP net.IP) time.Duration {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if ifIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: ifIP}
	}
	start := time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return 0
	}
	conn.Close()
	return time.Since(start)
}

// CheckECS 完整模式：先带本机公网 /24 的 ECS 查一次，再不带 ECS 查一次，答案不同则视为支持 ECS。
// 顺序很重要：先不带 ECS 会把答案写进解析器缓存，后一次带 ECS 的查询就拿不到真实结果了。
func CheckECS(r *prober.Runner, publicIP, probeDomain string) {
	r.Progress("干净度：EDNS Client Subnet 支持检测…")
	if publicIP == "" || probeDomain == "" {
		return
	}
	ip := net.ParseIP(publicIP).To4()
	if ip == nil {
		return
	}
	ecsCIDR := net.IPNet{IP: ip.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
	for _, ep := range r.Endpoints {
		if ep.Proto == prober.DOH || ep.Proto == prober.DOT {
			continue // 简化：仅对 UDP 做 ECS 对比
		}
		m := r.Metrics(ep)
		with, _, err := r.QueryECS(ep, probeDomain, ecsCIDR, probeTimeout)
		if err != nil || len(with) == 0 {
			continue
		}
		without, _, err := r.QueryA(ep, probeDomain, probeTimeout)
		if err != nil || len(without) == 0 {
			continue
		}
		m.ECSSupported = !overlap(with, without)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

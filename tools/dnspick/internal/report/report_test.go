package report

import (
	"strings"
	"testing"

	"dnspick/internal/prober"
	"dnspick/internal/score"
)

// 同一名称下挂着多个地址（如 DNSPod 的 4 个 IPv4）时，排名表与"本组建议"
// 都必须写明具体地址，否则几行长一个样，看不出这一行到底是哪个 DNS。
func TestTableShowsEndpointAddress(t *testing.T) {
	rows := []*score.Row{
		{Endpoint: prober.Endpoint{Server: "腾讯DNSPod", Address: "119.29.29.29", Proto: prober.UDP},
			Metrics: &prober.Metrics{}, Total: 90, Usable: true, Rank: 1},
		{Endpoint: prober.Endpoint{Server: "腾讯DNSPod", Address: "182.254.116.116", Proto: prober.UDP},
			Metrics: &prober.Metrics{}, Total: 80, Usable: true, Rank: 2},
	}
	gr := &score.GroupedResult{Groups: []score.Group{
		{Proto: prober.UDP, Rows: rows, Main: rows[0]},
	}}
	out := Table(gr, ReportMeta{Version: "test", Mode: "快速"}, "", "", false)
	for _, want := range []string{"腾讯DNSPod (119.29.29.29)", "腾讯DNSPod (182.254.116.116)"} {
		if !strings.Contains(out, want) {
			t.Errorf("输出应包含 %q，实际:\n%s", want, out)
		}
	}
}

// 只有 UDP/UDP6 端点才有能写进系统 DNS 的地址；
// DoH 端点的 Address 是 URL，当成 DNS 地址写下去会直接搞坏本机解析。
func TestPrimaryIPSkipsDoH(t *testing.T) {
	udp := &score.Row{Endpoint: prober.Endpoint{Server: "A", Address: "223.5.5.5", Proto: prober.UDP}}
	if got := primaryIP(udp); got != "223.5.5.5" {
		t.Errorf("UDP 端点应返回其地址，got %q", got)
	}
	udp6 := &score.Row{Endpoint: prober.Endpoint{Server: "A", Address: "2400:3200::1", Proto: prober.UDP6}}
	if got := primaryIP(udp6); got != "2400:3200::1" {
		t.Errorf("UDP6 端点应返回其地址，got %q", got)
	}
	doh := &score.Row{Endpoint: prober.Endpoint{Server: "A", Address: "https://doh.pub/dns-query", Proto: prober.DOH}}
	if got := primaryIP(doh); got != "" {
		t.Errorf("DoH 的 URL 不能当作系统 DNS，got %q", got)
	}
	dot := &score.Row{Endpoint: prober.Endpoint{Server: "A", Address: "dot.pub:853", Proto: prober.DOT}}
	if got := primaryIP(dot); got != "" {
		t.Errorf("DoT 的 host:port 不能当作系统 DNS，got %q", got)
	}
}

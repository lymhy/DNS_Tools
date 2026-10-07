package report

import (
	"testing"

	"dnspick/internal/prober"
	"dnspick/internal/score"
)

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

package checker

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sort"
	"time"
)

// sortedKeys 返回有序的域名列表：Go 的 map 遍历顺序随机，直接遍历会导致每个
// 端点取到的 TTFB 子集不同，列与列之间无法比较。
func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// newProbeClient 构造 HTTPS 探测客户端：绑定出口网卡、用 DialTLSContext 指定正确
// SNI、跳过证书校验（IP 直连时证书不匹配是正常的）。
// DisableKeepAlives 避免空闲连接堆积——--monitor 长跑时零值 Transport 的
// IdleConnTimeout=0 会让连接和它的 goroutine 一直不回收。
func newProbeClient(ifIP net.IP, sni string) *http.Client {
	d := &net.Dialer{Timeout: 4 * time.Second}
	if ifIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: ifIP}
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
				if err := tc.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return tc, nil
			},
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
			MaxIdleConns:        4,
		},
		Timeout: 6 * time.Second,
	}
}

// ttfbSamples 抽样 topN 个域名（按域名排序，保证所有端点抽的是同一批），
// 对每个域名返回的第一个 IP 以正确 SNI 发 HTTPS HEAD，测首字节时间。
func ttfbSamples(perDomain map[string][]string, topN int, ifIP net.IP) []float64 {
	var out []float64
	for _, domain := range sortedKeys(perDomain) {
		if len(out) >= topN {
			break
		}
		ips := perDomain[domain]
		if len(ips) == 0 {
			continue
		}
		hc := newProbeClient(ifIP, domain)
		d := ttfbOnce(hc, ips[0], domain)
		hc.CloseIdleConnections()
		if d > 0 {
			out = append(out, float64(d.Microseconds())/1000)
		}
	}
	return out
}

func ttfbOnce(hc *http.Client, ip, host string) time.Duration {
	req, err := http.NewRequest(http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "dnspick/1.0 (+probe)")
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return time.Since(start)
}

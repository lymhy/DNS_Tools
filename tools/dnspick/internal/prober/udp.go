package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// prober 实现三种协议的查询。绑定网卡时通过 customDialer 使用指定本地地址。
type prober struct {
	localAddr net.IP // 可为 nil；多网卡 --interface 时绑定出口
	hc        *http.Client
}

// NewQuerier 创建协议查询器；ifAddr 为要绑定的出口网卡 IPv4（可空）。
func NewQuerier(ifAddr net.IP) Querier {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if ifAddr != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ifAddr}
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &prober{
		localAddr: ifAddr,
		hc:        &http.Client{Transport: transport, Timeout: 6 * time.Second},
	}
}

// udpDialer 返回绑定了出口网卡的 UDP dialer；未指定网卡或地址族不匹配时返回 nil。
// 绑定必须覆盖所有协议，否则 --interface 只在部分查询上生效，实测流量会从
// 另一条网卡出去（多网卡/双栈环境结论直接失真）。
func (p *prober) udpDialer(timeout time.Duration, v6 bool) *net.Dialer {
	if p.localAddr == nil {
		return nil
	}
	if v6 != (p.localAddr.To4() == nil) {
		return nil // IPv4 本地地址绑不到 IPv6 套接字，反之亦然
	}
	return &net.Dialer{Timeout: timeout, LocalAddr: &net.UDPAddr{IP: p.localAddr}}
}

// tcpDialer 返回绑定了出口网卡的 TCP dialer（DoT 与权威直查共用）。
func (p *prober) tcpDialer(timeout time.Duration) *net.Dialer {
	if p.localAddr == nil {
		return nil
	}
	return &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: p.localAddr}}
}

// exchange 按协议发送一次查询；绑定网卡时使用指定本地地址。
func (p *prober) exchange(ep Endpoint, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	var client *dns.Client
	switch ep.Proto {
	case UDP:
		client = &dns.Client{Net: "udp", Timeout: timeout, Dialer: p.udpDialer(timeout, false), UDPSize: 1232}
	case UDP6:
		client = &dns.Client{Net: "udp", Timeout: timeout, Dialer: p.udpDialer(timeout, true), UDPSize: 1232}
	case DOT:
		client = &dns.Client{
			Net: "tcp-tls", Timeout: timeout,
			Dialer:    p.tcpDialer(timeout),
			TLSConfig: &tls.Config{ServerName: hostOnly(ep.Address), InsecureSkipVerify: true},
		}
	default:
		return nil, 0, fmt.Errorf("未知协议 %s", ep.Proto)
	}
	client.Timeout = timeout
	addr := ep.Address
	if ep.Proto == DOT {
		// DoT 地址形如 host:port；无端口则补 853
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "853")
		}
	} else if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return client.Exchange(m, addr)
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// buildQuery 构造 A 查询（含 warmup 可复用）。
func buildQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	return m
}

// QueryA 查询 A 记录：UDP/DoT 走 53/853，DoH 走 RFC8484 POST。
func (p *prober) QueryA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	m := buildQuery(name)
	if ep.Proto == DOH {
		resp, rtt, err := p.queryDoH(ep, m, timeout)
		if err != nil {
			return nil, 0, err
		}
		return extractA(resp), rtt, nil
	}
	resp, rtt, err := p.exchange(ep, m, timeout)
	if err != nil {
		return nil, 0, err
	}
	return extractA(resp), rtt, nil
}

// QueryTXT 查询 TXT 记录（echo 回显劫持检测用）。
func (p *prober) QueryTXT(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	if ep.Proto == DOH {
		resp, rtt, err := p.queryDoH(ep, m, timeout)
		if err != nil {
			return nil, 0, err
		}
		return extractTXT(resp), rtt, nil
	}
	resp, rtt, err := p.exchange(ep, m, timeout)
	if err != nil {
		return nil, 0, err
	}
	return extractTXT(resp), rtt, nil
}

// queryDoH 按 RFC 8484 以 wire-format POST，返回解包后的 DNS 报文；
// 调用方按自己的记录类型提取答案（原先这里写死 extractA，
// 导致 DoH 的 TXT 查询永远返回空，透明劫持检测对 7 个 DoH 端点全部失效）。
func (p *prober) queryDoH(ep Endpoint, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Address, strings.NewReader(string(wire)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	rtt := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	rm := new(dns.Msg)
	if err := rm.Unpack(body); err != nil {
		return nil, 0, err
	}
	return rm, rtt, nil
}

func extractA(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			out = append(out, r.A.String())
		}
	}
	return out
}

func extractTXT(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

// QueryNSViaTCP 用系统解析器找到域名的权威 NS，再用 TCP 53 直接问权威，得到"干净基准答案"。
func (p *prober) QueryNSViaTCP(name string, timeout time.Duration) ([]string, error) {
	nss, err := net.LookupNS(name)
	if err == nil && len(nss) > 0 {
		for _, ns := range nss {
			nsIPs, err := net.LookupHost(ns.Host)
			if err != nil || len(nsIPs) == 0 {
				continue
			}
			m := buildQuery(name)
			c := &dns.Client{Net: "tcp", Timeout: timeout, Dialer: p.tcpDialer(timeout)}
			resp, _, err := c.Exchange(m, net.JoinHostPort(nsIPs[0], "53"))
			if err != nil {
				continue
			}
			if ips := extractA(resp); len(ips) > 0 {
				return ips, nil
			}
		}
	}
	// 权威直查失败则退化用系统解析器结果作为基准（可信度略降）。
	return net.LookupHost(name)
}

// rawQueryRaw 供 ECS 检测携带自定义 EDNS 选项查询（UDP）。
func (p *prober) QueryWithECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) ([]string, time.Duration, error) {
	m := buildQuery(name)
	if ecsNet.IP != nil {
		if opt := m.IsEdns0(); opt != nil {
			family := uint16(1)
			if ecsNet.IP.To4() == nil {
				family = 2
			}
			mask, _ := ecsNet.Mask.Size()
			opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        family,
				SourceNetmask: uint8(mask),
				SourceScope:   0,
				Address:       ecsNet.IP,
			})
		}
	}
	resp, rtt, err := p.exchange(ep, m, timeout)
	if err != nil {
		return nil, 0, err
	}
	return extractA(resp), rtt, nil
}

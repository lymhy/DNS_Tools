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

	"dnspick/internal/config"
)

// defaultUDPBufSize 与 DNS Flag Day 2020 建议一致；阈值未配置时兜底。
const defaultUDPBufSize = 1232

// prober 实现三种协议的查询。绑定网卡时通过 customDialer 使用指定本地地址。
type prober struct {
	localAddr net.IP // 可为 nil；多网卡 --interface 时绑定出口
	hc        *http.Client
	th        config.Thresholds
}

// NewQuerier 创建协议查询器（使用内置默认阈值）；ifAddr 为要绑定的出口网卡 IPv4（可空）。
func NewQuerier(ifAddr net.IP) Querier {
	return NewQuerierWithThresholds(ifAddr, config.DefaultThresholds())
}

// NewQuerierWithThresholds 创建协议查询器并采用给定阈值（超时、EDNS0 载荷等）。
func NewQuerierWithThresholds(ifAddr net.IP, th config.Thresholds) Querier {
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
	doHTimeout := th.DoHTimeout()
	if doHTimeout <= 0 {
		doHTimeout = 6 * time.Second
	}
	return &prober{
		localAddr: ifAddr,
		hc:        &http.Client{Transport: transport, Timeout: doHTimeout},
		th:        th,
	}
}

// udpSize 返回 EDNS0 载荷大小；阈值未配置时用 1232 兜底，避免 0 导致分片。
func (p *prober) udpSize() uint16 {
	if p.th.UDPBufSize <= 0 {
		return defaultUDPBufSize
	}
	return uint16(p.th.UDPBufSize)
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
		client = &dns.Client{Net: "udp", Timeout: timeout, Dialer: p.udpDialer(timeout, false), UDPSize: p.udpSize()}
	case UDP6:
		client = &dns.Client{Net: "udp", Timeout: timeout, Dialer: p.udpDialer(timeout, true), UDPSize: p.udpSize()}
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

// buildQueryType 构造指定记录类型的查询；do 为 true 时置 EDNS0 DO 位（DNSSEC）。
func (p *prober) buildQueryType(name string, qtype uint16, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(p.udpSize(), do)
	return m
}

// buildQuery 构造 A 查询（含 warmup 可复用）。
func (p *prober) buildQuery(name string) *dns.Msg {
	return p.buildQueryType(name, dns.TypeA, false)
}

// QueryA 查询 A 记录：UDP/DoT 走 53/853，DoH 走 RFC8484 POST。
func (p *prober) QueryA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	return p.queryType(ep, name, dns.TypeA, timeout)
}

// QueryAAAA 查询 AAAA 记录（双栈可用性检测用）。
func (p *prober) QueryAAAA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	return p.queryType(ep, name, dns.TypeAAAA, timeout)
}

// queryType 是 A/AAAA 共用的查询路径。
func (p *prober) queryType(ep Endpoint, name string, qtype uint16, timeout time.Duration) ([]string, time.Duration, error) {
	m := p.buildQueryType(name, qtype, false)
	if ep.Proto == DOH {
		resp, rtt, err := p.queryDoH(ep, m, timeout)
		if err != nil {
			return nil, 0, err
		}
		return extractAddr(resp, qtype), rtt, nil
	}
	resp, rtt, err := p.exchange(ep, m, timeout)
	if err != nil {
		return nil, 0, err
	}
	return extractAddr(resp, qtype), rtt, nil
}

// QueryTXT 查询 TXT 记录（echo 回显劫持检测用）。
func (p *prober) QueryTXT(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	m := p.buildQueryType(name, dns.TypeTXT, false)
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

// QueryWithDO 以 EDNS0 DO=1 查询，返回 AD / RRSIG / Rcode，供 DNSSEC 判定（RFC 4035）。
func (p *prober) QueryWithDO(ep Endpoint, name string, timeout time.Duration) (*DNSSECReply, error) {
	m := p.buildQueryType(name, dns.TypeA, true)
	var resp *dns.Msg
	var err error
	if ep.Proto == DOH {
		resp, _, err = p.queryDoH(ep, m, timeout)
	} else {
		resp, _, err = p.exchange(ep, m, timeout)
	}
	if err != nil {
		return nil, err
	}
	out := &DNSSECReply{AD: resp.AuthenticatedData, RCode: resp.Rcode, Answers: extractA(resp)}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			out.RRSIG = true
			break
		}
	}
	return out, nil
}

// QueryNSID 以 EDNS0 NSID 选项查询根域，返回解析器节点标识（hex 字符串，RFC 5001）。
// 空串表示解析器未返回 NSID（不支持或未开启）。
func (p *prober) QueryNSID(ep Endpoint, timeout time.Duration) (string, error) {
	m := p.buildQueryType(".", dns.TypeNS, false)
	// buildQueryType 已经加了 OPT，这里只追加 NSID 选项（重复 SetEdns0 会产生两个 OPT）。
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	}
	var resp *dns.Msg
	var err error
	if ep.Proto == DOH {
		resp, _, err = p.queryDoH(ep, m, timeout)
	} else {
		resp, _, err = p.exchange(ep, m, timeout)
	}
	if err != nil {
		return "", err
	}
	opt := resp.IsEdns0()
	if opt == nil {
		return "", nil
	}
	for _, o := range opt.Option {
		if n, ok := o.(*dns.EDNS0_NSID); ok {
			return n.Nsid, nil
		}
	}
	return "", nil
}

// QueryCHAOS 以 CH 类查询 version.bind / hostname.bind（RFC 4892 实践）。
// REFUSED / NOTIMP / SERVFAIL 视为"未开放"：返回空切片且不报错。
func (p *prober) QueryCHAOS(ep Endpoint, name string, timeout time.Duration) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	m.RecursionDesired = false
	var resp *dns.Msg
	var err error
	if ep.Proto == DOH {
		resp, _, err = p.queryDoH(ep, m, timeout)
	} else {
		resp, _, err = p.exchange(ep, m, timeout)
	}
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNotImplemented:
		return nil, nil
	}
	return extractTXT(resp), nil
}

func extractA(m *dns.Msg) []string {
	return extractAddr(m, dns.TypeA)
}

func extractAddr(m *dns.Msg, qtype uint16) []string {
	var out []string
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				out = append(out, r.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				out = append(out, r.AAAA.String())
			}
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
			m := p.buildQuery(name)
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

// QueryWithECS 供 ECS 检测携带自定义 EDNS 选项查询（UDP）。
func (p *prober) QueryWithECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) ([]string, time.Duration, error) {
	m := p.buildQuery(name)
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
// Package config 负责 YAML 配置加载与内置默认值（候选 DNS、探测域名、评分权重、测量阈值）。
package config

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Server 是一个候选 DNS 服务器（一个名字可带多个入口：UDP IP、IPv6、DoH、DoT）。
type Server struct {
	Name   string   `yaml:"name"   json:"name"`
	IPs    []string `yaml:"ips"    json:"ips"`
	IPv6   []string `yaml:"ipv6"   json:"ipv6"`
	DoH    string   `yaml:"doh"    json:"doh"`
	DoT    string   `yaml:"dot"    json:"dot"`
	Region string   `yaml:"region" json:"region"` // 备注归属，如 "境内" / "境外"
}

// Domains 描述探测域名集。
type Domains struct {
	Web      []string `yaml:"web"`
	Video    []string `yaml:"video"`
	CDN      []string `yaml:"cdn"`
	Polluted []string `yaml:"polluted"`
}

// Weights 是评分权重（总分 = w1*延迟 + w2*稳定 + w3*就近 + w4*干净）。
type Weights struct {
	Latency   float64 `yaml:"latency"`
	Stable    float64 `yaml:"stable"`
	Prox      float64 `yaml:"proximity"`
	Cleanness float64 `yaml:"cleanness"`
}

// Thresholds 集中全部测量阈值，便于审计与按需覆盖。
// 每项的依据（RFC / 经验值）见 ThresholdDoc()，也会写入 docs 的技术方案 §3.4。
type Thresholds struct {
	QPS               float64 `yaml:"qps"                json:"qps"`                // 单端点每秒查询上限
	TimeoutMS         int     `yaml:"timeout_ms"         json:"timeout_ms"`         // 阶段1/就近性查询超时
	RecTimeoutMS      int     `yaml:"rec_timeout_ms"     json:"rec_timeout_ms"`     // 递归延迟查询超时
	Retries           int     `yaml:"retries"            json:"retries"`            // 传输失败后的重试次数
	Warmup            int     `yaml:"warmup"             json:"warmup"`             // 丢弃的热身样本数
	SamplesFast       int     `yaml:"samples_fast"       json:"samples_fast"`       // 快速模式有效样本数
	SamplesFull       int     `yaml:"samples_full"       json:"samples_full"`       // 完整模式有效样本数
	RecRounds         int     `yaml:"rec_rounds"         json:"rec_rounds"`         // 递归延迟轮数
	UDPBufSize        int     `yaml:"udp_buf_size"       json:"udp_buf_size"`       // EDNS0 载荷大小
	PollutionRTTMS    int     `yaml:"pollution_rtt_ms"   json:"pollution_rtt_ms"`   // 污染判定的"过快"阈值
	PollutionRepeat   int     `yaml:"pollution_repeat"   json:"pollution_repeat"`   // 污染判定的重复次数
	MaxIPsPerDomain   int     `yaml:"max_ips_per_domain" json:"max_ips_per_domain"` // 每域名抽样 IP 上限
	TTFBDomains       int     `yaml:"ttfb_domains"       json:"ttfb_domains"`       // 每端点 TTFB 域名数
	CDNFast           int     `yaml:"cdn_fast"           json:"cdn_fast"`           // 快速模式就近性域名数
	CDNFull           int     `yaml:"cdn_full"           json:"cdn_full"`           // 完整模式就近性域名数
	ConsistencyN      int     `yaml:"consistency_domains" json:"consistency_domains"` // 一致性检测域名数
	TCPTimeoutMS      int     `yaml:"tcp_timeout_ms"     json:"tcp_timeout_ms"`     // CDN TCP443 握手超时
	DoHTimeoutMS      int     `yaml:"doh_timeout_ms"     json:"doh_timeout_ms"`     // DoH 整体超时（含 TLS）
	ResolutionDelayMS int     `yaml:"resolution_delay_ms" json:"resolution_delay_ms"` // Happy Eyeballs ResolutionDelay
	AuxEnabled        bool    `yaml:"aux_probes"         json:"aux_probes"`         // 是否执行 DNSSEC/NSID/双栈辅助探测
}

// Timeout 阶段1/就近性的查询超时。
func (t Thresholds) Timeout() time.Duration { return time.Duration(t.TimeoutMS) * time.Millisecond }

// RecTimeout 递归延迟查询超时。
func (t Thresholds) RecTimeout() time.Duration {
	return time.Duration(t.RecTimeoutMS) * time.Millisecond
}

// TCPTimeout CDN 边缘 TCP443 握手超时。
func (t Thresholds) TCPTimeout() time.Duration {
	return time.Duration(t.TCPTimeoutMS) * time.Millisecond
}

// DoHTimeout DoH 整体超时（含 TLS 握手）。
func (t Thresholds) DoHTimeout() time.Duration {
	return time.Duration(t.DoHTimeoutMS) * time.Millisecond
}

// Config 是顶层配置。
type Config struct {
	Servers    []Server   `yaml:"servers"`
	Domains    Domains    `yaml:"domains"`
	Weights    Weights    `yaml:"weights"`
	Thresholds Thresholds `yaml:"thresholds"`
}

// DefaultThresholds 返回内置测量阈值（依据见 ThresholdDoc）。
func DefaultThresholds() Thresholds {
	return Thresholds{
		QPS: 5, TimeoutMS: 2000, RecTimeoutMS: 3000, Retries: 1,
		Warmup: 2, SamplesFast: 8, SamplesFull: 30, RecRounds: 5,
		UDPBufSize: 1232, PollutionRTTMS: 20, PollutionRepeat: 3,
		MaxIPsPerDomain: 3, TTFBDomains: 5, CDNFast: 8, CDNFull: 20,
		ConsistencyN: 3, TCPTimeoutMS: 3000, DoHTimeoutMS: 6000,
		ResolutionDelayMS: 250, AuxEnabled: true,
	}
}

// Default 返回内置默认配置（对应方案 3.3 节候选清单与附录 A 域名集）。
func Default() *Config {
	return &Config{
		Servers: []Server{
			{Name: "腾讯DNSPod", IPs: []string{"119.29.29.29", "182.254.116.116"}, IPv6: []string{"2402:4e00::"}, DoH: "https://doh.pub/dns-query", DoT: "dot.pub:853", Region: "境内"},
			{Name: "阿里AliDNS", IPs: []string{"223.5.5.5", "223.6.6.6"}, IPv6: []string{"2400:3200::1", "2400:3200:baba::1"}, DoH: "https://dns.alidns.com/dns-query", DoT: "dns.alidns.com:853", Region: "境内"},
			{Name: "114DNS", IPs: []string{"114.114.114.114", "114.114.115.115"}, Region: "境内"},
			{Name: "360DNS", IPs: []string{"101.226.4.6", "123.125.81.6"}, DoH: "https://doh.360.cn/dns-query", Region: "境内"},
			{Name: "百度DNS", IPs: []string{"180.76.76.76"}, DoH: "https://dns.baidu.com/dns-query", Region: "境内"},
			{Name: "CNNIC SDNS", IPs: []string{"1.2.4.8", "210.2.4.8"}, Region: "境内"},
			{Name: "Google", IPs: []string{"8.8.8.8", "8.8.4.4"}, IPv6: []string{"2001:4860:4860::8888"}, DoH: "https://dns.google/dns-query", DoT: "dns.google:853", Region: "境外"},
			{Name: "Cloudflare", IPs: []string{"1.1.1.1", "1.0.0.1"}, IPv6: []string{"2606:4700:4700::1111"}, DoH: "https://cloudflare-dns.com/dns-query", DoT: "one.one.one.one:853", Region: "境外"},
			{Name: "Quad9", IPs: []string{"9.9.9.9"}, IPv6: []string{"2620:fe::fe"}, DoH: "https://dns.quad9.net/dns-query", DoT: "dns.quad9.net:853", Region: "境外"},
		},
		Domains: Domains{
			Web:   []string{"www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com", "www.bilibili.com"},
			Video: []string{"v.qq.com", "www.iqiyi.com", "www.douyin.com"},
			CDN:   []string{"img.alicdn.com", "dl.google.com", "mirrors.tuna.tsinghua.edu.cn"},
			Polluted: []string{
				"www.youtube.com", "twitter.com", "www.facebook.com", "www.instagram.com",
				"www.wikipedia.org", "www.reddit.com", "news.ycombinator.com",
			},
		},
		Weights:    Weights{Latency: 0.35, Stable: 0.20, Prox: 0.30, Cleanness: 0.15},
		Thresholds: DefaultThresholds(),
	}
}

// Load 读取 YAML 配置覆盖默认值；path 为空或文件不存在时使用内置默认。
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[配置] %s 不存在，使用内置默认配置\n", path)
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	// 只覆盖用户显式提供的部分。
	ov := &struct {
		Servers    []Server            `yaml:"servers"`
		Domains    Domains             `yaml:"domains"`
		Weights    *weightsOverride    `yaml:"weights"`
		Thresholds *thresholdsOverride `yaml:"thresholds"`
	}{}
	if err := yaml.Unmarshal(data, ov); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	if len(ov.Servers) > 0 {
		cfg.Servers = ov.Servers
	}
	if len(ov.Domains.Web) > 0 {
		cfg.Domains.Web = ov.Domains.Web
	}
	if len(ov.Domains.Video) > 0 {
		cfg.Domains.Video = ov.Domains.Video
	}
	if len(ov.Domains.CDN) > 0 {
		cfg.Domains.CDN = ov.Domains.CDN
	}
	if len(ov.Domains.Polluted) > 0 {
		cfg.Domains.Polluted = ov.Domains.Polluted
	}
	// 权重逐项覆盖：只把显式写出的项应用到默认值上。
	// 用指针区分"没写"和"写了 0"——整体赋值会让漏写的项静默变成 0，
	// 而 0 权重本身是合法配置（比如只想看延迟）。
	if ov.Weights != nil {
		w := cfg.Weights
		if ov.Weights.Latency != nil {
			w.Latency = *ov.Weights.Latency
		}
		if ov.Weights.Stable != nil {
			w.Stable = *ov.Weights.Stable
		}
		if ov.Weights.Prox != nil {
			w.Prox = *ov.Weights.Prox
		}
		if ov.Weights.Cleanness != nil {
			w.Cleanness = *ov.Weights.Cleanness
		}
		cfg.Weights = w
	}
	sum := cfg.Weights.Latency + cfg.Weights.Stable + cfg.Weights.Prox + cfg.Weights.Cleanness
	if math.Abs(sum-1.0) > 0.01 {
		return nil, fmt.Errorf("权重之和必须为 1.00（当前 %.2f）：latency=%.2f stable=%.2f proximity=%.2f cleanness=%.2f",
			sum, cfg.Weights.Latency, cfg.Weights.Stable, cfg.Weights.Prox, cfg.Weights.Cleanness)
	}
	// 阈值同样逐项覆盖，理由与权重一致（区分"没写"与"写了 0/false"）。
	if ov.Thresholds != nil {
		cfg.Thresholds = ov.Thresholds.apply(cfg.Thresholds)
	}
	if err := cfg.Thresholds.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// weightsOverride 用指针区分"配置里没写这一项"和"显式写了 0"。
type weightsOverride struct {
	Latency   *float64 `yaml:"latency"`
	Stable    *float64 `yaml:"stable"`
	Prox      *float64 `yaml:"proximity"`
	Cleanness *float64 `yaml:"cleanness"`
}

// thresholdsOverride 与 weightsOverride 同理：区分"没写"与"写了 0/false"。
type thresholdsOverride struct {
	QPS               *float64 `yaml:"qps"`
	TimeoutMS         *int     `yaml:"timeout_ms"`
	RecTimeoutMS      *int     `yaml:"rec_timeout_ms"`
	Retries           *int     `yaml:"retries"`
	Warmup            *int     `yaml:"warmup"`
	SamplesFast       *int     `yaml:"samples_fast"`
	SamplesFull       *int     `yaml:"samples_full"`
	RecRounds         *int     `yaml:"rec_rounds"`
	UDPBufSize        *int     `yaml:"udp_buf_size"`
	PollutionRTTMS    *int     `yaml:"pollution_rtt_ms"`
	PollutionRepeat   *int     `yaml:"pollution_repeat"`
	MaxIPsPerDomain   *int     `yaml:"max_ips_per_domain"`
	TTFBDomains       *int     `yaml:"ttfb_domains"`
	CDNFast           *int     `yaml:"cdn_fast"`
	CDNFull           *int     `yaml:"cdn_full"`
	ConsistencyN      *int     `yaml:"consistency_domains"`
	TCPTimeoutMS      *int     `yaml:"tcp_timeout_ms"`
	DoHTimeoutMS      *int     `yaml:"doh_timeout_ms"`
	ResolutionDelayMS *int     `yaml:"resolution_delay_ms"`
	AuxEnabled        *bool    `yaml:"aux_probes"`
}

func (o *thresholdsOverride) apply(base Thresholds) Thresholds {
	t := base
	seti := func(dst *int, src *int) {
		if src != nil {
			*dst = *src
		}
	}
	setf := func(dst *float64, src *float64) {
		if src != nil {
			*dst = *src
		}
	}
	seti(&t.TimeoutMS, o.TimeoutMS)
	seti(&t.RecTimeoutMS, o.RecTimeoutMS)
	seti(&t.Retries, o.Retries)
	seti(&t.Warmup, o.Warmup)
	seti(&t.SamplesFast, o.SamplesFast)
	seti(&t.SamplesFull, o.SamplesFull)
	seti(&t.RecRounds, o.RecRounds)
	seti(&t.UDPBufSize, o.UDPBufSize)
	seti(&t.PollutionRTTMS, o.PollutionRTTMS)
	seti(&t.PollutionRepeat, o.PollutionRepeat)
	seti(&t.MaxIPsPerDomain, o.MaxIPsPerDomain)
	seti(&t.TTFBDomains, o.TTFBDomains)
	seti(&t.CDNFast, o.CDNFast)
	seti(&t.CDNFull, o.CDNFull)
	seti(&t.ConsistencyN, o.ConsistencyN)
	seti(&t.TCPTimeoutMS, o.TCPTimeoutMS)
	seti(&t.DoHTimeoutMS, o.DoHTimeoutMS)
	seti(&t.ResolutionDelayMS, o.ResolutionDelayMS)
	setf(&t.QPS, o.QPS)
	if o.AuxEnabled != nil {
		t.AuxEnabled = *o.AuxEnabled
	}
	return t
}

// validate 拦住会让测量失去意义的取值（0 次样本、0 QPS、0 超时等）。
func (t Thresholds) validate() error {
	switch {
	case t.QPS <= 0:
		return fmt.Errorf("thresholds.qps 必须 > 0（当前 %v）", t.QPS)
	case t.TimeoutMS <= 0:
		return fmt.Errorf("thresholds.timeout_ms 必须 > 0（当前 %d）", t.TimeoutMS)
	case t.RecTimeoutMS <= 0:
		return fmt.Errorf("thresholds.rec_timeout_ms 必须 > 0（当前 %d）", t.RecTimeoutMS)
	case t.Retries < 0:
		return fmt.Errorf("thresholds.retries 不能为负（当前 %d）", t.Retries)
	case t.Warmup < 0:
		return fmt.Errorf("thresholds.warmup 不能为负（当前 %d）", t.Warmup)
	case t.SamplesFast < 1:
		return fmt.Errorf("thresholds.samples_fast 必须 >= 1（当前 %d）", t.SamplesFast)
	case t.SamplesFull < 1:
		return fmt.Errorf("thresholds.samples_full 必须 >= 1（当前 %d）", t.SamplesFull)
	case t.MaxIPsPerDomain < 1:
		return fmt.Errorf("thresholds.max_ips_per_domain 必须 >= 1（当前 %d）", t.MaxIPsPerDomain)
	case t.PollutionRepeat < 1:
		return fmt.Errorf("thresholds.pollution_repeat 必须 >= 1（当前 %d）", t.PollutionRepeat)
	case t.CDNFast < 1 || t.CDNFull < 1:
		return fmt.Errorf("thresholds.cdn_fast/cdn_full 必须 >= 1（当前 %d/%d）", t.CDNFast, t.CDNFull)
	case t.TCPTimeoutMS <= 0:
		return fmt.Errorf("thresholds.tcp_timeout_ms 必须 > 0（当前 %d）", t.TCPTimeoutMS)
	case t.DoHTimeoutMS <= 0:
		return fmt.Errorf("thresholds.doh_timeout_ms 必须 > 0（当前 %d）", t.DoHTimeoutMS)
	}
	return nil
}

// CDNSet 返回用于就近性测试的域名集（web+video+cdn 合并）。
func (c *Config) CDNSet() []string {
	out := []string{}
	out = append(out, c.Domains.Web...)
	out = append(out, c.Domains.Video...)
	out = append(out, c.Domains.CDN...)
	return out
}

// ThresholdDoc 返回阈值与依据的 Markdown 表，供 --list-thresholds 打印与文档复用。
func ThresholdDoc() string {
	var b strings.Builder
	b.WriteString("dnspick 测量阈值与依据（可用 --dump-config 生成模板后按需覆盖）\n\n")
	b.WriteString("| 阈值 | 默认值 | 依据 |\n")
	b.WriteString("| --- | --- | --- |\n")
	rows := [][3]string{
		{"qps", "5", "自我限速，避免被上游当成攻击源（RFC 4697 观察法；无强制值）"},
		{"timeout_ms", "2000", "公共 DNS 正常在亚秒级；2s 足以区分超时与高延迟（RFC 4697）"},
		{"rec_timeout_ms", "3000", "递归路径更长，需覆盖 NXDOMAIN 递归耗时（RFC 2308）"},
		{"retries", "1", "瞬时丢包不应直接判失败，但重试过多会掩盖丢包（RFC 4697 §4）"},
		{"warmup", "2", "丢弃首查的冷启动/连接建立样本"},
		{"samples_fast", "8", "快速模式：足够估中位数，不足以准确估 P95"},
		{"samples_full", "30", "完整模式：n>=30 时依中心极限定理可用正态近似估 P95 与 95%CI"},
		{"rec_rounds", "5", "随机子域名法每轮域名唯一，防缓存（RFC 4697）"},
		{"udp_buf_size", "1232", "EDNS0 建议载荷，避免分片（RFC 6891 / DNS Flag Day 2020）"},
		{"pollution_rtt_ms", "20", "真递归不可能在 20ms 内完成，低于此值且答案不符即判污染"},
		{"pollution_repeat", "3", "单次判定噪声大，需重复验证后才计一次命中"},
		{"max_ips_per_domain", "3", "每域名抽样 IP 上限：控制时长并去掉「总取应答前几条」的偏好"},
		{"ttfb_domains", "5", "每端点测 TTFB 的域名数"},
		{"cdn_fast", "8", "快速模式就近性域名数"},
		{"cdn_full", "20", "完整模式就近性域名数"},
		{"consistency_domains", "3", "结果一致性检测的域名数"},
		{"tcp_timeout_ms", "3000", "CDN 边缘 TCP443 握手超时"},
		{"doh_timeout_ms", "6000", "DoH 走 HTTPS，需覆盖 TLS 握手（RFC 8484）"},
		{"resolution_delay_ms", "250", "Happy Eyeballs ResolutionDelay（RFC 8305 §8）"},
		{"aux_probes", "true", "是否执行 DNSSEC / NSID / 双栈辅助探测（--no-aux 可关）"},
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r[0], r[1], r[2])
	}
	return b.String()
}

// WriteDefaultTemplate 将默认配置写出为带注释的 YAML 模板，方便用户自行修改。
// 手写模板而非 yaml.Marshal：Marshal 产出零注释，"servers 会整体替换内置列表"
// 这类关键语义只能写在注释里。
func WriteDefaultTemplate(path string) error {
	return os.WriteFile(path, []byte(defaultTemplateYAML), 0o644)
}

const defaultTemplateYAML = `# dnspick 配置模板（由 dnspick --dump-config 生成）
#
# 用法：dnspick --config dnspick.yaml
# 规则：任一顶层段（servers / domains / weights / thresholds）缺失时，该段使用内置默认值；
#       某段一旦写出，段内的列表/字段按下方说明覆盖。

# ── 候选 DNS ───────────────────────────────────────────────────────────
# 注意：一旦提供 servers，就会「整体替换」内置候选列表（不是追加）。
# 想在默认 9 个候选之上增加，请复制下方全部条目后再追加自己的条目。
servers:
  - name: 腾讯DNSPod            # 展示名（必填）
    ips: ["119.29.29.29", "182.254.116.116"]   # IPv4 入口（必填，至少一项）
    ipv6: ["2402:4e00::"]                      # IPv6 入口（可选）
    doh: https://doh.pub/dns-query             # DoH 入口（可选，RFC 8484）
    dot: dot.pub:853                           # DoT 入口（可选，RFC 7858）
    region: 境内                                # 归属备注（可选）
  - name: 阿里AliDNS
    ips: ["223.5.5.5", "223.6.6.6"]
    ipv6: ["2400:3200::1", "2400:3200:baba::1"]
    doh: https://dns.alidns.com/dns-query
    dot: dns.alidns.com:853
    region: 境内
  - name: 114DNS
    ips: ["114.114.114.114", "114.114.115.115"]
    region: 境内
  - name: 360DNS
    ips: ["101.226.4.6", "123.125.81.6"]
    doh: https://doh.360.cn/dns-query
    region: 境内
  - name: 百度DNS
    ips: ["180.76.76.76"]
    doh: https://dns.baidu.com/dns-query
    region: 境内
  - name: CNNIC SDNS
    ips: ["1.2.4.8", "210.2.4.8"]
    region: 境内
  - name: Google
    ips: ["8.8.8.8", "8.8.4.4"]
    ipv6: ["2001:4860:4860::8888"]
    doh: https://dns.google/dns-query
    dot: dns.google:853
    region: 境外
  - name: Cloudflare
    ips: ["1.1.1.1", "1.0.0.1"]
    ipv6: ["2606:4700:4700::1111"]
    doh: https://cloudflare-dns.com/dns-query
    dot: one.one.one.one:853
    region: 境外
  - name: Quad9
    ips: ["9.9.9.9"]
    ipv6: ["2620:fe::fe"]
    doh: https://dns.quad9.net/dns-query
    dot: dns.quad9.net:853
    region: 境外

# ── 探测域名 ───────────────────────────────────────────────────────────
domains:
  web: ["www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com", "www.bilibili.com"]
  video: ["v.qq.com", "www.iqiyi.com", "www.douyin.com"]
  cdn: ["img.alicdn.com", "dl.google.com", "mirrors.tuna.tsinghua.edu.cn"]
  polluted: ["www.youtube.com", "twitter.com", "www.facebook.com", "www.instagram.com",
             "www.wikipedia.org", "www.reddit.com", "news.ycombinator.com"]

# ── 评分权重（四项之和必须为 1.00）────────────────────────────────────
weights:
  latency: 0.35      # 延迟
  stable: 0.20       # 稳定
  proximity: 0.30    # 就近
  cleanness: 0.15    # 干净

# ── 测量阈值（写哪项覆盖哪项，未写的用内置默认）──────────────────────
# 各项依据见 dnspick --list-thresholds
thresholds:
  qps: 5
  timeout_ms: 2000
  rec_timeout_ms: 3000
  retries: 1
  warmup: 2
  samples_fast: 8
  samples_full: 30
  rec_rounds: 5
  udp_buf_size: 1232
  pollution_rtt_ms: 20
  pollution_repeat: 3
  max_ips_per_domain: 3
  ttfb_domains: 5
  cdn_fast: 8
  cdn_full: 20
  consistency_domains: 3
  tcp_timeout_ms: 3000
  doh_timeout_ms: 6000
  resolution_delay_ms: 250
  aux_probes: true
`
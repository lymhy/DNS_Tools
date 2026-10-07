// Package config 负责 YAML 配置加载与内置默认值（候选 DNS、探测域名、评分权重）。
package config

import (
	"fmt"
	"math"
	"os"

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

// Config 是顶层配置。
type Config struct {
	Servers []Server `yaml:"servers"`
	Domains Domains  `yaml:"domains"`
	Weights Weights  `yaml:"weights"`
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
		Weights: Weights{Latency: 0.35, Stable: 0.20, Prox: 0.30, Cleanness: 0.15},
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
		Servers []Server         `yaml:"servers"`
		Domains Domains          `yaml:"domains"`
		Weights *weightsOverride `yaml:"weights"`
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
	return cfg, nil
}

// weightsOverride 用指针区分"配置里没写这一项"和"显式写了 0"。
type weightsOverride struct {
	Latency   *float64 `yaml:"latency"`
	Stable    *float64 `yaml:"stable"`
	Prox      *float64 `yaml:"proximity"`
	Cleanness *float64 `yaml:"cleanness"`
}

// CDNSet 返回用于就近性测试的域名集（web+video+cdn 合并）。
func (c *Config) CDNSet() []string {
	out := []string{}
	out = append(out, c.Domains.Web...)
	out = append(out, c.Domains.Video...)
	out = append(out, c.Domains.CDN...)
	return out
}

// WriteDefaultTemplate 将默认配置写出为 YAML 模板，方便用户自行修改。
func WriteDefaultTemplate(path string) error {
	data, err := yaml.Marshal(Default())
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dnspick.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadNoPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Weights != (Weights{Latency: 0.35, Stable: 0.20, Prox: 0.30, Cleanness: 0.15}) {
		t.Errorf("默认权重不符：%+v", cfg.Weights)
	}
	if len(cfg.Servers) == 0 {
		t.Error("默认配置应带内置候选 DNS")
	}
}

// 只写一部分权重时，没写的项保持默认值（而不是被清零），写了 0 的项才是真的 0。
func TestLoadPartialWeightsKeepsDefaults(t *testing.T) {
	cfg, err := Load(write(t, "weights:\n  latency: 0.5\n  proximity: 0.15\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Weights{Latency: 0.5, Stable: 0.20, Prox: 0.15, Cleanness: 0.15}
	if cfg.Weights != want {
		t.Errorf("部分覆盖后的权重 = %+v，want %+v", cfg.Weights, want)
	}
}

func TestLoadExplicitZeroWeightIsRespected(t *testing.T) {
	cfg, err := Load(write(t, "weights:\n  latency: 0\n  proximity: 0.65\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Weights.Latency != 0 {
		t.Errorf("显式写的 0 权重应生效，got %v", cfg.Weights.Latency)
	}
}

func TestLoadRejectsWeightsNotSummingToOne(t *testing.T) {
	if _, err := Load(write(t, "weights:\n  latency: 0.9\n")); err == nil {
		t.Error("权重之和不为 1 时应报错，而不是静默按比例算分")
	}
}

func TestLoadOverridesServers(t *testing.T) {
	cfg, err := Load(write(t, "servers:\n  - name: 自定义\n    ips: [192.0.2.1]\n    doh: https://example.com/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "自定义" {
		t.Fatalf("servers 应被整体覆盖，got %+v", cfg.Servers)
	}
	if len(cfg.Domains.Web) == 0 {
		t.Error("没写 domains 时应保留默认域名集")
	}
}

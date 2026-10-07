package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestDefaultThresholdsSane(t *testing.T) {
	th := DefaultThresholds()
	if err := th.validate(); err != nil {
		t.Fatalf("内置默认阈值应通过校验: %v", err)
	}
	if th.SamplesFast != 8 || th.SamplesFull != 30 {
		t.Errorf("默认样本量应为 快速8/完整30，got %d/%d", th.SamplesFast, th.SamplesFull)
	}
	if th.ResolutionDelayMS != 250 {
		t.Errorf("ResolutionDelay 应为 RFC 8305 §8 的 250ms，got %d", th.ResolutionDelayMS)
	}
}

// 只写一部分阈值时，没写的项保持默认值（而不是被清零），写了 0/false 的才是真的覆盖。
func TestLoadPartialThresholdsKeepsDefaults(t *testing.T) {
	cfg, err := Load(write(t, "thresholds:\n  samples_full: 50\n  aux_probes: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.SamplesFull != 50 {
		t.Errorf("显式写的 samples_full 应生效，got %d", cfg.Thresholds.SamplesFull)
	}
	if cfg.Thresholds.SamplesFast != 8 {
		t.Errorf("没写的 samples_fast 应保持默认 8，got %d", cfg.Thresholds.SamplesFast)
	}
	if cfg.Thresholds.AuxEnabled {
		t.Error("显式写的 aux_probes: false 应生效")
	}
	if cfg.Thresholds.TimeoutMS != 2000 {
		t.Errorf("没写的 timeout_ms 应保持默认 2000，got %d", cfg.Thresholds.TimeoutMS)
	}
}

func TestLoadRejectsInvalidThresholds(t *testing.T) {
	bad := []string{
		"thresholds:\n  samples_full: 0\n",
		"thresholds:\n  qps: 0\n",
		"thresholds:\n  timeout_ms: 0\n",
		"thresholds:\n  max_ips_per_domain: 0\n",
	}
	for _, body := range bad {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("非法阈值应报错，而不是静默按 0 测量：%q", body)
		}
	}
}

// 导出的模板必须能被 Load 解析回来，否则用户 --dump-config 后一用就报错。
func TestDefaultTemplateIsLoadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dnspick.yaml")
	if err := WriteDefaultTemplate(p); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("模板应可被 Load 解析: %v", err)
	}
	if cfg.Thresholds != DefaultThresholds() {
		t.Errorf("模板中的阈值应等于内置默认，got %+v", cfg.Thresholds)
	}
	if cfg.Weights != Default().Weights {
		t.Errorf("模板中的权重应等于内置默认，got %+v", cfg.Weights)
	}
	if len(cfg.Servers) != len(Default().Servers) {
		t.Errorf("模板应包含全部内置候选，got %d", len(cfg.Servers))
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("#")) {
		t.Error("模板应包含说明性注释（手写模板而非 yaml.Marshal 的意义所在）")
	}
}

func TestThresholdDocListsAllFields(t *testing.T) {
	doc := ThresholdDoc()
	for _, k := range []string{"qps", "samples_full", "pollution_repeat", "resolution_delay_ms", "aux_probes"} {
		if !strings.Contains(doc, k) {
			t.Errorf("阈值依据表应包含 %q", k)
		}
	}
}

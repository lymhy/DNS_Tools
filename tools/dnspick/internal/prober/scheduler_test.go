package prober

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// 分位数口径已切到 R-7 线性插值：偶样本下的中位数是两中值的平均。
// 次序统计量版本会返回 [10,20,30,40] 的 20，并非真中位。
func TestPercentileAndMedian(t *testing.T) {
	samples := []float64{30, 10, 20, 40}
	if got := Median(samples); got != 25 {
		t.Errorf("Median = %v, want 25（R-7 真中位）", got)
	}
	if got := Percentile(samples, 100); got != 40 {
		t.Errorf("P100 = %v, want 40", got)
	}
	if got := Percentile(samples, 0); got != 10 {
		t.Errorf("P0 = %v, want 10", got)
	}
	if got := Median(nil); got != 0 {
		t.Errorf("空样本应为 0，got %v", got)
	}
	// 不能改动调用方切片
	if samples[0] != 30 {
		t.Errorf("Percentile 不应重排入参，got %v", samples)
	}
}

// 递归延迟靠"每次都不一样的随机子域名"防缓存：一旦重复，
// 测到的就是缓存命中而不是递归。
func TestRandomSubdomainIsUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		name := RandomSubdomain("baidu.com")
		if !strings.HasSuffix(name, ".probe.baidu.com") {
			t.Fatalf("格式不对: %q", name)
		}
		if strings.HasPrefix(name, ".probe.") {
			t.Fatalf("随机部分为空: %q", name)
		}
		if seen[name] {
			t.Fatalf("出现重复的随机域名: %q", name)
		}
		seen[name] = true
	}
}

func TestRateLimiterSpacing(t *testing.T) {
	rl := newRateLimiter(50) // 20ms 间隔
	start := time.Now()
	rl.wait("ep")
	rl.wait("ep")
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Errorf("同一端点连续查询应被限速，实际间隔 %v", d)
	}
	// 不同端点之间不互相限速
	start = time.Now()
	rl.wait("other")
	if d := time.Since(start); d > 10*time.Millisecond {
		t.Errorf("不同端点不应互相限速，实际等待 %v", d)
	}
}

// stubQ 是可控的 Querier：firstFail 表示"仅首次尝试失败"。
type stubQ struct {
	alwaysFail bool
	firstFail  bool
	calls      int
}

func (s *stubQ) QueryA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	s.calls++
	if s.alwaysFail || (s.firstFail && s.calls == 1) {
		return nil, 0, errors.New("stub failure")
	}
	return []string{"192.0.2.10"}, 10 * time.Millisecond, nil
}

func (s *stubQ) QueryAAAA(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	return s.QueryA(ep, name, timeout)
}

func (s *stubQ) QueryTXT(ep Endpoint, name string, timeout time.Duration) ([]string, time.Duration, error) {
	return nil, 0, nil
}

func (s *stubQ) QueryNSViaTCP(name string, timeout time.Duration) ([]string, error) {
	return nil, nil
}

func (s *stubQ) QueryWithECS(ep Endpoint, name string, ecsNet net.IPNet, timeout time.Duration) ([]string, time.Duration, error) {
	return nil, 0, nil
}

func (s *stubQ) QueryWithDO(ep Endpoint, name string, timeout time.Duration) (*DNSSECReply, error) {
	return &DNSSECReply{}, nil
}

func (s *stubQ) QueryNSID(ep Endpoint, timeout time.Duration) (string, error) {
	return "", nil
}

func (s *stubQ) QueryCHAOS(ep Endpoint, name string, timeout time.Duration) ([]string, error) {
	return nil, nil
}

// 丢包率统计"首次尝试"，不受失败重试影响：重试成功仍记 1 次丢包，但不记 Failed。
func TestPhase1PacketLossCountsFirstAttempt(t *testing.T) {
	ep := Endpoint{Server: "X", Address: "192.0.2.1", Proto: UDP}
	q := &stubQ{firstFail: true}
	r := NewRunner(q, []Endpoint{ep}, false, nil)
	r.TH.Retries = 1
	r.SetSamples(1)
	r.Warmup = 0
	r.Phase1Latency([]string{"example.com"}, time.Second)

	m := r.Metrics(ep)
	if m.Attempts != 1 {
		t.Fatalf("应有 1 次尝试，got %d", m.Attempts)
	}
	if m.FirstFail != 1 {
		t.Errorf("首次尝试失败应记 1，got %d", m.FirstFail)
	}
	if m.Failed != 0 {
		t.Errorf("重试成功后不应记 Failed，got %d", m.Failed)
	}
	if m.PacketLoss != 1 {
		t.Errorf("丢包率 = %v, want 1（首次尝试即丢）", m.PacketLoss)
	}
	if m.SampleN != 1 || len(m.cache) != 1 {
		t.Errorf("重试成功应留下 1 个有效样本，got SampleN=%d", m.SampleN)
	}
	if m.Success != 1 {
		t.Errorf("成功率按最终成败算，应为 1，got %v", m.Success)
	}
}

// 样本量来自阈值：完整模式默认 30，--samples 覆盖并 clamp 到 [1,200]。
func TestSamplesFromThresholdAndClamp(t *testing.T) {
	full := NewRunner(nil, nil, true, nil)
	if full.Samples != 30 {
		t.Errorf("完整模式默认样本应为 30，got %d", full.Samples)
	}
	fast := NewRunner(nil, nil, false, nil)
	if fast.Samples != 8 {
		t.Errorf("快速模式默认样本应为 8，got %d", fast.Samples)
	}
	fast.SetSamples(999)
	if fast.Samples != 200 {
		t.Errorf("样本量应 clamp 到 200，got %d", fast.Samples)
	}
	fast.SetSamples(0) // 0 = 不覆盖
	if fast.Samples != 200 {
		t.Errorf("SetSamples(0) 不应改动，got %d", fast.Samples)
	}
	full.SetSamples(12)
	if full.Samples != 12 {
		t.Errorf("--samples 应覆盖模式默认，got %d", full.Samples)
	}
}

package prober

import (
	"strings"
	"testing"
	"time"
)

func TestPercentileAndMedian(t *testing.T) {
	samples := []float64{30, 10, 20, 40}
	if got := Median(samples); got != 20 {
		t.Errorf("Median = %v, want 20", got)
	}
	if got := Percentile(samples, 100); got != 40 {
		t.Errorf("P100 = %v, want 40", got)
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

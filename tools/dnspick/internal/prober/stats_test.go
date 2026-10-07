package prober

import (
	"math"
	"reflect"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestPercentileR7(t *testing.T) {
	samples := []float64{30, 10, 20, 40}
	// 真中位：R-7 下 [10,20,30,40] 的 P50 = 20 + 0.5*(30-20) = 25
	if got := PercentileR7(samples, 50); !almost(got, 25) {
		t.Errorf("P50 = %v, want 25", got)
	}
	if got := PercentileR7(samples, 0); !almost(got, 10) {
		t.Errorf("P0 = %v, want 10", got)
	}
	if got := PercentileR7(samples, 100); !almost(got, 40) {
		t.Errorf("P100 = %v, want 40", got)
	}
	if got := PercentileR7(samples, 95); got < 30 || got > 40 {
		t.Errorf("P95 应落在 [30,40]，got %v", got)
	}
	if got := PercentileR7(nil, 50); got != 0 {
		t.Errorf("空样本应为 0，got %v", got)
	}
	// 不能改动调用方切片
	if samples[0] != 30 {
		t.Errorf("PercentileR7 不应重排入参，got %v", samples)
	}
}

func TestStdDevAndCI(t *testing.T) {
	s := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	if got := StdDev(s); math.Abs(got-2.13809) > 1e-4 {
		t.Errorf("样本标准差 = %v, want 2.13809", got)
	}
	if got := StdDev([]float64{5}); got != 0 {
		t.Errorf("n=1 应返回 0，got %v", got)
	}
	if got := CI95HalfWidth([]float64{5}); got != 0 {
		t.Errorf("n=1 无置信区间，应返回 0，got %v", got)
	}
	// 样本量越大，均值置信区间应越窄（同分布）
	var big []float64
	for i := 0; i < 40; i++ {
		big = append(big, s[i%len(s)])
	}
	if CI95HalfWidth(big) >= CI95HalfWidth(s) {
		t.Errorf("n=%d 的 CI 半宽应小于 n=%d", len(big), len(s))
	}
}

func TestSampleSubsetIsDeterministicAndBounded(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	a := SampleSubset(items, 3, 42)
	b := SampleSubset(items, 3, 42)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("同 seed 结果应一致：%v vs %v", a, b)
	}
	if len(a) != 3 {
		t.Fatalf("应取 3 个，got %d", len(a))
	}
	// 每个元素都必须来自原集合，且不重复
	seen := map[string]bool{}
	for _, v := range a {
		if seen[v] {
			t.Errorf("抽样出现重复元素 %q", v)
		}
		seen[v] = true
		if !contains(items, v) {
			t.Errorf("抽样出现不属于原集合的元素 %q", v)
		}
	}
	// k >= len 时返回原序副本
	if got := SampleSubset(items, len(items), 7); !reflect.DeepEqual(got, items) {
		t.Errorf("k>=len 应返回原序副本，got %v", got)
	}
	// 副本可改，不影响入参
	cp := SampleSubset(items, len(items), 7)
	cp[0] = "zzz"
	if items[0] != "a" {
		t.Error("SampleSubset 应返回副本，不应改动入参")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
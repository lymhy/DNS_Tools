package prober

import (
	"math"
	"math/rand"
	"sort"
)

// Mean 算术平均；空样本返回 0。
func Mean(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range samples {
		sum += v
	}
	return sum / float64(len(samples))
}

// StdDev 样本标准差（分母 n-1，无偏估计）；n<2 返回 0。
func StdDev(samples []float64) float64 {
	n := len(samples)
	if n < 2 {
		return 0
	}
	mean := Mean(samples)
	var ss float64
	for _, v := range samples {
		d := v - mean
		ss += d * d
	}
	return math.Sqrt(ss / float64(n-1))
}

// t975 是 t 分布双侧 95% 的临界值，按自由度 1..30 索引（index 0 占位）。
var t975 = []float64{
	0,
	12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
	2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
	2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
}

// CI95HalfWidth 返回均值的 95% 置信区间半宽 = t(n-1, 0.975) * s / sqrt(n)。
// n<2 时无法估计离散度，返回 0；n-1>30 用正态近似 1.96。
func CI95HalfWidth(samples []float64) float64 {
	n := len(samples)
	if n < 2 {
		return 0
	}
	t := 1.96
	if df := n - 1; df < len(t975) {
		t = t975[df]
	}
	return t * StdDev(samples) / math.Sqrt(float64(n))
}

// PercentileR7 取 R-7 线性插值分位数（与 numpy / Excel PERCENTILE.INC 一致）。
// 相比次序统计量，偶样本下的中位数是真正的中位（两中值平均），
// 小样本估 P95 也不会总是落在最大值上。
func PercentileR7(samples []float64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	if p <= 0 {
		return s[0]
	}
	if p >= 100 {
		return s[len(s)-1]
	}
	h := float64(len(s)-1) * p / 100
	lo := int(math.Floor(h))
	if lo+1 >= len(s) {
		return s[len(s)-1]
	}
	return s[lo] + (h-float64(lo))*(s[lo+1]-s[lo])
}

// SampleSubset 用 seed 做确定性洗牌后取前 k 个，用于去掉"总取应答前几条"的
// 系统性偏好，同时保证同一 seed 下结果可复现。k<=0 或 k>=len(items) 时
// 返回原序副本（调用方拿到的是副本，改它不影响入参）。
func SampleSubset(items []string, k int, seed int64) []string {
	out := append([]string(nil), items...)
	if k <= 0 || k >= len(out) {
		return out
	}
	r := rand.New(rand.NewSource(seed))
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:k]
}
package checker

import (
	"testing"

	"github.com/miekg/dns"

	"dnspick/internal/prober"
)

// 反向 DNSSEC 判定：只有"对签名失效域名返回 SERVFAIL"才算真验证；
// 无法判定（nil）时不能判为验证型。
func TestDNSSECStrict(t *testing.T) {
	if dnssecStrict(nil) {
		t.Error("无法判定（nil）时不应判为严格验证")
	}
	if !dnssecStrict(&prober.DNSSECReply{RCode: dns.RcodeServerFailure}) {
		t.Error("对签名失效域名 SERVFAIL 应判为严格验证")
	}
	if dnssecStrict(&prober.DNSSECReply{RCode: dns.RcodeSuccess}) {
		t.Error("返回了答案不应判为严格验证")
	}
}

func TestAAAAFailRate(t *testing.T) {
	if got := aaaaFailRate(0, 0); got != 0 {
		t.Errorf("无查询应返回 0，got %v", got)
	}
	if got := aaaaFailRate(3, 1); got != 0.25 {
		t.Errorf("3 成 1 败应为 0.25，got %v", got)
	}
	if got := aaaaFailRate(0, 4); got != 1 {
		t.Errorf("全失败应为 1，got %v", got)
	}
}

func TestPreferredFamily(t *testing.T) {
	cases := []struct {
		v4, v6 float64
		delay  int
		want   int
	}{
		{20, 22, 250, 0},  // 差值在 ResolutionDelay 内 → 不做倾向
		{20, 0, 250, 0},   // 缺 v6 样本 → 0
		{0, 20, 250, 0},   // 缺 v4 样本 → 0
		{500, 20, 250, 1}, // v6 明显更快 → 倾向 v6
		{20, 500, 250, -1}, // v4 明显更快 → 倾向 v4
	}
	for _, c := range cases {
		if got := preferredFamily(c.v4, c.v6, c.delay); got != c.want {
			t.Errorf("preferredFamily(%v,%v,%d) = %d, want %d", c.v4, c.v6, c.delay, got, c.want)
		}
	}
}

// NSID 重复判定：大小写归一后相同的算重复；空串（未返回）不参与统计。
func TestNSIDDuplicates(t *testing.T) {
	got := nsidDuplicates(map[string]string{
		"a": "AbCd",
		"b": "abcd", // 与 a 归一化后相同 → 重复
		"c": "ef01",
		"d": "", // 未返回 NSID，不参与统计
	})
	if !got["abcd"] {
		t.Error("大小写不同的同一 NSID 应判为重复")
	}
	if got["ef01"] {
		t.Error("唯一 NSID 不应判为重复")
	}
	if len(got) != 1 {
		t.Errorf("应只有 1 个重复 NSID，got %v", got)
	}
}
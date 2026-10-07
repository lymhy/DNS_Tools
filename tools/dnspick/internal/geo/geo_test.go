package geo

import "testing"

// 没有 ip2region 库（New 传入不存在的路径 → avail=false）时，私网/环回/保留地址
// 仍应给出人能看懂的标签，而不是 "未知" 或 "Reserved Reserved"。
func TestDescribeReservedWithoutDB(t *testing.T) {
	l := New("testdata/does-not-exist.xdb")
	if l.Available() {
		t.Fatal("库不存在时不应报告可用")
	}
	cases := map[string]string{
		"192.168.100.1":   "内网",
		"10.0.0.1":        "内网",
		"172.16.0.1":      "内网",
		"fd00::1":         "内网",
		"fe80::1":         "内网",
		"127.0.0.1":       "本机",
		"::1":             "本机",
		"0.0.0.0":         "保留地址",
		"224.0.0.251":     "保留地址",
		"203.0.113.7":     "未知", // 没有库时公网地址查不出来，只能标未知
		"2402:4e00::1111": "未知",
	}
	for ip, want := range cases {
		if got := l.Describe(ip); got != want {
			t.Errorf("Describe(%q) = %q, 期望 %q", ip, got, want)
		}
	}
}

func TestProvinceUnavailable(t *testing.T) {
	l := New("testdata/does-not-exist.xdb")
	if got := l.Province("203.0.113.7"); got != "" {
		t.Errorf("无库时 Province 应为空，得到 %q", got)
	}
	if got := l.Summary(); got == "" {
		t.Error("Summary 不应为空")
	}
}

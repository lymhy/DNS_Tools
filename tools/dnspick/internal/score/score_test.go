package score

import (
	"testing"

	"dnspick/internal/config"
	"dnspick/internal/prober"
)

func testWeights() *config.Weights {
	return &config.Weights{Latency: 0.35, Stable: 0.20, Prox: 0.30, Cleanness: 0.15}
}

// 全部超时/失败的端点不能拿到默认干净分，也不能被推荐。
// 这是体检发现的头号问题：4 个 DoH 端点全部 0% 成功率却因"干净度默认 100"
// 拿到 0.15×100 = 15 分，排在一起看起来像正常结果。
func TestUnusableEndpointScoresZeroAndIsNotRecommended(t *testing.T) {
	eps := []prober.Endpoint{
		{Server: "全超时DNS", Address: "10.255.255.1", Proto: prober.UDP},
		{Server: "正常DNS", Address: "10.255.255.2", Proto: prober.UDP},
	}
	r := prober.NewRunner(nil, eps, false, nil)
	m := r.Metrics(eps[1])
	m.CacheP50, m.Success = 20, 1

	rows := Score(r, testWeights(), false)
	if rows[0].Endpoint.Server != "正常DNS" {
		t.Fatalf("有数据的端点应排在前面，got %q", rows[0].Endpoint.Server)
	}
	dead := rows[1]
	if dead.Usable {
		t.Error("全部失败的端点不应被标记为可用")
	}
	if dead.CleanScore != 0 {
		t.Errorf("没测到数据不能拿默认干净分，CleanScore=%v", dead.CleanScore)
	}
	if dead.Total != 0 {
		t.Errorf("没测到数据总分应为 0，Total=%v", dead.Total)
	}
	if dead.RecommendMain || dead.RecommendBack {
		t.Error("无数据端点不应参与主备推荐")
	}
	if dead.Rank != 0 {
		t.Errorf("无数据端点不应占名次（显示 -），Rank=%d", dead.Rank)
	}
	if rows[0].Rank != 1 {
		t.Errorf("唯一可用端点应是第 1 名，Rank=%d", rows[0].Rank)
	}
}

// 主用优先选干净度满分者（哪怕不是总分第一），备用必须换一家运营商，
// 系统基线不参与主备。
func TestMainPrefersCleanAndBackupDiffersOperator(t *testing.T) {
	eps := []prober.Endpoint{
		{Server: "腾讯DNSPod", Address: "119.29.29.29", Proto: prober.UDP},
		{Server: "阿里AliDNS", Address: "223.5.5.5", Proto: prober.UDP},
		{Server: "当前系统DNS", Address: "192.168.1.1", Proto: prober.UDP, IsSystem: true},
	}
	r := prober.NewRunner(nil, eps, false, nil)
	fastDirty := r.Metrics(eps[0])
	fastDirty.CacheP50, fastDirty.Success = 10, 1
	fastDirty.PollutionTotal, fastDirty.PollutionHits = 5, 1 // 干净分 80
	slowClean := r.Metrics(eps[1])
	slowClean.CacheP50, slowClean.Success = 12, 1
	base := r.Metrics(eps[2])
	base.CacheP50, base.Success = 1, 1

	rows := Score(r, testWeights(), false)
	if rows[0].Endpoint.Server != "腾讯DNSPod" {
		t.Errorf("总分第一应是更快但被污染的腾讯，got %q", rows[0].Endpoint.Server)
	}
	var main, back *Row
	for _, row := range rows {
		if row.RecommendMain {
			main = row
		}
		if row.RecommendBack {
			back = row
		}
	}
	if main == nil || main.Endpoint.Server != "阿里AliDNS" {
		t.Fatalf("干净度满分者应优先主用，got %v", main)
	}
	if back == nil || back.Endpoint.Server != "腾讯DNSPod" {
		t.Fatalf("备用应来自另一家运营商，got %v", back)
	}
	if rows[len(rows)-1].Endpoint.Server != "当前系统DNS" {
		t.Errorf("本地基线应排在最后且不占名次，got %q（rank=%d）",
			rows[len(rows)-1].Endpoint.Server, rows[len(rows)-1].Rank)
	}
	if rows[len(rows)-1].Rank != 0 {
		t.Errorf("本地基线不应有名次，Rank=%d", rows[len(rows)-1].Rank)
	}
}

// 指标完全相同时排名必须稳定（sort.Slice 不稳定，需要显式 tie-break）。
func TestRankingIsDeterministicOnTies(t *testing.T) {
	eps := []prober.Endpoint{
		{Server: "BBB", Address: "203.0.113.2", Proto: prober.UDP},
		{Server: "AAA", Address: "203.0.113.1", Proto: prober.UDP},
	}
	r := prober.NewRunner(nil, eps, false, nil)
	for _, ep := range eps {
		m := r.Metrics(ep)
		m.CacheP50, m.Success = 20, 1
	}
	rows := Score(r, testWeights(), false)
	if rows[0].Endpoint.Label() >= rows[1].Endpoint.Label() {
		t.Errorf("并列时应按端点标签稳定排序，got %q 排在 %q 之前",
			rows[0].Endpoint.Label(), rows[1].Endpoint.Label())
	}
}

// 同一个地址重复出现（系统 DNS 恰好也是内置候选）只保留一行。
func TestDuplicateEndpointsCollapse(t *testing.T) {
	eps := []prober.Endpoint{
		{Server: "当前系统DNS", Address: "114.114.114.114", Proto: prober.UDP, IsSystem: true},
		{Server: "114DNS", Address: "114.114.114.114", Proto: prober.UDP},
	}
	r := prober.NewRunner(nil, eps, false, nil)
	r.Metrics(eps[0]).Success = 1
	if rows := Score(r, testWeights(), false); len(rows) != 1 {
		t.Fatalf("同一地址只应保留一行，got %d 行", len(rows))
	}
}

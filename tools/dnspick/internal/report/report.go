// Package report 输出终端表格 / JSON / CSV，以及一键应用命令（默认 dry-run）。
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"

	"dnspick/internal/prober"
	"dnspick/internal/score"
)

// ReportMeta 是本次运行的测量元数据，随终端报告 / JSON 一并输出，
// 让结果文件自身就能说明"这轮是怎么测的"，便于复现与审计。
type ReportMeta struct {
	Version    string    `json:"version"`
	Mode       string    `json:"mode"` // 快速 / 完整
	Seed       int64     `json:"seed"`
	Samples    int       `json:"samples"`
	Warmup     int       `json:"warmup"`
	QPS        float64   `json:"qps"`
	TimeoutMS  int       `json:"timeout_ms"`
	Retries    int       `json:"retries"`
	AuxEnabled bool      `json:"aux_enabled"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	DurationS  float64   `json:"duration_s"`
}

// Table 渲染终端排名表：按协议组分别成表（每组各自排名、各自推荐主备）。
// caveat 非空时作为醒目提示追加在末尾，让存下来的结果文件自身就说明这轮不可信。
func Table(gr *score.GroupedResult, meta ReportMeta, envSummary, caveat string, full bool) string {
	var buf bytes.Buffer
	fmt.Fprintln(&buf)
	if envSummary != "" {
		fmt.Fprintln(&buf, envSummary)
	}
	fmt.Fprintf(&buf, "测试时间: %s\n", meta.Finished.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&buf, "测量元数据: 版本 v%s | 模式 %s | seed %d | 样本 %d（+热身 %d）| QPS≤%g | 超时 %dms | 重试 %d | 辅助探测 %s | 耗时 %.0fs\n",
		meta.Version, meta.Mode, meta.Seed, meta.Samples, meta.Warmup,
		meta.QPS, meta.TimeoutMS, meta.Retries, onOff(meta.AuxEnabled), meta.DurationS)
	fmt.Fprintln(&buf)

	for _, g := range gr.Groups {
		renderGroup(&buf, g, meta.AuxEnabled, full)
		fmt.Fprintln(&buf)
		switch {
		case g.Main == nil:
			fmt.Fprintf(&buf, "本组建议：没有端点测到有效数据，不做推荐\n")
		case g.Back != nil:
			fmt.Fprintf(&buf, "本组建议：主用 %s，备用 %s\n", dnsCell(g.Main), dnsCell(g.Back))
		default:
			fmt.Fprintf(&buf, "本组建议：主用 %s（未找到跨运营商的备用）\n", dnsCell(g.Main))
		}
		fmt.Fprintln(&buf)
	}

	if caveat != "" {
		fmt.Fprintln(&buf, caveat)
		fmt.Fprintln(&buf)
	}
	fmt.Fprintln(&buf, "口径说明：分位数为 R-7 线性插值（与 numpy/Excel PERCENTILE.INC 一致）；CI± 为均值的 95% 置信区间半宽（t 分布）；名次为「协议组内」排名，跨协议不可比。")

	fmt.Print(buf.String())
	return buf.String()
}

// renderGroup 渲染单个协议组：基线行 + 组内排名表。
func renderGroup(buf *bytes.Buffer, g score.Group, aux, full bool) {
	fmt.Fprintf(buf, "【协议组 %s】\n", g.Proto)
	if base := baseline(g.Rows); base != nil {
		fmt.Fprintf(buf, "本地基线（仅作对比，不参与推荐、不参与归一化基准）：%s 缓存P50 %s、成功率 %.0f%%、同省率 %s\n",
			dnsCell(base), ms(base.CacheP50), base.Success*100, rate(base.SameProvinceRate))
	}

	hdr := []string{"排名", "DNS", "协议", "归属", "缓存P50", "样本n", "丢包", "成功率", "同省率", "TCP中位", "干净度", "总分", "备注"}
	if full {
		hdr = []string{"排名", "DNS", "协议", "归属", "缓存P50", "递归P50", "样本n", "丢包", "CI±",
			"成功率", "同省率", "TCP中位", "TTFB", "NSID", "DNSSEC", "AAAA", "干净度", "总分", "备注"}
	}
	w := tablewriter.NewWriter(buf)
	w.SetHeader(hdr)
	w.SetAutoFormatHeaders(false)
	for _, r := range g.Rows {
		mark := ""
		if r.RecommendMain {
			mark = "◀ 推荐"
		} else if r.RecommendBack {
			mark = "◀ 备用"
		}
		row := []string{
			rank(r), dnsCell(r), string(r.Endpoint.Proto), geo(r.Geo),
			ms(r.CacheP50), sampleN(r), loss(r),
			fmt.Sprintf("%.0f%%", r.Success*100), rate(r.SameProvinceRate), ms(r.TCPMedian),
			clean(r), fmt.Sprintf("%.1f", r.Total),
			mark + " " + strings.Join(r.Flags, ","),
		}
		if full {
			row = []string{
				rank(r), dnsCell(r), string(r.Endpoint.Proto), geo(r.Geo),
				ms(r.CacheP50), ms(r.RecP50), sampleN(r), loss(r), ci(r),
				fmt.Sprintf("%.0f%%", r.Success*100), rate(r.SameProvinceRate), ms(r.TCPMedian), ms(r.TTFBMedian),
				nsidCell(r, aux), dnssecCell(r, aux), aaaaCell(r, aux),
				clean(r), fmt.Sprintf("%.1f", r.Total),
				mark + " " + strings.Join(r.Flags, ","),
			}
		}
		w.Append(row)
	}
	w.Render()
}

func baseline(rows []*score.Row) *score.Row {
	for _, r := range rows {
		if r.Endpoint.IsSystem {
			return r
		}
	}
	return nil
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func geo(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// dnsCell 输出"名称（具体地址）"。同一个名称下可能挂着多个地址（如 DNSPod 的
// 4 个 IPv4、一个 DoH URL），只写名称时排名表里这几行长得一模一样，看不出
// 到底哪一行是哪个 DNS，所以这里把端点地址一并写出来。
func dnsCell(r *score.Row) string {
	if r.Endpoint.Address == "" || r.Endpoint.Address == r.Endpoint.Server {
		return r.Endpoint.Server
	}
	return r.Endpoint.Server + " (" + r.Endpoint.Address + ")"
}

// rank 本地基线不参与名次，显示 "-"。
func rank(r *score.Row) string {
	if r.Rank == 0 {
		return "-"
	}
	return fmt.Sprint(r.Rank)
}

func clean(r *score.Row) string {
	if !r.Usable {
		return "-" // 没有成功测量，没有"干净"可言
	}
	return fmt.Sprint(r.CleanScore)
}

func rate(v float64) string {
	if v < 0 {
		return "-" // 省份未知：不是 0%
	}
	return fmt.Sprintf("%.0f%%", v*100)
}

func ms(v float64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.0fms", v)
}

func sampleN(r *score.Row) string {
	if r.SampleN <= 0 {
		return "-"
	}
	return fmt.Sprint(r.SampleN)
}

// loss 丢包率（首次尝试口径）；无尝试时留 "-" 而不是 0%。
func loss(r *score.Row) string {
	if r.Attempts == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", r.PacketLoss*100)
}

func ci(r *score.Row) string {
	if r.CacheCI95 <= 0 {
		return "-"
	}
	return fmt.Sprintf("±%.1f", r.CacheCI95)
}

func nsidCell(r *score.Row, aux bool) string {
	if !aux || r.NSID == "" {
		return "-"
	}
	return r.NSID
}

func dnssecCell(r *score.Row, aux bool) string {
	if !aux || !r.Usable {
		return "-"
	}
	if r.DNSSECStrict || r.DNSSECAD {
		return "验证"
	}
	return "未验证"
}

func aaaaCell(r *score.Row, aux bool) string {
	if !aux || !r.Usable {
		return "-"
	}
	if r.AAAAFailRate > 0 {
		return fmt.Sprintf("异常%.0f%%", r.AAAAFailRate*100)
	}
	if r.SupportsAAAA {
		return "支持"
	}
	return "-"
}

// JSON 导出完整结果：顶层含 meta 与 groups（分组），results 保留扁平全量（schema 向后兼容）。
func JSON(gr *score.GroupedResult, meta ReportMeta, path string) error {
	groups := make([]map[string]any, 0, len(gr.Groups))
	for _, g := range gr.Groups {
		groups = append(groups, map[string]any{
			"proto":   string(g.Proto),
			"main":    g.Main,
			"back":    g.Back,
			"results": g.Rows,
		})
	}
	out := map[string]any{
		"time":    time.Now().Format(time.RFC3339),
		"meta":    meta,
		"groups":  groups,
		"results": gr.All,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// CSV 导出分组结果。未知值留空而不是写 0 / -1：下游按数值处理时，
// 0 会被当成"延迟极低""同省率 0%"，而它们其实是"没测到"。
// 首行为注释：rank 为协议组内排名（跨协议不可比）。
func CSV(gr *score.GroupedResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	recs := [][]string{
		{"# rank 为协议组内排名；跨协议不可比"},
		{"group", "rank", "server", "endpoint", "proto", "geo", "usable",
			"cache_p50_ms", "rec_p50_ms", "success_rate", "same_province_rate",
			"tcp_median_ms", "ttfb_median_ms", "n_samples", "loss_rate", "ci95_ms",
			"nsid", "dnssec", "aaaa", "clean_score", "total", "flags"},
	}
	for _, g := range gr.Groups {
		for _, r := range g.Rows {
			recs = append(recs, []string{
				string(g.Proto), fmt.Sprint(r.Rank), r.Endpoint.Server, r.Endpoint.Label(), string(r.Endpoint.Proto),
				r.Geo, fmt.Sprint(r.Usable),
				fnum(r.CacheP50), fnum(r.RecP50),
				fmt.Sprintf("%.3f", r.Success), frate(r.SameProvinceRate),
				fnum(r.TCPMedian), fnum(r.TTFBMedian),
				fmt.Sprint(r.SampleN), fmt.Sprintf("%.3f", r.PacketLoss), fnum(r.CacheCI95),
				r.NSID, csvDNSSEC(r), csvAAAA(r),
				fnum(r.CleanScore), fmt.Sprintf("%.1f", r.Total),
				strings.Join(r.Flags, ";"),
			})
		}
	}
	cw := csv.NewWriter(f)
	// WriteAll 内部会 Flush；错误必须显式检查，否则写盘失败会静默返回 nil。
	if err := cw.WriteAll(recs); err != nil {
		f.Close()
		return err
	}
	if err := cw.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func csvDNSSEC(r *score.Row) string {
	if r.DNSSECStrict || r.DNSSECAD {
		return "verified"
	}
	if r.DNSSECRRSIG {
		return "rrsig-unverified"
	}
	return "unverified"
}

func csvAAAA(r *score.Row) string {
	if r.AAAAFailRate > 0 {
		return fmt.Sprintf("%.3f", r.AAAAFailRate)
	}
	if r.SupportsAAAA {
		return "ok"
	}
	return ""
}

func fnum(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", v)
}

func frate(v float64) string {
	if v < 0 {
		return ""
	}
	return fmt.Sprintf("%.3f", v)
}

// ApplyCommands 生成分平台的应用命令；dry 为 true 时只打印。
// 取 udp 组（回退 udp6 组）的主备；udpIP 是 服务器名 -> 首选 UDP IP 的映射
// （推荐主备统一用 IPv4 UDP 地址写入系统）。
func ApplyCommands(gr *score.GroupedResult, ifName string, udpIP map[string]string, dry bool) error {
	main, back := gr.UDPServers()
	if main == nil {
		return fmt.Errorf("没有可推荐的结果")
	}
	servers := []string{}
	for _, r := range []*score.Row{main, back} {
		if r == nil {
			continue
		}
		ip := ""
		if udpIP != nil {
			ip = udpIP[r.Endpoint.Server]
		}
		if ip == "" {
			ip = primaryIP(r)
		}
		if ip == "" {
			continue // 非 UDP 端点没有可写入系统 DNS 的解析器地址
		}
		servers = append(servers, ip)
	}
	if len(servers) == 0 {
		return fmt.Errorf("推荐结果里没有可用的 UDP 解析器地址，无法写入系统 DNS（请把 udp 端点纳入候选：--protocol udp,doh）")
	}
	fmt.Println("\n应用命令（默认 dry-run，仅展示；确认后以管理员执行或加 --apply-force）：")
	var cmds []string
	switch osName := runtimeName(); osName {
	case "windows":
		cmds = append(cmds, fmt.Sprintf(
			`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses %s`,
			ifName, strings.Join(servers, ",")))
	case "darwin":
		// 必须用 networksetup 的"网络服务名"（如 Wi-Fi），不是 BSD 接口名（如 en0）。
		cmds = append(cmds, fmt.Sprintf(`networksetup -setdnsservers "%s" %s`, serviceNameFor(ifName), strings.Join(servers, " ")))
	default:
		cmds = append(cmds, "sudo sh -c 'printf \"nameserver "+strings.Join(servers, "\\nnameserver ")+"\\n\" > /etc/resolv.conf'")
		cmds = append(cmds, "# 或使用 nmcli: nmcli con mod <连接名> ipv4.dns \""+strings.Join(servers, " ")+"\" && nmcli con up <连接名>")
	}
	for _, c := range cmds {
		fmt.Println("  " + c)
	}
	if dry {
		fmt.Println("\n（dry-run 模式未修改系统配置；确认无误后可手动执行以上命令。）")
		return nil
	}
	// 实际应用：仅实现 Windows 与 macOS/Linux 的直接执行，先备份当前 DNS。
	return apply(servers, ifName)
}

// primaryIP 返回可以写进系统 DNS 的解析器地址。
// 只有 UDP/UDP6 端点有这种地址：DoH 端点的 Address 是一个 URL，
// 把它当系统 DNS 写下去会直接把本机解析搞坏，所以这里返回空串，
// 由调用方决定跳过还是报错。
func primaryIP(r *score.Row) string {
	if r.Endpoint.Proto == prober.UDP || r.Endpoint.Proto == prober.UDP6 {
		return r.Endpoint.Address
	}
	return ""
}

// report_unix.go / report_windows.go 提供 apply()、serviceNameFor() 与 runtimeName()。
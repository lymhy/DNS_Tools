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

// Table 渲染终端排名表（对齐方案 4.3 示例），同时返回完整文本供保存结果文件。
// caveat 非空时作为醒目提示追加在末尾，让存下来的结果文件自身就说明这轮不可信。
func Table(rows []*score.Row, envSummary, caveat string, full bool) string {
	var buf bytes.Buffer
	w := tablewriter.NewWriter(&buf)
	fmt.Fprintln(&buf)
	if envSummary != "" {
		fmt.Fprintln(&buf, envSummary)
	}
	fmt.Fprintf(&buf, "测试时间: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	if base := baseline(rows); base != nil {
		fmt.Fprintf(&buf, "本地基线（仅作对比，不参与推荐、不参与归一化基准）：%s 缓存P50 %s、成功率 %.0f%%、同省率 %s\n\n",
			base.Endpoint.Server, ms(base.CacheP50), base.Success*100, rate(base.SameProvinceRate))
	}
	hdr := []string{"排名", "DNS", "协议", "归属", "缓存P50", "成功率", "同省率", "TCP中位", "干净度", "总分", "备注"}
	if full {
		hdr = []string{"排名", "DNS", "协议", "归属", "缓存P50", "递归P50", "成功率", "同省率", "TCP中位", "TTFB", "干净度", "总分", "备注"}
	}
	w.SetHeader(hdr)
	w.SetAutoFormatHeaders(false)
	for _, r := range rows {
		mark := ""
		if r.RecommendMain {
			mark = "◀ 推荐"
		} else if r.RecommendBack {
			mark = "◀ 备用"
		}
		row := []string{
			rank(r),
			r.Endpoint.Server,
			string(r.Endpoint.Proto),
			geo(r.Geo),
			ms(r.CacheP50),
			fmt.Sprintf("%.0f%%", r.Success*100),
			rate(r.SameProvinceRate),
			ms(r.TCPMedian),
			clean(r),
			fmt.Sprintf("%.1f", r.Total),
			mark + " " + strings.Join(r.Flags, ","),
		}
		if full {
			row = []string{
				rank(r),
				r.Endpoint.Server,
				string(r.Endpoint.Proto),
				geo(r.Geo),
				ms(r.CacheP50),
				ms(r.RecP50),
				fmt.Sprintf("%.0f%%", r.Success*100),
				rate(r.SameProvinceRate),
				ms(r.TCPMedian),
				ms(r.TTFBMedian),
				clean(r),
				fmt.Sprintf("%.1f", r.Total),
				mark + " " + strings.Join(r.Flags, ","),
			}
		}
		w.Append(row)
	}
	w.Render()

	main, back := pick(rows)
	if main != nil {
		fmt.Fprintln(&buf)
		if back != nil {
			fmt.Fprintf(&buf, "建议：主用 %s，备用 %s\n", main.Endpoint.Server, back.Endpoint.Server)
		} else {
			fmt.Fprintf(&buf, "建议：主用 %s（未找到跨运营商的备用）\n", main.Endpoint.Server)
		}
	} else {
		fmt.Fprintln(&buf)
		fmt.Fprintln(&buf, "建议：本次没有任何端点测到有效数据，不做推荐（请检查网络/代理/VPN 后重试）")
	}
	if caveat != "" {
		fmt.Fprintln(&buf)
		fmt.Fprintln(&buf, caveat)
	}
	fmt.Print(buf.String())
	return buf.String()
}

func pick(rows []*score.Row) (main, back *score.Row) {
	for _, r := range rows {
		if r.RecommendMain {
			main = r
		}
		if r.RecommendBack {
			back = r
		}
	}
	return
}

func baseline(rows []*score.Row) *score.Row {
	for _, r := range rows {
		if r.Endpoint.IsSystem {
			return r
		}
	}
	return nil
}

func geo(s string) string {
	if s == "" {
		return "-"
	}
	return s
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

// JSON 导出完整结果。
func JSON(rows []*score.Row, path string) error {
	out := map[string]any{
		"time":    time.Now().Format(time.RFC3339),
		"results": rows,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// CSV 导出扁平结果。未知值留空而不是写 0 / -1：下游按数值处理时，
// 0 会被当成"延迟极低""同省率 0%"，而它们其实是"没测到"。
func CSV(rows []*score.Row, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	recs := [][]string{{"rank", "server", "endpoint", "proto", "geo", "usable", "cache_p50_ms", "rec_p50_ms",
		"success_rate", "same_province_rate", "tcp_median_ms", "ttfb_median_ms", "clean_score", "total", "flags"}}
	for _, r := range rows {
		recs = append(recs, []string{
			fmt.Sprint(r.Rank), r.Endpoint.Server, r.Endpoint.Label(), string(r.Endpoint.Proto),
			r.Geo, fmt.Sprint(r.Usable),
			fnum(r.CacheP50), fnum(r.RecP50),
			fmt.Sprintf("%.3f", r.Success), frate(r.SameProvinceRate),
			fnum(r.TCPMedian), fnum(r.TTFBMedian),
			fnum(r.CleanScore), fmt.Sprintf("%.1f", r.Total),
			strings.Join(r.Flags, ";"),
		})
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
// udpIP 是 服务器名 -> 首选 UDP IP 的映射（推荐主备统一用 IPv4 UDP 地址写入系统）。
func ApplyCommands(rows []*score.Row, ifName string, udpIP map[string]string, dry bool) error {
	main, back := pick(rows)
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

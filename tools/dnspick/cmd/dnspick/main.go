// dnspick —— 本地宽带 DNS 优选工具（按《DNS优选工具技术方案》实现）。
//
//	dnspick                       快速模式（~1 分钟）
//	dnspick --full                完整模式（~6 分钟，+递归/污染/ECS/TTFB）
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dnspick/internal/checker"
	"dnspick/internal/config"
	"dnspick/internal/envcheck"
	"dnspick/internal/geo"
	"dnspick/internal/prober"
	"dnspick/internal/report"
	"dnspick/internal/score"
)

var (
	version = "1.1.0"
	showVer = flag.Bool("version", false, "显示版本")
)

func main() {
	// 退出前还原控制台输出码页：init 里把输出码页切成了 UTF-8，不还原会把
	// 调用方（如 dnspick.bat）留在 UTF-8 下，它随后用 GBK 写的中文就成乱码。
	defer restoreConsoleOutputCP()
	full := flag.Bool("full", false, "完整模式（+递归延迟/污染比对/ECS/TTFB）")
	serversFlag := flag.String("servers", "", "只测指定 DNS（逗号分隔 IP 或名称）")
	protoFlag := flag.String("protocol", "", "协议筛选：udp,udp6,doh,dot（默认 udp,doh；IPv6 可用时含 udp6）")
	iface := flag.String("interface", "", "使用指定网卡（名字见 --list-interfaces；影响源地址绑定、基线 DNS 来源与 --apply 写入目标）")
	listIfaces := flag.Bool("list-interfaces", false, "列出本机所有网卡及其 DNS 后退出")
	pickIface := flag.Bool("pick", false, "运行前交互式选择出口网卡（在终端里运行时会自动询问）")
	configPath := flag.String("config", "", "YAML 配置文件路径（候选DNS/域名/权重）")
	dumpConfig := flag.Bool("dump-config", false, "导出默认配置模板到 dnspick.yaml 后退出")
	jsonOut := flag.String("json", "", "结果导出为 JSON 文件")
	csvOut := flag.String("csv", "", "结果导出为 CSV 文件")
	applyFlag := flag.Bool("apply", false, "生成将推荐结果写入系统 DNS 的命令（dry-run 展示）")
	applyForce := flag.Bool("apply-force", false, "实际执行写入系统 DNS（先备份当前配置）")
	monitor := flag.String("monitor", "", "周期复测，如 30m；Ctrl-C 结束输出汇总")
	samplesFlag := flag.Int("samples", 0, "覆盖有效样本数（0=按模式默认：快速 8 / 完整 30，上限 200）")
	seedFlag := flag.Int64("seed", 20260101, "抽样随机种子（0=真随机；默认固定以便复现）")
	noAux := flag.Bool("no-aux", false, "跳过 DNSSEC/NSID/双栈辅助探测")
	listThresholds := flag.Bool("list-thresholds", false, "打印测量阈值与依据表后退出")
	flag.Parse()

	if *showVer {
		fmt.Println("dnspick v" + version)
		return
	}
	if *dumpConfig {
		if err := config.WriteDefaultTemplate("dnspick.yaml"); err != nil {
			fmt.Fprintln(os.Stderr, "导出配置失败:", err)
			exitNow(1)
		}
		fmt.Println("已导出默认配置到 dnspick.yaml，可修改后用 --config dnspick.yaml 使用")
		return
	}
	if *listThresholds {
		fmt.Print(config.ThresholdDoc())
		return
	}
	fmt.Printf("dnspick v%s —— 本地宽带 DNS 优选工具\n\n", version)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载配置失败:", err)
		exitNow(1)
	}
	// 生效阈值：--no-aux 直接关掉辅助探测，score/report 据此决定是否展示 DNSSEC/NSID/AAAA。
	th := cfg.Thresholds
	if *noAux {
		th.AuxEnabled = false
	}

	// ── 阶段0 环境自检 ──
	env := envcheck.Check()

	// warning 分两批打印：环境自检产生的先出，选网卡时新增的（没读到 DNS 等）在
	// 选完之后补，顺序和用户的操作一致。--list-interfaces 只出第一批，且不弹选择，
	// 否则"我只是想看看有哪些网卡"也会被拦一句提问。
	printWarnings := func(from int) int {
		for _, w := range env.Warnings[from:] {
			fmt.Fprintf(os.Stderr, "\033[31m[警告] %s\033[0m\n", w)
		}
		return len(env.Warnings)
	}
	seenWarnings := printWarnings(0)

	if *listIfaces {
		fmt.Printf("[环境] 自动探测到的出口网卡: %s\n\n", orDash(env.InterfaceName))
		printInterfaces(env.InterfaceName, env.SystemDNS)
		return
	}

	// 出口网卡：--interface 显式指定；没指定时，在终端里运行（含双击 exe）就先问一句，
	// 避免多网卡机器上默默用了自动探测出来的那块。选哪块网卡不只决定源地址绑定，
	// 也决定"当前系统DNS"基线读谁、以及 --apply 往哪块网卡写，三者必须一致。
	ifName, ifIP := env.InterfaceName, env.InterfaceIP
	if *iface != "" {
		ifName, ifIP = useInterface(env, *iface)
	} else if *pickIface || isTerminalIn() {
		if chosen := promptInterface(env, bufio.NewReader(os.Stdin), os.Stdout); chosen != "" {
			ifName, ifIP = useInterface(env, chosen)
		}
	}
	printWarnings(seenWarnings)

	loc := geo.New(findGeoDB())
	geoOK := loc.Available()
	myProvince := ""
	if env.PublicIP != "" && geoOK {
		myProvince = loc.Province(env.PublicIP)
	}

	// ── 构建候选端点 ──
	// udp6 默认跟随 IPv6 自检结果：自检已经确认过 IPv6 出口是否真的可用，
	// 硬编码开启只会在没有 IPv6 的环境里白跑一批必然超时的端点。
	protos := map[string]bool{"udp": true, "udp6": env.IPv6OK, "doh": true, "dot": false}
	if *protoFlag != "" {
		protos = map[string]bool{}
		for _, p := range strings.Split(*protoFlag, ",") {
			protos[strings.TrimSpace(p)] = true
		}
	}
	if !env.IPv6OK {
		protos["udp6"] = false
	}
	only := map[string]bool{}
	if *serversFlag != "" {
		for _, s := range strings.Split(*serversFlag, ",") {
			only[strings.TrimSpace(s)] = true
		}
	}

	var eps []prober.Endpoint
	udpIP := map[string]string{}
	// 同一地址可能既出现在系统 DNS 里、又是内置候选（例如运营商 DNS 恰好是
	// 114.114.114.114），重复探测会共用同一份 Metrics 而双倍计数，这里先按端点去重。
	seen := map[string]bool{}
	push := func(ep prober.Endpoint) {
		if seen[ep.Label()] {
			return
		}
		seen[ep.Label()] = true
		eps = append(eps, ep)
	}
	addServer := func(s config.Server, isSystem bool) {
		if len(only) > 0 && !only[s.Name] {
			matched := false
			for _, ip := range append(append([]string{}, s.IPs...), s.IPv6...) {
				if only[ip] {
					matched = true
				}
			}
			if !matched {
				return
			}
		}
		region := s.Region
		if isSystem {
			region = "本地基线"
		}
		if len(s.IPs) > 0 {
			udpIP[s.Name] = s.IPs[0]
		}
		for _, ip := range s.IPs {
			if protos["udp"] {
				push(prober.Endpoint{Server: s.Name, Address: ip, Proto: prober.UDP, Region: region, IsSystem: isSystem})
			}
		}
		for _, ip := range s.IPv6 {
			if protos["udp6"] {
				push(prober.Endpoint{Server: s.Name, Address: ip, Proto: prober.UDP6, Region: region, IsSystem: isSystem})
			}
		}
		if s.DoH != "" && protos["doh"] {
			push(prober.Endpoint{Server: s.Name, Address: s.DoH, Proto: prober.DOH, Region: region, IsSystem: isSystem})
		}
		if s.DoT != "" && protos["dot"] {
			push(prober.Endpoint{Server: s.Name, Address: s.DoT, Proto: prober.DOT, Region: region, IsSystem: isSystem})
		}
	}

	if len(env.SystemDNS) > 0 {
		sys := config.Server{Name: "当前系统DNS", IPs: env.SystemDNS, Region: "本地基线"}
		addServer(sys, true)
	}
	for _, s := range cfg.Servers {
		addServer(s, false)
	}
	if len(eps) == 0 {
		fmt.Fprintln(os.Stderr, "没有可测的候选 DNS 端点")
		exitNow(1)
	}

	run := func() (*score.GroupedResult, report.ReportMeta, string) {
		started := time.Now()
		q := prober.NewQuerierWithThresholds(ifIP, th)
		r := prober.NewRunner(q, eps, *full, func(f string, a ...any) {
			fmt.Printf("[进度] "+f+"\n", a...)
		})
		r.SetThresholds(th)
		r.SetSamples(*samplesFlag)

		hot := cfg.CDNSet()
		if len(hot) == 0 {
			hot = []string{"www.baidu.com"}
		}
		// 就近性域名集：快速模式 th.CDNFast 个；完整模式 th.CDNFull 个
		cdnDomains := hot
		limit := th.CDNFast
		if *full {
			limit = th.CDNFull
		}
		if len(cdnDomains) > limit {
			cdnDomains = cdnDomains[:limit]
		}

		// 阶段1：缓存延迟 + 成功率
		r.Phase1Latency(hot, th.Timeout())
		// 干净度：劫持（快速/完整都测）
		checker.CheckHijack(r, env.SystemDNS, &th)

		// 辅助探测：DNSSEC 验证 / NSID / 双栈（--no-aux 可关）
		if th.AuxEnabled {
			checker.CheckDNSSEC(r, &th)
			checker.CheckNSID(r, &th)
			auxDomains := cdnDomains
			if len(auxDomains) > 3 {
				auxDomains = auxDomains[:3]
			}
			checker.CheckDualStack(r, auxDomains, &th)
		}

		// 就近性：解析 + geo + TCP
		answers := r.Phase3ResolveCDN(cdnDomains, th.Timeout())
		checker.CheckCDN(r, answers, loc, myProvince, *full, ifIP, &th, *seedFlag)

		if *full {
			r.Phase2Recursion([]string{"probe.baidu.com", "probe.qq.com"}, th.RecRounds, th.RecTimeout())
			checker.CheckConsistency(r, cdnDomains, &th)
			auth := func(d string) []string {
				ips, err := q.QueryNSViaTCP(d, th.RecTimeout())
				if err != nil {
					return nil
				}
				return ips
			}
			checker.CheckPollution(r, cfg.Domains.Polluted, auth, &th)
			checker.CheckECS(r, env.PublicIP, cdnDomains[0], &th)
		}
		gr := score.ScoreByGroup(r, &cfg.Weights, geoOK)
		// 归属列：给能查到归属的解析器地址（UDP/UDP6）补上地理/运营商描述。
		if geoOK {
			for _, row := range gr.All {
				if row.Endpoint.Proto == prober.UDP || row.Endpoint.Proto == prober.UDP6 {
					row.Geo = loc.Describe(row.Endpoint.Address)
				}
			}
		}
		ptLabel := proxyTUNLabel(env)
		ptText := "未检出 ✓"
		if ptLabel != "" {
			ptText = ptLabel + " ⚠"
		}
		envSummary := fmt.Sprintf("[环境] 出口网卡: %s | 系统DNS: %s | 公网 IP: %s | IPv6: %s | 代理/TUN: %s | geo: %s",
			ifName, orDash(systemDNSSummary(env)), orDash(env.PublicIP), yesNo(env.IPv6OK),
			orDash(ptText), loc.Summary())
		// 代理/TUN 会把全部流量接管，测速必然失真：光在环境行留个 ⚠ 太弱，
		// 报告末尾再落一句醒目提示，让存下来的结果文件自身就说明"这一轮不可信"。
		caveat := ""
		if ptLabel != "" {
			caveat = "⚠ 检测到 " + ptLabel + "：全部流量已被接管，本次延迟与就近性数据不可信，" +
				"以上推荐仅供参考——请关闭代理/TUN 后重测。"
		}
		finished := time.Now()
		mode := "快速"
		if *full {
			mode = "完整"
		}
		meta := report.ReportMeta{
			Version: version, Mode: mode, Seed: *seedFlag,
			Samples: r.Samples, Warmup: r.Warmup, QPS: th.QPS, TimeoutMS: th.TimeoutMS,
			Retries: th.Retries, AuxEnabled: th.AuxEnabled,
			Started: started, Finished: finished, DurationS: finished.Sub(started).Seconds(),
		}
		tableText := report.Table(gr, meta, envSummary, caveat, *full)
		return gr, meta, tableText
	}

	if *monitor != "" {
		interval, err := time.ParseDuration(*monitor)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--monitor 参数无效:", err)
			exitNow(1)
		}
		fmt.Printf("监控模式：每 %s 复测一轮，Ctrl-C 结束输出汇总\n", interval)
		for {
			run()
			fmt.Printf("\n下一轮：%s\n", time.Now().Add(interval).Format("15:04:05"))
			time.Sleep(interval)
		}
	}

	gr, meta, tableText := run()

	// 结果文件：双击运行（无任何 flag，窗口结束即关）或没有用 --json/--csv 落盘时，
	// 至少留下一份文本结果，避免"跑完什么都没留下"。
	if *jsonOut == "" && *csvOut == "" {
		name := "dnspick-result-" + time.Now().Format("20060102-150405") + ".txt"
		if path, err := writeResult(name, tableText); err != nil {
			fmt.Fprintln(os.Stderr, "保存结果文件失败:", err)
		} else {
			fmt.Printf("\n结果已保存到 %s（可用记事本查看）\n", path)
		}
	}

	if *jsonOut != "" {
		if err := report.JSON(gr, meta, *jsonOut); err != nil {
			fmt.Fprintln(os.Stderr, "导出 JSON 失败:", err)
		} else {
			fmt.Println("JSON 结果已写入", *jsonOut)
		}
	}
	if *csvOut != "" {
		if err := report.CSV(gr, *csvOut); err != nil {
			fmt.Fprintln(os.Stderr, "导出 CSV 失败:", err)
		} else {
			fmt.Println("CSV 结果已写入", *csvOut)
		}
	}
	if *applyFlag || *applyForce {
		if err := report.ApplyCommands(gr, ifName, udpIP, !*applyForce); err != nil {
			fmt.Fprintln(os.Stderr, "生成应用命令失败:", err)
		}
		if !*applyForce {
			fmt.Println("\n（以上为 dry-run 展示；确认无误后运行 dnspick --apply-force 实际写入。）")
		}
	}

	// 无 flag（双击）运行结束时暂停，防止控制台窗口直接关闭。
	if flag.NFlag() == 0 && isTerminalIn() {
		fmt.Print("\n按 Enter 键退出…")
		fmt.Scanln()
	}
}

// exitNow 还原控制台输出码页后再退出。
// os.Exit 不会执行 defer，所以带错误码退出的路径必须走这里，否则码页还原会被跳过。
func exitNow(code int) {
	restoreConsoleOutputCP()
	os.Exit(code)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// proxyTUNLabel 汇总自检到的代理/TUN 类型（如 "系统代理+TUN"），都没检出时返回空串。
func proxyTUNLabel(env *envcheck.Info) string {
	var s []string
	if env.ProxyDetected {
		s = append(s, "系统代理")
	}
	if env.TUNDetected {
		s = append(s, "TUN")
	}
	return strings.Join(s, "+")
}

// useInterface 把出口网卡切到指定网卡：解析 IPv4、重读这块网卡的系统 DNS 作基线，
// 并就地补充 warning。名字不存在时列出全部网卡后退出（比一句"找不到网卡"好排查）。
func useInterface(env *envcheck.Info, name string) (string, net.IP) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "找不到网卡 %q。本机网卡：\n", name)
		printInterfaces("", nil)
		exitNow(1)
	}
	var ifIP net.IP
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ifIP = ipn.IP.To4()
		}
	}
	if ifIP == nil {
		env.Warnings = append(env.Warnings, "网卡 "+ifc.Name+" 没有 IPv4 地址，探测流量无法绑定到它，结果可能仍走默认路由。")
	}
	if dns, from := envcheck.SystemDNSFor(ifc.Name); len(dns) > 0 {
		env.SystemDNS, env.SystemDNSFrom = dns, from
	} else {
		env.SystemDNS, env.SystemDNSFrom = nil, ""
		env.Warnings = append(env.Warnings, "网卡 "+ifc.Name+" 上没有读到系统 DNS，本次没有本地基线对比行。")
	}
	return ifc.Name, ifIP
}

// promptInterface 交互式选网卡：双击 exe 的人不用先记住网卡名。
// 只列"已启用且有 IPv4"的网卡（没 IPv4 的选了也绑不上）；直接回车 = 用自动探测的出口网卡。
func promptInterface(env *envcheck.Info, in *bufio.Reader, out io.Writer) string {
	cands := pickCandidates(envcheck.Interfaces())
	if len(cands) < 2 {
		return "" // 只有一块可用网卡，没必要问
	}
	dnsMap := envcheck.InterfaceDNS()
	fmt.Fprintf(out, "检测到 %d 块可用网卡，请选择出口网卡：\n", len(cands))
	fmt.Fprintf(out, "   0) 自动（当前: %s %s）\n", orDash(env.InterfaceName), orDash(ipOf(env.InterfaceIP)))
	for i, it := range cands {
		fmt.Fprintf(out, "   %d) %s %s", i+1, padRight(it.Name, 34), it.IPv4[0])
		dns := dnsMap[it.Name]
		if len(dns) == 0 && it.Name == env.InterfaceName {
			dns = env.SystemDNS // 非 Windows 平台没有"每块网卡的 DNS"，用全局的
		}
		if len(dns) > 0 {
			fmt.Fprintf(out, "   DNS: %s", strings.Join(dns, ","))
		}
		if it.Name == env.InterfaceName {
			fmt.Fprint(out, "   ◀ 默认")
		}
		fmt.Fprintln(out)
	}
	fmt.Fprint(out, "请输入序号后回车 [0]: ")
	line, _ := in.ReadString('\n')
	n := parseChoice(line, len(cands))
	if n == 0 {
		if strings.TrimSpace(line) != "" {
			fmt.Fprintln(out, "（无效输入，使用自动探测的出口网卡）")
		}
		return ""
	}
	return cands[n-1].Name
}

// pickCandidates 挑出可以当出口用的网卡：已启用、有 IPv4、且不是环回。
// 保留 Interfaces() 的名字排序，保证同一台机器每次显示的序号一致。
func pickCandidates(list []envcheck.Interface) []envcheck.Interface {
	var out []envcheck.Interface
	for _, it := range list {
		if !it.Up || len(it.IPv4) == 0 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(it.Name), "loopback") {
			continue
		}
		out = append(out, it)
	}
	return out
}

// parseChoice 解析用户输入的序号：返回 1..n；回车（空输入）或非法输入返回 0（= 自动）。
func parseChoice(line string, n int) int {
	s := strings.TrimSpace(line)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 || v > n {
		return 0
	}
	return v
}

func ipOf(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// printInterfaces 列出本机网卡，* 标出本次使用的那块。
// DNS 逐网卡显示（Windows 能按适配器读；其他平台系统 DNS 是全局的，
// 就挂在选中网卡这一行上），方便判断"该选哪块网卡"。
func printInterfaces(selected string, selectedDNS []string) {
	dnsMap := envcheck.InterfaceDNS()
	fmt.Println("本机网卡（* = 本次使用的出口网卡）：")
	for _, it := range envcheck.Interfaces() {
		state := "down"
		if it.Up {
			state = "up"
		}
		mark := " "
		if selected != "" && it.Name == selected {
			mark = "*"
		}
		addrs := append(append([]string{}, it.IPv4...), it.IPv6...)
		addrText := orDash(strings.Join(addrs, ", "))
		dns := dnsMap[it.Name]
		if len(dns) == 0 && it.Name == selected {
			dns = selectedDNS
		}
		fmt.Printf("  %s %s %-4s %s DNS: %s\n", mark, padRight(it.Name, 34), state,
			padRight(addrText, 46), orDash(strings.Join(dns, ",")))
	}
	fmt.Println("\n用法：dnspick --interface \"<网卡名>\"（可只测这块网卡的出口，环境行会显示它读到的系统 DNS）")
}

// padRight 按显示宽度补空格：中文/全角字符占两列，直接用 %-30s 会让后面的列错位。
func padRight(s string, width int) string {
	w := 0
	for _, r := range s {
		if isWide(r) {
			w += 2
		} else {
			w++
		}
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115f, // 韩文字母
		r >= 0x2e80 && r <= 0xa4cf, // 中日韩部首、假名、汉字
		r >= 0xac00 && r <= 0xd7a3, // 韩文音节
		r >= 0xf900 && r <= 0xfaff, // 兼容汉字
		r >= 0xfe30 && r <= 0xfe6f, // 兼容形式
		r >= 0xff00 && r <= 0xff60, // 全角形式
		r >= 0xffe0 && r <= 0xffe6:
		return true
	}
	return false
}

// systemDNSSummary 汇总系统 DNS 及其来源网卡，方便判断读到的是不是出口网卡的配置。
func systemDNSSummary(env *envcheck.Info) string {
	if len(env.SystemDNS) == 0 {
		return ""
	}
	s := strings.Join(env.SystemDNS, ",")
	if env.SystemDNSFrom != "" {
		s += "（来自 " + env.SystemDNSFrom + "）"
	}
	return s
}

// writeResult 先把结果写到当前目录；当前目录不可写（只读目录、受限沙箱等）时
// 退回到用户缓存目录，别让一次几分钟的测评结果直接丢掉。
func writeResult(name, text string) (string, error) {
	if err := os.WriteFile(name, []byte(text), 0o644); err == nil {
		return name, nil
	} else if dir, derr := os.UserCacheDir(); derr == nil {
		alt := filepath.Join(dir, "dnspick")
		if merr := os.MkdirAll(alt, 0o700); merr == nil {
			p := filepath.Join(alt, name)
			if werr := os.WriteFile(p, []byte(text), 0o644); werr == nil {
				return p, nil
			}
		}
		return "", err
	} else {
		return "", err
	}
}

// findGeoDB 依次尝试 CWD 与可执行文件目录下的 data/geoip.xdb。
func findGeoDB() string {
	for _, p := range []string{"data/geoip.xdb"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "data", "geoip.xdb")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "data/geoip.xdb"
}

func yesNo(b bool) string {
	if b {
		return "可用"
	}
	return "不可用"
}

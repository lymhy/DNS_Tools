# dnspick —— 本地宽带 DNS 优选工具

按 [《DNS优选工具技术方案》](../../docs/DNS优选工具技术方案.md) 实现的 Go CLI。

**核心设计**：DNS 查询延迟只占上网体验的一小部分，真正决定体验的是"DNS 帮你选的 CDN 节点好不好"。因此本工具做**端到端验证**——用每个候选 DNS 解析同一批大流量域名，再实际连接返回的 IP 测 TCP/HTTP 延迟与归属地，而不是只测 DNS 本身的响应速度。

## 功能

- **阶段0 环境自检**：读取系统/运营商 DNS 作为基线候选；检测 IPv6、系统代理、TUN/TAP 虚拟网卡（**仅当该虚拟网卡确实接管了默认路由/上网流量时才红字警告**——Tailscale 未开 exit node、Hyper-V/VMware 等虚拟网卡只要没抢默认路由就只作提示，不影响结果）；获取公网 IP
- **阶段1 延迟与稳定性**：缓存延迟 P50/P95（**同一个**热门域名连查「热身 2 + 有效样本」次，否则每次都在查冷域名；有效样本快速 8 / 完整 30，`--samples` 可覆盖）、均值 95% 置信区间半宽（t 分布）、丢包率（**首次尝试**就失败的占比，重试成功也照记，避免被重试掩盖）、成功率（超时 2s，重试 1 次，重试同样走限速）；分位数用 R-7 线性插值（与 numpy / Excel `PERCENTILE.INC` 一致）；阶段内交叉轮询平均网络波动，QPS≤5 限速
- **阶段2 干净度**：NXDOMAIN 劫持、解析器透明劫持（`o-o.myaddr.l.google.com` echo 回显）——这两种快速模式也测；完整模式再加随机子域名法递归延迟（防缓存）、污染比对（与权威 NS TCP 直查答案比对，基准只取一次供所有端点共用）、结果一致性
- **阶段3 就近性（核心）**：解析 CDN 域名（快速模式取前 8 个、完整模式最多 20 个；默认集 11 个 = web 5 + video 3 + CDN 3，可用 `--config` 扩充）→ ip2region 离线归属库算**同省率**（省份查不到的 IP 不计入分母，本机省份未知时该列为 `-`）→ 对返回 IP 做 **TCP 443 握手计时** → 完整模式加测 **HTTPS TTFB**（带正确 SNI，所有端点抽同一批域名）
- **辅助探测**（完整/快速模式都做，`--no-aux` 可整体跳过）：**DNSSEC** 正反双向验证（正：`cloudflare.com` 带 DO 看 AD/RRSIG；反：`dnssec-failed.org` 应 SERVFAIL，返回答案即"声称验证但未验证"）、**NSID / CHAOS**（EDNS0 NSID 与 `version.bind`；多端点返回同一 NSID 标"NSID重复(可能代理)"）、**双栈可用性**（AAAA 失败率 + 同一服务器 v4/v6 缓存 P50 差值超 250ms 才给倾向，RFC 8305 §8）。这些**只披露、不计分**。
- **评分推荐**：总分 = 0.35×延迟 + 0.20×稳定 + 0.30×就近 + 0.15×干净，**比值归一**（按方案 §4.1 公式：`100 × 本轮最快 / 本机`，不是 min-max），**每个协议组（udp / udp6 / doh / dot）各自归一、各自排名、各自推荐主备**（跨协议延迟不可比，故不下全局名次）。权重可配置且会校验总和为 1。**没有任何成功测量的端点记 0 分、标"无数据"、不显示名次也不参与推荐**（"没测到"不等于"干净"）；主用优先选干净度满分者，备用跨运营商；"本地基线"（当前系统 DNS）单独成行、不占名次、也不参与归一化基准。归属列由 ip2region 给出，私网/环回/保留地址分别显示为 `内网`/`本机`/`保留地址`，DoH/DoT 端点没有解析器 IP 时显示 `-`。DNSSEC / AAAA 异常 / 丢包 / NSID 重复以**备注标记 + 报告列**呈现，不进总分（保持四项权重恒为 1，新旧结果可比）。

## 使用

```bash
make build && ./dnspick.exe          # 快速模式（~1 分钟：有效样本 8 + 命中/基础就近性/辅助探测）
./dnspick.exe --full                 # 完整模式（数分钟，实测时长随候选数与网络而定：有效样本 30 + 递归/污染/ECS/TTFB）
./dnspick.exe --servers 223.5.5.5,119.29.29.29
./dnspick.exe --protocol udp,doh     # udp/udp6/doh/dot；指定即"只测这些"（整体替换默认值）；不带时默认 udp,doh（IPv6 自检通过时含 udp6）
./dnspick.exe --list-interfaces      # 列出本机所有网卡（含各自的 DNS），挑一块再测
./dnspick.exe --interface "WLAN"     # 只用这块网卡：源地址绑定、基线 DNS 来源、--apply 写入目标
./dnspick.exe --pick                 # 强制先交互式选网卡（管道/脚本里默认不问，所以需要时显式加）
./dnspick.exe --json r.json --csv r.csv
./dnspick.exe --apply                # dry-run 展示应用命令；--apply-force 实际写入（先备份）
./dnspick.exe --monitor 30m          # 每 30 分钟复测一轮
./dnspick.exe --samples 30           # 覆盖有效样本数（0=按模式默认：快速 8 / 完整 30，上限 200）
./dnspick.exe --seed 20260101        # 抽样随机种子（默认固定以便复现；0=真随机）
./dnspick.exe --no-aux               # 跳过 DNSSEC/NSID/双栈辅助探测
./dnspick.exe --dump-config          # 导出默认配置模板 dnspick.yaml（含测量阈值）
./dnspick.exe --list-thresholds      # 打印测量阈值与依据表后退出
./dnspick.exe --version              # 版本号
```

抽样（每域名 IP 子集、TTFB 域名子集）统一由 `--seed` 驱动：默认固定种子 `20260101`，**同参数两次运行抽到同一批**，便于复现与对比；`--seed 0` 为真随机。测量相关的常量集中在配置的 `thresholds:` 段（`--list-thresholds` 可打印），`--config` 里**写哪项覆盖哪项**（未写的用内置默认）。

多网卡（有线 + 无线 + 虚拟网卡）时的做法：先 `--list-interfaces` 看名字（如 `WLAN`、`以太网`、`VMware Network Adapter VMnet8`，带 `*` 的是自动探测到的出口网卡），再用 `--interface "<名字>"` 指定。指定后工具会**改用这块网卡的 DNS 作为"当前系统DNS"基线**，并把 `--apply` 的写入目标切到它；网卡名写错会直接列出可用网卡后退出。

注意 `--interface` 改变的是"源地址绑定 + 读谁的 DNS + 往哪写"，**不会绕过代理/TUN 的路由接管**：如果 TUN 已经把默认路由接走，绑源地址也照样走隧道，测速仍然失真 —— 官方建议仍是关掉代理/TUN 再测。

自定义候选/域名/权重：`--config dnspick.yaml`，或参考 [configs/](configs/) 下的 `servers.yaml` / `domains.yaml`。

### 双击运行（Windows）

直接双击 `dnspick.exe` 即为快速模式：运行结束窗口会提示**按 Enter 退出**（不会一闪而过），并把完整结果保存为同目录的 `dnspick-result-日期时间.txt`，可用记事本查看。没写 `--json`/`--csv` 时也会保存这份文本结果；当前目录不可写（只读目录等）时自动改存到用户缓存目录 `%LOCALAPPDATA%\dnspick\`。

在终端里运行（而不是双击）时，程序会**先列出可用网卡并问你用哪一块**（回车 = 自动探测）；脚本/管道里不会问，想强制询问用 `--pick`。

想少记参数就双击 **`dnspick.bat`** —— 唯一的菜单入口，中文提示，按使用顺序问三步：**①模式**（快速 / 完整 / 只看网卡 / 退出）→ **②端点类型**（默认 / IPv4 UDP / DoH / DoT / IPv6 UDP / 全部，**可多选**，如输入 `23` 表示同时测 IPv4 UDP 与 DoH）→ **③服务器范围**（当前列表 / 只测国内公共 DNS / 只测国外公共 DNS）。每一步都会回显当前已选内容，选完先把真实命令行打印出来再执行。跑完 `pause` 一下就退出（不回菜单，避免按键/管道输入下空转），想再测一次就再双击一次。

目录下存在 `dnspick.yaml` 时它会自动带上 `--config dnspick.yaml`，菜单顶部会标出「候选来源」，所以自定义列表里加的 DNS 从菜单进去也会被测到；「只测国内 / 只测国外」都是对**当前候选列表**按 IP 做过滤，不是另外硬塞一批服务器——列表里一个都不匹配时那一轮就没有可测端点。另注意 `--protocol` 是「指定即只测」，选了 DoT 那一轮就不会再出现 UDP 结果；第 2 步的「默认」等于 `udp + doh + udp6`（IPv6 自检不通过时 `udp6` 自动去掉），与不传 `--protocol` 完全等价。v1.1 起**完整模式会额外执行 DNSSEC / NSID / 双栈辅助探测**（快速模式也做，如需跳过用命令行的 `--no-aux`，bat 菜单未单列该开关）。批处理首行是 `chcp 65001`，所以 UTF-8 保存的中文提示在任何系统代码页下都能正常显示。

## 输出

结果**按协议组分表**（udp / udp6 / doh / dot 各一张，各自排名与"本组建议"），顶部另打印环境行、测试时间与测量元数据（版本/模式/seed/样本/QPS/超时/重试/辅助探测/耗时）。

终端表格列：

- 快速模式：`排名 | DNS | 协议 | 归属 | 缓存P50 | 样本n | 丢包 | 成功率 | 同省率 | TCP中位 | 干净度 | 总分 | 备注`
- 完整模式：`排名 | DNS | 协议 | 归属 | 缓存P50 | 递归P50 | 样本n | 丢包 | CI± | 成功率 | 同省率 | TCP中位 | TTFB | NSID | DNSSEC | AAAA | 干净度 | 总分 | 备注`

- `排名` 为 `-` 表示这一行不参与排名：本地基线（当前系统 DNS）和"无数据"端点都是这样，也不会被推荐。**名次是"协议组内"排名，跨协议不可比**（表尾口径说明也会写明）。
- `归属` 是解析器 IP 的省市/运营商（`中国 深圳市 腾讯 CN` 这种），私网/环回/保留地址显示 `内网`/`本机`/`保留地址`，DoH/DoT 没有解析器 IP 时显示 `-`。
- `样本n` / `丢包` / `CI±` 是 v1.1 新增的测量可信度列；`NSID`/`DNSSEC`/`AAAA` 是辅助探测列（`--no-aux` 时为空）。
- 任何"没测到"的指标都显示 `-`（快速模式不测递归延迟与 TTFB），**不写 0**。
- `备注` 里可能出现的标记（均**只披露、不计分**）：`DNSSEC验证` / `DNSSEC未验证` / `AAAA异常` / `丢包x%`（首次尝试丢包率 > 5%）/ `NSID重复(可能代理)` / `NXDOMAIN重定向` / `透明劫持(53被代理)` / `污染` / `一致性异常` / `无数据`。

结果落盘：

- 没写 `--json`/`--csv` 时自动存一份 `dnspick-result-日期时间.txt`（当前目录不可写就落到 `%LOCALAPPDATA%\dnspick\`）。
- `--json`：顶层 `{time, meta, groups:[{proto,main,back,results}], results}`，含 `meta`（seed/样本/模式等）、按协议分组的 `groups`（每组带组内 `main`/`back` 推荐）与 `results`（全量行，含 `Geo`/`Usable`/`Rank`/各分项指标与 `Flags`）。
- `--csv`：首行是注释 `# rank 为协议组内排名；跨协议不可比`，扁平列 `group,rank,server,endpoint,proto,geo,usable,cache_p50_ms,rec_p50_ms,n_samples,loss_rate,ci95_ms,success_rate,same_province_rate,tcp_median_ms,ttfb_median_ms,nsid,dnssec,aaaa,clean_score,total,flags`；**没测到的数值留空**（写 0 会被下游当成"延迟极低""同省率 0%"），省份未知时 `same_province_rate` 也留空。消费脚本请按 `group` 列分组看 `rank`。

## 测试

```bash
make test        # 等价于 go test ./...
```

覆盖的是评分/推荐、权重合并、阈值覆盖、统计口径、辅助探测纯函数、环境自检解析、网卡选择这些**纯逻辑**（不联网）：无数据端点记 0 且不被推荐、主用优先干净满分、备用跨运营商、并列名次稳定、重复端点合并、**分组排名各协议独立且各自推荐主备**、权重只覆盖写明的项（含显式 0 与总和≠1 报错）、**阈值逐项覆盖（区分"没写"与"写了 0/false"）**、`scutil --dns` 与 `resolv.conf` 解析、网卡列表与"网卡名|DNS"解析（Windows 占位 DNS `fec0:0:0:ffff::1..3` 会被滤掉、同网卡 v4/v6 去重）、交互选网卡的候选过滤与序号解析（空/越界/非法输入回落到自动探测）、随机子域名唯一性、限速间隔、**R-7 分位数/样本标准差/95%CI、丢包独立记账、样本量**、**DNSSEC 严格判定 / AAAA 失败率 / v4-v6 倾向 / NSID 去重**、归属地降级（无 xdb / 私网 / 环回 / 保留）、DoH 地址不会被当成系统 DNS、检查项重叠与排序。

## 依赖

- Go 1.22+，第三方库：`miekg/dns`（UDP/TCP/DoT）、`yaml.v3`、`tablewriter`
- 离线 IP 库：[ip2region](https://gitee.com/lionsoul/ip2region) `data/geoip.xdb`（已内置并随仓库提交；缺失时会降级为"无同省率"，此时就近性只按 TCP 延迟评分）
- 绑定源码：ip2region 的 Go 绑定 vendor 在 `internal/geo/xdb/`，以 **Apache-2.0** 授权，许可正文见该目录下的 `LICENSE`
- 许可：本项目以 **AGPL-3.0** 发布（见仓库根目录 `LICENSE`）；上述 vendor 的 Apache-2.0 代码与 AGPL-3.0 兼容

## 注意

- 测试时请**关闭代理/TUN 模式**，否则结果失真（工具会检测并警告）
- Windows 防火墙首次运行弹窗放行即可；TCP 探测仅出站连接
- 公共 DNS 的 anycast 节点会调整，建议每月复测
- `--apply-force` 会先把当前 DNS 配置导出成 **JSON** 备份到 `%APPDATA%\dnspick\dns-backup-时间戳.json`（带时间戳，不会互相覆盖），**备份失败就中止、不改配置**；还原用 `Get-Content 备份.json | ConvertFrom-Json`
- macOS 上写入用的是 `networksetup`，传的是**网络服务名**（如 `Wi-Fi`），不是 `en0`；Linux 上 `/etc/resolv.conf` 若是指向 systemd-resolved 的符号链接，工具会拒绝改写并提示改用 `nmcli`/`resolvectl`，能改时也会先备份到 `/etc/resolv.conf.dnspick.bak`，并用同目录临时文件 + rename 落盘（避免留下半个文件）
- `--apply` 写入系统 DNS 时统一用推荐端点的 **IPv4 UDP 地址**（DoH/DoT 只用于测量，不适合直接当成系统 DNS）
- 读到的"系统 DNS"优先取**出口网卡**上的配置，避免把 VPN/虚拟网卡的残留 DNS（例如 `172.18.0.2`）当成基线

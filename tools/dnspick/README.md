# dnspick —— 本地宽带 DNS 优选工具

按 [《DNS优选工具技术方案》](../../docs/DNS优选工具技术方案.md) 实现的 Go CLI。

**核心设计**：DNS 查询延迟只占上网体验的一小部分，真正决定体验的是"DNS 帮你选的 CDN 节点好不好"。因此本工具做**端到端验证**——用每个候选 DNS 解析同一批大流量域名，再实际连接返回的 IP 测 TCP/HTTP 延迟与归属地，而不是只测 DNS 本身的响应速度。

## 功能

- **阶段0 环境自检**：读取系统/运营商 DNS 作为基线候选；检测 IPv6、系统代理、TUN/TAP 虚拟网卡（检测到会红字警告）；获取公网 IP
- **阶段1 延迟与稳定性**：缓存延迟 P50/P95（**同一个**热门域名连查 10 次、前 2 次热身丢弃，否则每次都在查冷域名）、成功率（超时 2s，重试 1 次，重试同样走限速）；阶段内交叉轮询平均网络波动，QPS≤5 限速
- **阶段2 干净度**：NXDOMAIN 劫持、解析器透明劫持（`o-o.myaddr.l.google.com` echo 回显）——这两种快速模式也测；完整模式再加随机子域名法递归延迟（防缓存）、污染比对（与权威 NS TCP 直查答案比对，基准只取一次供所有端点共用）、结果一致性
- **阶段3 就近性（核心）**：解析 CDN 域名（快速模式取前 8 个、完整模式最多 20 个；默认集 11 个 = web 5 + video 3 + CDN 3，可用 `--config` 扩充）→ ip2region 离线归属库算**同省率**（省份查不到的 IP 不计入分母，本机省份未知时该列为 `-`）→ 对返回 IP 做 **TCP 443 握手计时** → 完整模式加测 **HTTPS TTFB**（带正确 SNI，所有端点抽同一批域名）
- **评分推荐**：总分 = 0.35×延迟 + 0.20×稳定 + 0.30×就近 + 0.15×干净，**比值归一**（按方案 §4.1 公式：`100 × 本轮最快 / 本机`，不是 min-max）；权重可配置且会校验总和为 1。**没有任何成功测量的端点记 0 分、标"无数据"、不显示名次也不参与推荐**（"没测到"不等于"干净"）；主用优先选干净度满分者，备用跨运营商；"本地基线"（当前系统 DNS）单独成行、不占名次、也不参与归一化基准。归属列由 ip2region 给出，私网/环回/保留地址分别显示为 `内网`/`本机`/`保留地址`，DoH/DoT 端点没有解析器 IP 时显示 `-`

## 使用

```bash
make build && ./dnspick.exe          # 快速模式（~1 分钟；终端里会先问你用哪块网卡）
./dnspick.exe --full                 # 完整模式（~6 分钟：+递归/污染/ECS/TTFB）
./dnspick.exe --servers 223.5.5.5,119.29.29.29
./dnspick.exe --protocol udp,doh     # udp/udp6/doh/dot；默认 udp,doh（IPv6 自检通过时含 udp6）
./dnspick.exe --list-interfaces      # 列出本机所有网卡（含各自的 DNS），挑一块再测
./dnspick.exe --interface "WLAN"     # 只用这块网卡：源地址绑定、基线 DNS 来源、--apply 写入目标
./dnspick.exe --pick                 # 强制先交互式选网卡（管道/脚本里默认不问，所以需要时显式加）
./dnspick.exe --json r.json --csv r.csv
./dnspick.exe --apply                # dry-run 展示应用命令；--apply-force 实际写入（先备份）
./dnspick.exe --monitor 30m          # 每 30 分钟复测一轮
./dnspick.exe --dump-config          # 导出默认配置模板 dnspick.yaml
./dnspick.exe --version              # 版本号
```

多网卡（有线 + 无线 + 虚拟网卡）时的做法：先 `--list-interfaces` 看名字（如 `WLAN`、`以太网`、`VMware Network Adapter VMnet8`，带 `*` 的是自动探测到的出口网卡），再用 `--interface "<名字>"` 指定。指定后工具会**改用这块网卡的 DNS 作为"当前系统DNS"基线**，并把 `--apply` 的写入目标切到它；网卡名写错会直接列出可用网卡后退出。

注意 `--interface` 改变的是"源地址绑定 + 读谁的 DNS + 往哪写"，**不会绕过代理/TUN 的路由接管**：如果 TUN 已经把默认路由接走，绑源地址也照样走隧道，测速仍然失真 —— 官方建议仍是关掉代理/TUN 再测。

自定义候选/域名/权重：`--config dnspick.yaml`，或参考 [configs/](configs/) 下的 `servers.yaml` / `domains.yaml`。

### 双击运行（Windows）

直接双击 `dnspick.exe` 即为快速模式：运行结束窗口会提示**按 Enter 退出**（不会一闪而过），并把完整结果保存为同目录的 `dnspick-result-日期时间.txt`，可用记事本查看。没写 `--json`/`--csv` 时也会保存这份文本结果；当前目录不可写（只读目录等）时自动改存到用户缓存目录 `%LOCALAPPDATA%\dnspick\`。

在终端里运行（而不是双击）时，程序会**先列出可用网卡并问你用哪一块**（回车 = 自动探测）；脚本/管道里不会问，想强制询问用 `--pick`。

想少记参数就双击 **`dnspick.bat`**：一个纯 ASCII 的菜单启动器，可选快速模式、完整模式、只列网卡、只测国内公共 DNS。它不做 `chcp`、也不在跑完后回到菜单（避免把控制台代码页搞乱、也避免按键/管道输入下空转），跑完 `pause` 一下就退出，再测一次就再双击一次。

## 输出

终端表格列：`排名 | DNS | 协议 | 归属 | 缓存P50 | [递归P50] | 成功率 | 同省率 | TCP中位 | [TTFB] | 干净度 | 总分 | 备注`（方括号两列只有 `--full` 才有）。

- `排名` 为 `-` 表示这一行不参与排名：本地基线（当前系统 DNS）和"无数据"端点都是这样，也不会被推荐。
- `归属` 是解析器 IP 的省市/运营商（`中国 深圳市 腾讯 CN` 这种），私网/环回/保留地址显示 `内网`/`本机`/`保留地址`，DoH/DoT 没有解析器 IP 时显示 `-`。
- 任何"没测到"的指标都显示 `-`（快速模式不测递归延迟与 TTFB），**不写 0**。

结果落盘：

- 没写 `--json`/`--csv` 时自动存一份 `dnspick-result-日期时间.txt`（当前目录不可写就落到 `%LOCALAPPDATA%\dnspick\`）。
- `--json`：完整结构，含 `Geo`、`Usable`、`Rank`、各分项指标与 `Flags`。
- `--csv`：扁平列 `rank,server,endpoint,proto,geo,usable,cache_p50_ms,rec_p50_ms,success_rate,same_province_rate,tcp_median_ms,ttfb_median_ms,clean_score,total,flags`；**没测到的数值留空**（写 0 会被下游当成"延迟极低""同省率 0%"），省份未知时 `same_province_rate` 也留空。

## 测试

```bash
make test        # 等价于 go test ./...
```

覆盖的是评分/推荐、权重合并、环境自检解析、网卡选择这些**纯逻辑**（不联网）：无数据端点记 0 且不被推荐、主用优先干净满分、备用跨运营商、并列名次稳定、重复端点合并、权重只覆盖写明的项（含显式 0 与总和≠1 报错）、`scutil --dns` 与 `resolv.conf` 解析、网卡列表与"网卡名|DNS"解析（Windows 占位 DNS `fec0:0:0:ffff::1..3` 会被滤掉、同网卡 v4/v6 去重）、交互选网卡的候选过滤与序号解析（空/越界/非法输入回落到自动探测）、随机子域名唯一性、限速间隔、分位数、归属地降级（无 xdb / 私网 / 环回 / 保留）、DoH 地址不会被当成系统 DNS、检查项重叠与排序。

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

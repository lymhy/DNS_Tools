# DNS_Tools

本地宽带 DNS 优选工具集。

核心工具 `dnspick` 采用**端到端验证**的思路挑选最适合当前宽带的 DNS：用每个候选 DNS 解析同一批大流量域名，
再实际连接返回的 IP 测 TCP/HTTPS 延迟与归属地，而不是只测 DNS 本身的响应速度——因为决定上网体验的
是"DNS 帮你选的 CDN 节点好不好"，而不是解析请求那几十毫秒。

## 仓库内容

| 路径 | 说明 |
|---|---|
| [tools/dnspick/](tools/dnspick/) | Go CLI 实现，**使用说明见 [tools/dnspick/README.md](tools/dnspick/README.md)** |
| [docs/DNS优选工具技术方案.md](docs/DNS%E4%BC%98%E9%80%89%E5%B7%A5%E5%85%B7%E6%8A%80%E6%9C%AF%E6%96%B9%E6%A1%88.md) | 设计文档：指标定义、测量方法、评分模型、技术选型 |

## 快速开始

```bash
cd tools/dnspick
make build && ./dnspick.exe     # 快速模式（~1 分钟）
./dnspick.exe --full            # 完整模式（~6 分钟，+递归/污染/ECS/TTFB）
```

Windows 下也可直接双击 `tools/dnspick/dnspick.exe` 或 `dnspick.bat` 启动。

全部参数、输出格式、评分口径与注意事项请见 [tools/dnspick/README.md](tools/dnspick/README.md)。

## 许可

本项目以 **AGPL-3.0** 发布，许可正文见 [LICENSE](LICENSE)。

`tools/dnspick/internal/geo/xdb/` 下的 ip2region 绑定源码源自
[ip2region](https://gitee.com/lionsoul/ip2region)，以 **Apache-2.0** 授权，许可正文见
[tools/dnspick/internal/geo/xdb/LICENSE](tools/dnspick/internal/geo/xdb/LICENSE)。

## 注意

测试前请**关闭代理/TUN 模式**，否则延迟与就近性数据失真（工具会检测并在报告末尾给出警示）。
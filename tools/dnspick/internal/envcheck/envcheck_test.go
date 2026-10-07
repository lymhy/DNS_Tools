package envcheck

import (
	"reflect"
	"testing"
)

// macOS 的 `scutil --dns` 输出形如 "  nameserver[0] : 192.168.1.1"，
// 原来按 "nameserver[" 前缀切分后取第一个字段，得到的是 "0]"。
func TestParseScutilDNS(t *testing.T) {
	text := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 14 (en0)
`
	got := parseScutilDNS(text)
	want := []string{"192.168.1.1", "fe80::1%en0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScutilDNS = %v, want %v", got, want)
	}
}

func TestParseResolvConfHandlesTabsAndComments(t *testing.T) {
	text := "nameserver\t192.168.1.1\n# nameserver 8.8.8.8\nnameserver 223.5.5.5 ; 备用\n  nameserver   2400:3200::1\noptions edns0\n"
	got := parseResolvConf(text)
	want := []string{"192.168.1.1", "223.5.5.5", "2400:3200::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseResolvConf = %v, want %v", got, want)
	}
}

func TestSplitDNS(t *testing.T) {
	if got := splitDNS(" 192.168.1.1 , 223.5.5.5 ,, "); len(got) != 2 {
		t.Errorf("splitDNS 应忽略空白项，got %v", got)
	}
	if got := splitDNS(""); len(got) != 0 {
		t.Errorf("空输入应返回空切片，got %v", got)
	}
}

func TestExtractIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7\n":        "203.0.113.7",
		"\"198.51.100.9\"":     "198.51.100.9",
		"您的IP是 198.51.100.9 ？": "198.51.100.9",
		"2001:db8::1":          "", // 只接受 IPv4（ECS 检测用）
		"no ip here":           "",
		"":                     "",
	}
	for in, want := range cases {
		if got := extractIP(in); got != want {
			t.Errorf("extractIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// --list-interfaces 依赖 Interfaces()：至少要列出网卡（环回也算）、按名字排序。
func TestInterfacesSortedAndNonEmpty(t *testing.T) {
	list := Interfaces()
	if len(list) == 0 {
		t.Fatal("应至少列出环回网卡")
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name > list[i].Name {
			t.Errorf("网卡应按名字排序，%q 排在 %q 之前", list[i-1].Name, list[i].Name)
		}
	}
	hasAddr := false
	for _, it := range list {
		if len(it.IPv4) > 0 || len(it.IPv6) > 0 {
			hasAddr = true
		}
	}
	if !hasAddr {
		t.Error("所有网卡都没有地址，地址收集逻辑有问题")
	}
}

// PowerShell 输出的 "网卡名|地址,地址" 要能解析，且同一网卡的 IPv4/IPv6 两行会合并去重，
// Windows 的 fec0:0:0:ffff:: 占位值被丢掉。
func TestParseAliasDNS(t *testing.T) {
	text := "WLAN|192.168.100.1\r\nWLAN|fe80::46df:65ff:fef6:2679,192.168.100.1\r\n以太网|192.168.1.1\r\n" +
		"Tailscale|fec0:0:0:ffff::1,fec0:0:0:ffff::2\r\nvEthernet (Default Switch)|\r\n"
	got := parseAliasDNS(text)
	want := map[string][]string{
		"WLAN": {"192.168.100.1", "fe80::46df:65ff:fef6:2679"},
		"以太网":  {"192.168.1.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseAliasDNS = %v, want %v", got, want)
	}
	if parseAliasDNS("") != nil {
		t.Error("空输入应返回 nil")
	}
}

// 虚拟网卡只有真的成了默认路由出口才算"接管上网流量"；
// Tailscale 未开 exit node 时上网仍走物理网卡，不该被判为 TUN。
func TestTUNTakesOver(t *testing.T) {
	cases := []struct {
		iface, exit string
		want        bool
	}{
		{"Tailscale", "WLAN", false},   // 虚拟网卡在，但出口是物理网卡 → 不接管
		{"Tailscale", "Tailscale", true}, // 出口就是它 → 接管
		{"singbox_tun", "SINGBOX_TUN", true}, // 名字大小写不同也算同一块
		{"Tailscale", "", true},        // 探不到默认路由 → 保守判真
	}
	for _, c := range cases {
		if got := tunTakesOver(c.iface, c.exit); got != c.want {
			t.Errorf("tunTakesOver(%q, %q) = %v, want %v", c.iface, c.exit, got, c.want)
		}
	}
}

// 用户明确指定了网卡时，读不到 DNS 也不能悄悄回落到别的网卡。
func TestSystemDNSForUnknownInterface(t *testing.T) {
	dns, from := SystemDNSFor("这个网卡肯定不存在-9f8e7d")
	if len(dns) != 0 {
		t.Errorf("不存在的网卡不该读到 DNS，got %v（来自 %q）", dns, from)
	}
}

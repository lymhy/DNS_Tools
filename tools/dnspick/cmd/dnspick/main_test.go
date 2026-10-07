package main

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"

	"dnspick/internal/envcheck"
)

// 交互式选择只列"能真当出口用"的网卡：已启用、有 IPv4、不是环回；
// 并保持 Interfaces() 的排序，否则每次显示的序号都会变。
func TestPickCandidates(t *testing.T) {
	list := []envcheck.Interface{
		{Name: "Loopback Pseudo-Interface 1", Up: true, IPv4: []string{"127.0.0.1"}},
		{Name: "以太网", Up: false, IPv4: []string{"192.168.1.5"}},
		{Name: "Tailscale", Up: true}, // 没有 IPv4：绑不上源地址
		{Name: "WLAN", Up: true, IPv4: []string{"192.168.100.15"}},
		{Name: "VMware Network Adapter VMnet8", Up: true, IPv4: []string{"192.168.133.1"}},
	}
	got := pickCandidates(list)
	want := []string{"WLAN", "VMware Network Adapter VMnet8"}
	if len(got) != len(want) {
		t.Fatalf("pickCandidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("第 %d 项 = %q, want %q", i, got[i].Name, want[i])
		}
	}
}

func TestParseChoice(t *testing.T) {
	cases := []struct {
		line string
		n    int
		want int
	}{
		{"", 3, 0},     // 直接回车 = 自动
		{"\r\n", 3, 0}, // 双击环境下 ReadString 带 \r
		{"\n", 3, 0},
		{"0", 3, 0}, // 显式选"自动"
		{" 1 ", 3, 1},
		{"3\n", 3, 3},
		{"4", 3, 0},   // 越界
		{"abc", 3, 0}, // 非数字
		{"1", 0, 0},   // 没有候选
	}
	for _, c := range cases {
		if got := parseChoice(c.line, c.n); got != c.want {
			t.Errorf("parseChoice(%q, %d) = %d, want %d", c.line, c.n, got, c.want)
		}
	}
}

// 走一遍真实的交互选择：输入序号 → 返回对应网卡；回车 → 返回 ""（自动）。
func TestPromptInterface(t *testing.T) {
	cands := pickCandidates(envcheck.Interfaces())
	if len(cands) < 2 {
		t.Skip("本机可用网卡不足两块，跳过交互选择测试")
	}
	env := &envcheck.Info{
		InterfaceName: "WLAN",
		InterfaceIP:   net.ParseIP("192.168.100.15"),
		SystemDNS:     []string{"192.168.100.1"},
	}
	var out bytes.Buffer
	got := promptInterface(env, bufio.NewReader(strings.NewReader("1\n")), &out)
	if got != cands[0].Name {
		t.Errorf("选 1 应返回 %q，got %q", cands[0].Name, got)
	}
	if !strings.Contains(out.String(), cands[0].Name) {
		t.Errorf("菜单里应列出候选网卡，got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "0) 自动") {
		t.Error("菜单应提供「自动」选项")
	}

	got = promptInterface(env, bufio.NewReader(strings.NewReader("\n")), &bytes.Buffer{})
	if got != "" {
		t.Errorf("直接回车应回落到自动探测，got %q", got)
	}

	// 越界输入同样回落到自动，并给一句提示而不是默默忽略。
	out.Reset()
	got = promptInterface(env, bufio.NewReader(strings.NewReader("99\n")), &out)
	if got != "" {
		t.Errorf("越界输入应回落到自动，got %q", got)
	}
	if !strings.Contains(out.String(), "无效输入") {
		t.Error("越界输入应给出提示")
	}
}

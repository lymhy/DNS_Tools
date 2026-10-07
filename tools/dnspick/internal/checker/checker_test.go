package checker

import (
	"reflect"
	"testing"
)

func TestOverlap(t *testing.T) {
	if !overlap([]string{"1.1.1.1", "2.2.2.2"}, []string{"3.3.3.3", "2.2.2.2"}) {
		t.Error("有交集应返回 true")
	}
	if overlap([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Error("无交集应返回 false")
	}
	if overlap(nil, []string{"2.2.2.2"}) {
		t.Error("空切片不应算有交集")
	}
}

// 域名遍历顺序必须稳定：map 顺序随机会让每个端点抽到不同的 TTFB 子集，
// 各列之间就不可比了。
func TestSortedKeys(t *testing.T) {
	m := map[string][]string{"c": nil, "a": nil, "b": nil}
	for i := 0; i < 20; i++ {
		if got := sortedKeys(m); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
			t.Fatalf("sortedKeys 应稳定有序，got %v", got)
		}
	}
}

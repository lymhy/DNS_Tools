package checker

import (
	"github.com/miekg/dns"

	"dnspick/internal/config"
	"dnspick/internal/prober"
)

// 正 / 反向 DNSSEC 测试域名：
//   - cloudflare.com 已签名，验证型解析器应回 AD=1（并带 RRSIG）。
//   - dnssec-failed.org 的签名故意失效（Verisign/Comcast 提供的公共测试域），
//     真正做 DNSSEC 验证的解析器必须返回 SERVFAIL；返回答案说明"声称验证但未验证"。
const (
	dnssecSignedDomain = "cloudflare.com"
	dnssecBrokenDomain = "dnssec-failed.org"
)

// dnssecStrict 判定解析器是否真的在验证签名：对签名失效域名必须 SERVFAIL。
// neg 为 nil（传输失败/超时无法判定）时返回 false，不据此扣分。
func dnssecStrict(neg *prober.DNSSECReply) bool {
	if neg == nil {
		return false
	}
	return neg.RCode == dns.RcodeServerFailure
}

// CheckDNSSEC 判定各端点是否真正做 DNSSEC 验证（RFC 4035）。
// 正向填 AD / RRSIG（上游是否签名、解析器是否声称验证）；
// 反向判定 dnssecStrict（对签名失效域名是否 SERVFAIL）。
// 反向域名不可达（本机 DNS 污染/网络受限）时跳过反向判定，不因此判负。
func CheckDNSSEC(r *prober.Runner, th *config.Thresholds) {
	r.Progress("干净度：DNSSEC 验证能力检测（AD / RRSIG / 失效签名）…")
	for _, ep := range r.Endpoints {
		m := r.Metrics(ep)
		if pos, err := r.QueryDO(ep, dnssecSignedDomain, th.Timeout()); err == nil && pos != nil {
			m.DNSSECAD = pos.AD
			m.DNSSECRRSIG = pos.RRSIG
		}
		neg, err := r.QueryDO(ep, dnssecBrokenDomain, th.Timeout())
		if err == nil {
			m.DNSSECStrict = dnssecStrict(neg)
		}
	}
}
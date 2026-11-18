package suggest

import "strings"

// Network is the coarse type of an ASN, which decides between "block"
// and "challenge" (SPEC 13.1 guard rail: blocking an eyeball/backbone ASN
// hurts real users — learned the hard way).
type Network string

const (
	Hosting Network = "hosting" // cloud / datacenter: no humans browse from here
	Eyeball Network = "eyeball" // residential / mobile / backbone ISP
	Unknown Network = "unknown"
)

// Well-known networks. Deliberately short: precision beats coverage, and
// anything unlisted falls back to the ASN name, then to Unknown (which is
// treated like Eyeball — challenge, never block).
var hostingASNs = map[int]bool{
	16509: true, 14618: true, 8987: true, // AWS
	396982: true, 15169: true, // Google Cloud / Google
	8075:  true,              // Microsoft / Azure
	45102: true, 37963: true, // Alibaba Cloud
	132203: true, 45090: true, // Tencent Cloud
	136907: true, 55990: true, // Huawei Cloud
	150436: true, 396986: true, // BytePlus / ByteDance
	31898: true,              // Oracle Cloud
	14061: true,              // DigitalOcean
	24940: true,              // Hetzner
	16276: true,              // OVH
	63949: true,              // Linode / Akamai
	20473: true,              // Vultr / Choopa
	51167: true, 40021: true, // Contabo
	12876: true,              // Scaleway
	9009:  true,              // M247
	60781: true, 16265: true, // Leaseweb
	47583:  true, // Hostinger
	212238: true, // Datacamp
	36352:  true, // ColoCrossing
	53667:  true, // FranTech / BuyVM
	199524: true, // G-Core
	62240:  true, // Clouvider
	3214:   true, // xTom
}

var eyeballASNs = map[int]bool{
	4134: true, 4812: true, 4809: true, // China Telecom
	4837: true, 4808: true, 17621: true, // China Unicom
	9808: true, 56040: true, 56041: true, 56046: true, 56047: true, 56048: true, // China Mobile
	3462: true,             // HiNet
	4766: true, 9318: true, // KT, SK Broadband
	17676: true, 2516: true, 4713: true, // SoftBank, KDDI, NTT OCN
	7922: true, 7018: true, 701: true, 22773: true, 20115: true, 21928: true, // US ISPs
	3320: true, 3215: true, 2856: true, 5089: true, 12322: true, 1136: true, 3352: true, 3269: true, 6830: true, // EU ISPs
	12389: true,                           // Rostelecom
	9829:  true, 55836: true, 24560: true, // India
	9299: true, 7552: true, 45899: true, // PH, VN
	28573: true, 18881: true, 8151: true, // LATAM
}

var hostingWords = []string{"hosting", "cloud", "datacenter", "data center", "data-center", "server", "vps", "colocation",
	"amazon", "aws", "digitalocean", "hetzner", "ovh", "linode", "vultr", "contabo", "alibaba", "tencent", "oracle", "leaseweb", "m247",
	"byteplus", "bytedance", "volcengine", "huawei cloud", "baidu cloud", "kingsoft", "ucloud", "akamai", "fastly", "datacamp", "choopa", "psychz"}

var eyeballWords = []string{"telecom", "telekom", "mobile", "broadband", "cable", "wireless", "cellular", "fiber", "fibre", "dsl",
	"unicom", "comcast", "verizon", "isp", "telco", "movil", "telefonica"}

// Classify returns the network type of an ASN, using the built-in table
// first and the registered name (may be empty) second.
func Classify(asn int, name string) Network {
	switch {
	case hostingASNs[asn]:
		return Hosting
	case eyeballASNs[asn]:
		return Eyeball
	}
	l := strings.ToLower(name)
	if l == "" {
		return Unknown
	}
	for _, w := range eyeballWords {
		if strings.Contains(l, w) {
			return Eyeball
		}
	}
	for _, w := range hostingWords {
		if strings.Contains(l, w) {
			return Hosting
		}
	}
	return Unknown
}

// HostingASNs returns the built-in hosting / cloud networks, sorted.
func HostingASNs() []int {
	out := make([]int, 0, len(hostingASNs))
	for a := range hostingASNs {
		out = append(out, a)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

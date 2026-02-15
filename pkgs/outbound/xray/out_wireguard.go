package xray

import (
	"fmt"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/komoe-shwemyae/vpnparse/pkgs/parser"
	"github.com/komoe-shwemyae/vpnparse/pkgs/utils"
)

var XrayWireguard = `{
  "protocol": "wireguard",
  "tag": "proxy",
  "settings": {
    "secretKey": "",
    "address": [],
    "mtu": 1280,
    "peers": [
      {
        "publicKey": "",
        "allowedIPs": ["0.0.0.0/0","::/0"],
        "endpoint": "",
        "persistentKeepalive": 0
      }
    ]
  }
}`

// XRWireguardOut implements IOutbound
type WireguardOut struct {
	RawUri   string
	Parser   *parser.ParserWirguard
	outbound string
}

// -------------------------
// IOutbound methods
// -------------------------

func (x *WireguardOut) Parse(rawUri string) {
	p := &parser.ParserWirguard{}
	if err := p.Parse(rawUri); err != nil {
		fmt.Println("WireGuard parse error:", err)
	}
	x.Parser = p
	x.RawUri = rawUri
}

func (x *WireguardOut) Addr() string {
	if x.Parser == nil {
		return ""
	}
	return x.Parser.GetAddr()
}

func (x *WireguardOut) Port() int {
	if x.Parser == nil {
		return 0
	}
	return x.Parser.GetPort()
}

func (x *WireguardOut) Scheme() string {
	return parser.SchemeWireguard
}

func (x *WireguardOut) GetRawUri() string {
	return x.RawUri
}

func (x *WireguardOut) GetOutboundStr() string {
	if x.outbound == "" {
		x.outbound = x.getSettings()
	}
	return x.outbound
}

// -------------------------
// internal helper
// -------------------------

func (x *WireguardOut) getSettings() string {
	if x.Parser == nil {
		return ""
	}

	j := gjson.New(XrayWireguard)

	j.Set("tag", utils.OutboundTag)

	j.Set("settings.secretKey", x.Parser.PrivateKey)
	j.Set("settings.address.0", x.Parser.AddrV4+"/32")

	if x.Parser.MTU > 0 {
		j.Set("settings.mtu", x.Parser.MTU)
	}

	j.Set("settings.peers.0.publicKey", x.Parser.PublicKey)
	j.Set("settings.peers.0.preSharedKey", x.Parser.PresharedKey)
	j.Set("settings.peers.0.endpoint",
		fmt.Sprintf("%s:%d", x.Parser.Address, x.Parser.Port),
	)
	if x.Parser.KeepAlive > 0 {
		j.Set("settings.peers.0.persistentKeepalive", x.Parser.KeepAlive)
	}


	return j.MustToJsonString()
}

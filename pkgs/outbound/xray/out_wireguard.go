package xray

import (
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/komoe-shwemyae/vpnparse/pkgs/parser"
	"github.com/komoe-shwemyae/vpnparse/pkgs/utils"
)

var XrayWireguard = `{
  "protocol": "wireguard",
  "tag": "wireguard-out",
  "settings": {
    "secretKey": "",
    "address": [],
    "peers": [
      {
        "publicKey": "",
        "allowedIPs": ["0.0.0.0/0","::/0"],
        "endpoint": ""
      }
    ],
    "mtu": 1280
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
	if x.Parser == nil || x.Parser.Address == "" || x.Parser.Port == 0 {
		return ""
	}

	j := gjson.New(XrayWireguard)
	j.Set("tag", utils.OutboundTag)
	j.Set("settings.secretKey", x.Parser.PrivateKey)

	// addresses
	var addresses []string
	if x.Parser.AddrV4 != "" {
		addr := strings.TrimSpace(x.Parser.AddrV4)
		if !strings.Contains(addr, "/") {
			addr += "/32"
		}
		addresses = append(addresses, addr)

	} else {
		addresses = append(addresses, "10.0.0.1/32")
	}
	if x.Parser.AddrV6 != "" {
		if !strings.Contains(x.Parser.AddrV6, "/") {
			addresses = append(addresses, x.Parser.AddrV6+"/128")
		} else {
			addresses = append(addresses, x.Parser.AddrV6)
		}
	}
	j.Set("settings.address", addresses)

	// Peer Settings
	j.Set("settings.peers.0.publicKey", x.Parser.PublicKey)
	// PresharedKey ရှိရင် ထည့်ပေးရန် (Xray support လုပ်ပါတယ်)
	if x.Parser.PresharedKey != "" {
		j.Set("settings.peers.0.preSharedKey", x.Parser.PresharedKey)
	}

	endpoint := fmt.Sprintf("%s:%d", x.Parser.Address, x.Parser.Port)
	j.Set("settings.peers.0.endpoint", endpoint)

	if x.Parser.KeepAlive > 0 {
		j.Set("settings.peers.0.persistentKeepalive", x.Parser.KeepAlive)
	}
	// MTU
	if x.Parser.MTU > 0 {
		j.Set("settings.mtu", x.Parser.MTU)
	} else {
		j.Set("settings.mtu", 1420) // Default MTU
	}

	// Reserved (Xray-core မှာ [int, int, int] format အတိုင်း ဖြစ်ရပါမယ်)
	if len(x.Parser.Reserved) > 0 {
		j.Set("settings.reserved", x.Parser.Reserved)
	}

	return j.MustToJsonString()
}

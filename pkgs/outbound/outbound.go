package outbound

import (
	"fmt"

	"github.com/komoe-shwemyae/vpnparse/pkgs/outbound/xray"
	"github.com/komoe-shwemyae/vpnparse/pkgs/parser"
	"github.com/komoe-shwemyae/vpnparse/pkgs/utils"
)

type ClientType string

const (
	XrayCore ClientType = "xray"
)

func GetOutbound(clientType ClientType, rawUri string) (result IOutbound) {
	scheme := utils.ParseScheme(rawUri)
	switch clientType {
	case XrayCore:
		switch scheme {
		case parser.SchemeVmess:
			result = &xray.VmessOut{RawUri: rawUri}
		case parser.SchemeVless:
			result = &xray.VlessOut{RawUri: rawUri}
		case parser.SchemeTrojan:
			result = &xray.TrojanOut{RawUri: rawUri}
		case parser.SchemeSS:
			result = &xray.ShadowSocksOut{RawUri: rawUri}
		default:
			fmt.Println("unsupported protocol: ", scheme)
		}
	
	default:
		fmt.Println("unsupported client type")
	}
	return
}

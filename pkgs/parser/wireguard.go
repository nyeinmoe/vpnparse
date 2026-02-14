package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gvcgo/goutils/pkgs/gtui"
)

type ParserWirguard struct {
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	AddrV4       string
	AddrV6       string
	MTU          int
	KeepAlive    int
	UDP          bool
	Reserved     []int
	Address      string
	Port         int
	DeviceName   string
}

// Parse detects which style the URI is and parses it accordingly
func (p *ParserWirguard) Parse(rawUri string) error {

	rawUri = strings.TrimSpace(rawUri)

	// remove both possible schemes
	rawUri = strings.TrimPrefix(rawUri, "wireguard://")
	rawUri = strings.TrimPrefix(rawUri, "wg://")

	// ✅ If JSON style (starts with { )
	if strings.HasPrefix(rawUri, "{") {
		if err := json.Unmarshal([]byte(rawUri), p); err != nil {
			gtui.PrintError(err)
			return err
		}
		return nil
	}

	// ✅ Otherwise treat as query style
	u, err := url.Parse("wg://" + rawUri)
	if err != nil {
		gtui.PrintError(err)
		return err
	}

	p.Address = u.Hostname()

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return fmt.Errorf("invalid port")
	}
	p.Port = port

	q := u.Query()

	// 🔥 FIX: restore + in base64 keys
	p.PrivateKey = restorePlus(q.Get("privateKey"))
	p.PublicKey = restorePlus(q.Get("publicKey"))
	p.PresharedKey = restorePlus(q.Get("presharedKey"))
	p.AddrV4 = q.Get("ip")

	p.MTU, _ = strconv.Atoi(q.Get("mtu"))
	p.KeepAlive, _ = strconv.Atoi(q.Get("keepalive"))
	p.UDP = q.Get("udp") == "1"

	// Reserved array
	res := q.Get("reserved")
	if res != "" {
		p.Reserved = []int{} // reset အရင်လုပ်ပါ
		parts := strings.Split(res, ",")
		for _, v := range parts {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			p.Reserved = append(p.Reserved, n)
		}
	}

	p.DeviceName = q.Get("ifp")

	return nil
}

func restorePlus(s string) string {
	return strings.ReplaceAll(s, " ", "+")
}

func (p *ParserWirguard) GetAddr() string {
	return p.Address
}

func (p *ParserWirguard) GetPort() int {
	return p.Port
}

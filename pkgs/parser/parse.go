package parser

import (
	"net/url"
	"strings"

	"github.com/gvcgo/goutils/pkgs/crypt"
	"github.com/gvcgo/goutils/pkgs/gtui"
)

const (
	SchemeSS        string = "ss://"
	SchemeSSR       string = "ssr://"
	SchemeTrojan    string = "trojan://"
	SchemeVless     string = "vless://"
	SchemeVmess     string = "vmess://"
	SchemeWireguard string = "wireguard://"
)

func GetVpnScheme(rawUri string) string {
	sep := "://"
	if !strings.Contains(rawUri, sep) {
		return ""
	}
	sList := strings.Split(rawUri, sep)
	return sList[0] + sep
}

func HandleQuery(rawUri string) (result string) {
	result = rawUri
	if !strings.Contains(rawUri, "?") {
		return
	}
	sList := strings.Split(rawUri, "?")
	query := sList[1]
	if strings.Contains(query, ";") && !strings.Contains(query, "&") {
		result = sList[0] + "?" + strings.ReplaceAll(sList[1], ";", "&")
	}
	return
}

func ParseRawUri(rawUri string) (result string) {

	// ================= VMESS =================
	if strings.HasPrefix(rawUri, SchemeVmess) {
		if r := crypt.DecodeBase64(strings.Split(rawUri, "://")[1]); r != "" {
			result = SchemeVmess + r
		}
		return
	}

	// ================= SS (FIXED BASE64 LOGIC) =================
	if strings.HasPrefix(rawUri, SchemeSS) {
		// ss:// ဖြုတ်
		body := strings.TrimPrefix(rawUri, SchemeSS)

		// # comment ခွဲ
		comment := ""
		if idx := strings.Index(body, "#"); idx != -1 {
			comment = body[idx:]
			body = body[:idx]
		}

		// @ မရှိရင် SS မမှန်
		if strings.Contains(body, "@") {
			parts := strings.SplitN(body, "@", 2)
			userinfo := parts[0] // base64(method:password)
			hostport := parts[1]

			// base64 decode (SS standard)
			if decoded := crypt.DecodeBase64(userinfo); decoded != "" {
				// ss://method:password@host:port#comment
				result = SchemeSS + decoded + "@" + hostport + comment
				return
			}
		}

		// decode မဖြစ်ရင် original ပြန်
		result = rawUri
		return
	}

	// ================= COMMON LOGIC =================
	if strings.Contains(rawUri, "\u0026") {
		rawUri = strings.ReplaceAll(rawUri, "\u0026", "&")
	}

	rawUri, _ = url.QueryUnescape(rawUri)

	r, err := url.Parse(rawUri)
	result = rawUri
	if err != nil {
		gtui.PrintError(err)
		return
	}

	host := r.Host
	uname := r.User.Username()
	_, hasPassword := r.User.Password() // passw မလိုတော့ဘူး

	if !strings.Contains(rawUri, "@") {
		// host base64 decode (rare case)
		if hostDecrypted := crypt.DecodeBase64(host); hostDecrypted != "" {
			result = strings.ReplaceAll(rawUri, host, hostDecrypted)
		}
	} else if uname != "" && !hasPassword && !strings.Contains(uname, "-") {
		// username base64 decode
		if unameDecrypted := crypt.DecodeBase64(uname); unameDecrypted != "" {
			result = strings.ReplaceAll(rawUri, uname, unameDecrypted)
		}
	}

	if strings.Contains(result, "%") {
		result, _ = url.QueryUnescape(result)
	}

	result = HandleQuery(result)
	return
}



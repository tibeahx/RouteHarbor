// Package adapter owns source-specific inputs and strictly validates engine imports.
package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/model"
)

var (
	idPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	uuidPattern      = regexp.MustCompile(
		`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
	)
)

type ProxySettings struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}
type InterfaceSettings struct {
	Name string `json:"name"`
}
type PacketSettings struct {
	Strategy string `json:"strategy"`
}
type TLSSettings struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
}
type Transport struct {
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}
type SingOutbound struct {
	Type       string       `json:"type"`
	Server     string       `json:"server"`
	ServerPort int          `json:"server_port"`
	UUID       string       `json:"uuid,omitempty"`
	Password   string       `json:"password,omitempty"`
	Username   string       `json:"username,omitempty"`
	Method     string       `json:"method,omitempty"`
	TLS        *TLSSettings `json:"tls,omitempty"`
	Transport  *Transport   `json:"transport,omitempty"`
}
type XraySettings struct {
	Link     string        `json:"link,omitempty"`
	Outbound *XrayOutbound `json:"outbound,omitempty"`
}
type XrayUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}
type XrayServer struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []XrayUser `json:"users"`
}
type XrayEndpoint struct {
	VNext []XrayServer `json:"vnext"`
}
type XrayTLS struct {
	ServerName string `json:"serverName,omitempty"`
}
type XrayWS struct {
	Path string `json:"path,omitempty"`
}
type XrayStream struct {
	Network  string   `json:"network"`
	Security string   `json:"security"`
	TLS      *XrayTLS `json:"tlsSettings,omitempty"`
	WS       *XrayWS  `json:"wsSettings,omitempty"`
}
type XrayOutbound struct {
	Protocol string       `json:"protocol"`
	Settings XrayEndpoint `json:"settings"`
	Stream   XrayStream   `json:"streamSettings"`
}

// StrictDecode rejects unknown keys, trailing values and duplicate keys at any depth.
// Errors deliberately exclude attacker-controlled values and credential-bearing input.
func StrictDecode(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > 64<<10 || len(bytes.TrimSpace(raw)) == 0 ||
		(bytes.TrimSpace(raw)[0] != '{' && bytes.TrimSpace(raw)[0] != '[') {
		return errors.New("settings must be a bounded JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func() error
	visit = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate key")
				}
				seen[s] = true
				if e = visit(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := visit(); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid delimiter")
		}
		_, e = d.Token()
		return e
	}
	if err := visit(); err != nil {
		return errors.New("invalid or duplicate JSON settings")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("unsupported or invalid settings fields")
	}
	return nil
}

func validHost(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.TrimSpace(s) != s ||
		strings.ContainsAny(s, "/\\@?#%\x00\r\n\t ") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.Contains(s, ":") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func validEndpoint(
	host string,
	port int,
) bool {
	return validHost(host) && port > 0 && port < 65536
}

func validateProxy(p ProxySettings) error {
	if !validEndpoint(p.Server, p.ServerPort) {
		return errors.New("invalid proxy endpoint")
	}
	if len(p.Username) > 255 || len(p.Password) > 255 ||
		strings.ContainsAny(p.Username+p.Password, "\r\n\x00") {
		return errors.New("invalid proxy credentials")
	}
	if p.Password != "" && p.Username == "" {
		return errors.New("proxy password requires a username")
	}
	return nil
}

func validateSing(s SingOutbound) error {
	if !validEndpoint(s.Server, s.ServerPort) {
		return errors.New("invalid outbound endpoint")
	}
	if len(s.Password) > 4096 || len(s.Username) > 255 {
		return errors.New("outbound credential exceeds limit")
	}
	switch s.Type {
	case "vless":
		if !uuidPattern.MatchString(s.UUID) || s.Password != "" || s.Username != "" ||
			s.Method != "" {
			return errors.New("invalid VLESS outbound")
		}
	case "trojan":
		if s.Password == "" || s.UUID != "" || s.Username != "" || s.Method != "" {
			return errors.New("invalid Trojan outbound")
		}
	case "shadowsocks":
		if s.Password == "" || s.UUID != "" || s.Username != "" {
			return errors.New("invalid Shadowsocks outbound")
		}
		switch s.Method {
		case "aes-128-gcm",
			"aes-256-gcm",
			"chacha20-ietf-poly1305",
			"2022-blake3-aes-128-gcm",
			"2022-blake3-aes-256-gcm":
		default:
			return errors.New("unsupported Shadowsocks cipher")
		}
	case "socks", "http":
		if e := validateProxy(
			ProxySettings{
				Server:     s.Server,
				ServerPort: s.ServerPort,
				Username:   s.Username,
				Password:   s.Password,
			},
		); e != nil {
			return e
		}
		if s.UUID != "" || s.Method != "" {
			return errors.New("invalid proxy outbound")
		}
	default:
		return errors.New("unsupported sing-box outbound type")
	}
	if s.TLS != nil {
		if !s.TLS.Enabled || s.TLS.ServerName != "" && !validHost(s.TLS.ServerName) {
			return errors.New("TLS verification must be enabled")
		}
	}
	if (s.Type == "vless" || s.Type == "trojan") && s.TLS == nil {
		return errors.New("this outbound requires verified TLS")
	}
	if s.Transport != nil {
		if s.Type != "vless" && s.Type != "trojan" {
			return errors.New("transport unsupported for this outbound")
		}
		switch s.Transport.Type {
		case "ws":
			if s.Transport.ServiceName != "" || len(s.Transport.Path) > 2048 ||
				strings.ContainsAny(s.Transport.Path, "\r\n\x00") ||
				s.Transport.Path != "" && !strings.HasPrefix(s.Transport.Path, "/") {
				return errors.New("invalid WebSocket transport")
			}
		case "grpc":
			if s.Transport.Path != "" || len(s.Transport.ServiceName) > 256 ||
				strings.ContainsAny(s.Transport.ServiceName, "\r\n\x00") {
				return errors.New("invalid gRPC transport")
			}
		default:
			return errors.New("unsupported transport")
		}
	}
	return nil
}

func normalizeXray(s XraySettings) (XrayOutbound, error) {
	if (s.Link == "") == (s.Outbound == nil) {
		return XrayOutbound{}, errors.New("supply one Xray link or native outbound")
	}
	if s.Outbound != nil {
		return *s.Outbound, validateXray(*s.Outbound)
	}
	u, err := url.Parse(s.Link)
	if err != nil || u.Scheme != "vless" || u.User == nil || u.Path != "" || u.Opaque != "" {
		return XrayOutbound{}, errors.New("only supported VLESS Xray links are accepted")
	}
	if _, ok := u.User.Password(); ok {
		return XrayOutbound{}, errors.New("invalid Xray identity")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		return XrayOutbound{}, errors.New("xray link requires a port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return XrayOutbound{}, errors.New("invalid Xray link query")
	}
	for k, v := range q {
		if len(v) != 1 {
			return XrayOutbound{}, errors.New("duplicate Xray link option")
		}
		switch k {
		case "type", "security", "sni", "path", "encryption":
		default:
			return XrayOutbound{}, errors.New("unsupported Xray link option")
		}
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	enc := q.Get("encryption")
	if enc == "" {
		enc = "none"
	}
	out := XrayOutbound{
		Protocol: "vless",
		Settings: XrayEndpoint{
			VNext: []XrayServer{
				{
					Address: u.Hostname(),
					Port:    p,
					Users:   []XrayUser{{ID: u.User.Username(), Encryption: enc}},
				},
			},
		},
		Stream: XrayStream{
			Network:  network,
			Security: q.Get("security"),
			TLS:      &XrayTLS{ServerName: q.Get("sni")},
		},
	}
	if network == "ws" {
		out.Stream.WS = &XrayWS{Path: q.Get("path")}
	} else if q.Get("path") != "" {
		return XrayOutbound{}, errors.New("path requires WebSocket")
	}
	return out, validateXray(out)
}

func validateXray(o XrayOutbound) error {
	if o.Protocol != "vless" || len(o.Settings.VNext) != 1 {
		return errors.New("only one native Xray VLESS server is supported")
	}
	v := o.Settings.VNext[0]
	if !validEndpoint(v.Address, v.Port) || len(v.Users) != 1 ||
		!uuidPattern.MatchString(v.Users[0].ID) ||
		v.Users[0].Encryption != "none" {
		return errors.New("invalid native Xray server")
	}
	if o.Stream.Security != "tls" || o.Stream.TLS == nil ||
		o.Stream.TLS.ServerName != "" && !validHost(o.Stream.TLS.ServerName) {
		return errors.New("xray requires verified TLS")
	}
	switch o.Stream.Network {
	case "tcp":
		if o.Stream.WS != nil {
			return errors.New("unexpected WebSocket settings")
		}
	case "ws":
		if o.Stream.WS != nil &&
			(len(o.Stream.WS.Path) > 2048 || strings.ContainsAny(o.Stream.WS.Path, "\r\n\x00") || o.Stream.WS.Path != "" && !strings.HasPrefix(o.Stream.WS.Path, "/")) {
			return errors.New("invalid WebSocket path")
		}
	default:
		return errors.New("unsupported Xray transport")
	}
	return nil
}

func ValidateSource(s model.Source) error {
	if !idPattern.MatchString(s.ID) {
		return errors.New("invalid source ID")
	}
	switch s.Type {
	case "direct":
		var x struct{}
		return StrictDecode(s.Settings, &x)
	case "socks5", "http-connect":
		var p ProxySettings
		if err := StrictDecode(s.Settings, &p); err != nil {
			return err
		}
		return validateProxy(p)
	case "interface":
		var p InterfaceSettings
		if err := StrictDecode(s.Settings, &p); err != nil {
			return err
		}
		if !interfacePattern.MatchString(p.Name) {
			return errors.New("invalid interface name")
		}
	case "packet-engine":
		var p PacketSettings
		if err := StrictDecode(s.Settings, &p); err != nil {
			return err
		}
		if p.Strategy != "multisplit-v1" {
			return errors.New(
				"unsupported packet strategy; custom scripts and arguments are prohibited",
			)
		}
	case "sing-box":
		var o SingOutbound
		if err := StrictDecode(s.Settings, &o); err != nil {
			return err
		}
		return validateSing(o)
	case "xray":
		var x XraySettings
		if err := StrictDecode(s.Settings, &x); err != nil {
			return err
		}
		_, err := normalizeXray(x)
		return err
	default:
		return errors.New("unsupported source type")
	}
	return nil
}

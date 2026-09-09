// Package continuity carries logical TCP streams and UDP mappings over redundant
// mutually authenticated TLS connections. It deliberately does not create routes,
// transparent listeners, or privileged sockets; callers supply those resources.
package continuity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
)

const CarriersPerPath = 6

var (
	ErrClosed      = errors.New("continuity closed")
	ErrGeneration  = errors.New("relay session generation changed")
	ErrCapacity    = errors.New("continuity resource limit")
	ErrNoPath      = errors.New("no ready continuity path")
	ErrDestination = errors.New("relay destination is not permitted")
)

// Limits bound application queues. Kernel socket buffers and TLS allocations are
// additional to these limits and must be measured for each deployment profile.
type Limits struct {
	BufferBytes       int64
	UDPReserveBytes   int64
	FlowBytes         int64
	ControlBytes      int64
	MaxTCP            int
	MaxUDP            int
	DisconnectedGrace time.Duration
	UDPIdle           time.Duration
	UDPReplay         time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		32 << 20,
		4 << 20,
		2 << 20,
		256 << 10,
		512,
		256,
		30 * time.Second,
		120 * time.Second,
		100 * time.Millisecond,
	}
}

// Normalize applies defaults and validates an explicit resource profile.
func (l Limits) Normalize() (Limits, error) { return l.normalized() }

func (l Limits) normalized() (Limits, error) {
	d := DefaultLimits()
	if l.BufferBytes == 0 {
		l.BufferBytes = d.BufferBytes
	}
	if l.UDPReserveBytes == 0 {
		l.UDPReserveBytes = d.UDPReserveBytes
	}
	if l.FlowBytes == 0 {
		l.FlowBytes = d.FlowBytes
	}
	if l.ControlBytes == 0 {
		l.ControlBytes = d.ControlBytes
	}
	if l.MaxTCP == 0 {
		l.MaxTCP = d.MaxTCP
	}
	if l.MaxUDP == 0 {
		l.MaxUDP = d.MaxUDP
	}
	if l.DisconnectedGrace == 0 {
		l.DisconnectedGrace = d.DisconnectedGrace
	}
	if l.UDPIdle == 0 {
		l.UDPIdle = d.UDPIdle
	}
	if l.UDPReplay == 0 {
		l.UDPReplay = d.UDPReplay
	}
	if l.BufferBytes < 512<<10 || l.BufferBytes > 1<<30 || l.UDPReserveBytes < 256<<10 ||
		l.UDPReserveBytes >= l.BufferBytes ||
		l.FlowBytes < 16<<10 ||
		l.FlowBytes > 16<<20 ||
		l.ControlBytes < 64<<10 ||
		l.ControlBytes > 4<<20 ||
		l.MaxTCP < 1 ||
		l.MaxTCP > 4096 ||
		l.MaxUDP < 1 ||
		l.MaxUDP > 4096 ||
		l.DisconnectedGrace < time.Second ||
		l.DisconnectedGrace > time.Minute*5 ||
		l.UDPIdle < time.Second ||
		l.UDPIdle > time.Hour ||
		l.UDPReplay < time.Millisecond ||
		l.UDPReplay > time.Second {
		return l, errors.New("invalid continuity limits")
	}
	return l, nil
}

type (
	DialFunc       func(context.Context) (net.Conn, error)
	TargetDialFunc func(context.Context, string, string) (net.Conn, error)
)

type GatewayConfig struct {
	TLSConfig *tls.Config
	Limits    Limits
}
type RelayConfig struct {
	TLSConfig  *tls.Config
	Limits     Limits
	MaxClients int
	// DialTarget overrides the public-address-only default. It is intended for
	// isolated test fixtures or an equally restrictive policy supplied by a host.
	DialTarget TargetDialFunc
}

type CarrierSnapshot struct {
	Index  int     `json:"index"`
	Kind   string  `json:"kind"`
	Ready  bool    `json:"ready"`
	SRTTMS float64 `json:"srtt_ms"`
	RTOMS  float64 `json:"rto_ms"`
}
type PathSnapshot struct {
	Name     string            `json:"name"`
	Ready    bool              `json:"ready"`
	Carriers []CarrierSnapshot `json:"carriers"`
}
type Snapshot struct {
	SessionID         string         `json:"session_id"`
	Generation        string         `json:"generation"`
	PreferredPath     string         `json:"preferred_path"`
	ActivePath        string         `json:"active_path"`
	StandbyPath       string         `json:"standby_path"`
	Paths             []PathSnapshot `json:"paths"`
	TCPFlows          int            `json:"tcp_flows"`
	UDPFlows          int            `json:"udp_flows"`
	QueueBytes        int64          `json:"queue_bytes"`
	UDPQueueBytes     int64          `json:"udp_queue_bytes"`
	ControlQueueBytes int64          `json:"control_queue_bytes"`
	ReplayedFrames    uint64         `json:"replayed_frames"`
	ExpiredUDP        uint64         `json:"expired_udp"`
	DroppedUDP        uint64         `json:"dropped_udp"`
	Switches          uint64         `json:"switches"`
	LastSwitchPauseMS float64        `json:"last_switch_pause_ms"`
	Qualified         bool           `json:"qualified"`
	Status            string         `json:"status"`
	DegradedReason    string         `json:"degraded_reason"`
}

func CertificateFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// ClientTLS pins the relay's leaf certificate instead of delegating trust to a
// public CA. The local identity must be provisioned out of band on the relay.
func ClientTLS(cert tls.Certificate, relayFingerprint string) (*tls.Config, error) {
	check, err := fingerprintVerifier([]string{relayFingerprint})
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyConnection:   check,
	}, nil // pin verified above, no CA/DNS trust
}

func ServerTLS(cert tls.Certificate, authorizedFingerprints []string) (*tls.Config, error) {
	check, err := fingerprintVerifier(authorizedFingerprints)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: check,
	}, nil
}

func fingerprintVerifier(pins []string) (func(tls.ConnectionState) error, error) {
	if len(pins) == 0 || len(pins) > 256 {
		return nil, errors.New("explicit peer identities required")
	}
	var decoded [][]byte
	for _, pin := range pins {
		b, err := hex.DecodeString(strings.ToLower(pin))
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("invalid peer fingerprint")
		}
		decoded = append(decoded, b)
	}
	return func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || len(s.PeerCertificates) == 0 {
			return errors.New("mutual TLS 1.3 required")
		}
		cert := s.PeerCertificates[0]
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return errors.New("peer certificate is outside its validity interval")
		}
		sum := sha256.Sum256(cert.Raw)
		valid := 0
		for _, p := range decoded {
			valid |= subtle.ConstantTimeCompare(sum[:], p)
		}
		if valid != 1 {
			return errors.New("peer identity is not authorized")
		}
		return nil
	}, nil
}

func validTLS(c *tls.Config, server bool) bool {
	return c != nil && c.MinVersion >= tls.VersionTLS13 && c.VerifyConnection != nil &&
		len(c.Certificates) > 0 &&
		(!server || c.ClientAuth >= tls.RequireAnyClientCert)
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

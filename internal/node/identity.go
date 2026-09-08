package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

type Identity struct {
	ID          string
	Certificate tls.Certificate
	Fingerprint string
}
type identityDisk struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func LoadIdentity(dir string) (Identity, error) {
	r, e := openStateRoot(dir)
	if e != nil {
		return Identity{}, e
	}
	defer func() { _ = r.Close() }()
	lock, e := stateLock(r, "identity.lock")
	if e != nil {
		return Identity{}, e
	}
	defer stateUnlock(lock)
	data, e := readPrivate(r, "identity.json")
	if errors.Is(e, os.ErrNotExist) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return Identity{}, e
		}
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			return Identity{}, e
		}
		id := hex.EncodeToString(pub[:16])
		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "openrhp-" + id},
			NotBefore:    now.Add(-5 * time.Minute),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
			BasicConstraintsValid: true,
		}
		der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
		if e != nil {
			return Identity{}, e
		}
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return Identity{}, e
		}
		d := identityDisk{
			ID:          id,
			Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		}
		data, e = json.Marshal(d)
		if e != nil {
			return Identity{}, e
		}
		if e = writePrivate(r, "identity.json", data); e != nil {
			return Identity{}, e
		}
	} else if e != nil {
		return Identity{}, errors.New("cannot read private node identity")
	}
	var d identityDisk
	if e = adapter.StrictDecode(data, &d); e != nil {
		return Identity{}, errors.New("invalid node identity")
	}
	cert, e := tls.X509KeyPair([]byte(d.Certificate), []byte(d.PrivateKey))
	if e != nil || len(cert.Certificate) != 1 {
		return Identity{}, errors.New("invalid node identity keypair")
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return Identity{}, errors.New(
			"node identity certificate expired or invalid; renew through trusted administrator access",
		)
	}
	cert.Leaf = leaf
	return Identity{d.ID, cert, fingerprint(leaf)}, nil
}

func fingerprint(c *x509.Certificate) string {
	hash := sha256.Sum256(c.Raw)
	return hex.EncodeToString(hash[:])
}

func validFingerprint(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size
}

// PinnedTLS replaces CA/DNS trust with an explicitly administrator-verified
// certificate fingerprint. Verification is mandatory despite SkipVerify: the
// connection checks the exact pin, certificate validity, and TLS 1.3.
func PinnedTLS(identity Identity, pin string) (*tls.Config, error) {
	if !validFingerprint(pin) {
		return nil, errors.New("invalid_peer_fingerprint")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{identity.Certificate},
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("peer_identity_mismatch")
			}
			cert := cs.PeerCertificates[0]
			if subtle.ConstantTimeCompare([]byte(fingerprint(cert)), []byte(pin)) != 1 ||
				time.Now().Before(cert.NotBefore) ||
				time.Now().After(cert.NotAfter) {
				return errors.New("peer_identity_mismatch")
			}
			return nil
		},
	}, nil
}

type enrollment struct {
	Version            int       `json:"version"`
	CodeHash           string    `json:"code_hash,omitempty"`
	Expires            time.Time `json:"expires,omitempty"`
	Attempts           int       `json:"attempts"`
	GatewayFingerprint string    `json:"gateway_fingerprint,omitempty"`
}

type Pairing struct {
	mu   sync.Mutex
	root *os.Root
	now  func() time.Time
}

func NewPairing(dir string) (*Pairing, error) {
	r, e := openStateRoot(dir)
	if e != nil {
		return nil, e
	}
	return &Pairing{root: r, now: time.Now}, nil
}

func (p *Pairing) Close() error {
	return p.root.Close()
}

func (p *Pairing) read() (enrollment, error) {
	var s enrollment
	data, e := readPrivate(p.root, "enrollment.json")
	if errors.Is(e, os.ErrNotExist) {
		return enrollment{Version: 1}, nil
	}
	if e != nil {
		return s, e
	}
	e = adapter.StrictDecode(data, &s)
	if e != nil || s.Version != 1 {
		return s, errors.New("invalid enrollment state")
	}
	return s, nil
}

func (p *Pairing) save(s enrollment) error {
	data, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return writePrivate(p.root, "enrollment.json", data)
}

// Bootstrap must be called only through existing local administrator access.
// Calling it on an enrolled device does not silently revoke the gateway.
func (p *Pairing) Bootstrap(ttl time.Duration) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ttl < time.Minute || ttl > 15*time.Minute {
		return "", errors.New("enrollment lifetime must be 1 to 15 minutes")
	}
	lock, e := stateLock(p.root, "enrollment.lock")
	if e != nil {
		return "", e
	}
	defer stateUnlock(lock)
	s, e := p.read()
	if e != nil {
		return "", e
	}
	if s.GatewayFingerprint != "" {
		return "", errors.New("node already paired; revoke before issuing a new code")
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		return "", e
	}
	code := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(code))
	s = enrollment{Version: 1, CodeHash: hex.EncodeToString(hash[:]), Expires: p.now().Add(ttl)}
	if e = p.save(s); e != nil {
		return "", e
	}
	return code, nil
}

func (p *Pairing) Enroll(code, pin string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, e := stateLock(p.root, "enrollment.lock")
	if e != nil {
		return e
	}
	defer stateUnlock(lock)
	s, e := p.read()
	if e != nil {
		return e
	}
	if s.GatewayFingerprint != "" || s.CodeHash == "" || !p.now().Before(s.Expires) ||
		s.Attempts >= 5 {
		return errors.New("enrollment_rejected")
	}
	hash := sha256.Sum256([]byte(code))
	s.Attempts++
	valid := len(code) == 43 && validFingerprint(pin) &&
		subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(s.CodeHash)) == 1
	if valid {
		s.GatewayFingerprint = pin
		s.CodeHash = ""
		s.Expires = time.Time{}
	}
	if e = p.save(s); e != nil {
		return e
	}
	if !valid {
		return errors.New("enrollment_rejected")
	}
	return nil
}

func (p *Pairing) Authorized(pin string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, e := p.read()
	return e == nil && s.GatewayFingerprint != "" &&
		subtle.ConstantTimeCompare([]byte(s.GatewayFingerprint), []byte(pin)) == 1
}

func (p *Pairing) Revoke(pin string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, e := stateLock(p.root, "enrollment.lock")
	if e != nil {
		return e
	}
	defer stateUnlock(lock)
	s, e := p.read()
	if e != nil {
		return e
	}
	if s.GatewayFingerprint == "" ||
		subtle.ConstantTimeCompare([]byte(s.GatewayFingerprint), []byte(pin)) != 1 {
		return errors.New("unauthorized_peer")
	}
	return p.save(enrollment{Version: 1})
}

// Package protocol implements the authenticated UDP wire format shared by mesh nodes.
package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version         = 1
	DefaultTTL      = 8
	MaxDatagramSize = 60000
)

var ErrProtocol = errors.New("mesh protocol error")

func B64Encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func B64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// CanonicalJSON is deliberately compatible with Python json.dumps(sort_keys=True,
// separators=(",", ":")) for the protocol's plain JSON values.
func CanonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func NodeID(publicDER []byte) string {
	s := sha256.Sum256(publicDER)
	return hex.EncodeToString(s[:16])
}

type Identity struct {
	Private   *ecdh.PrivateKey
	PublicDER []byte
	Public    string
	ID        string
}

func NewIdentity() (*Identity, error) {
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return IdentityFromPrivate(p)
}
func IdentityFromPrivate(p *ecdh.PrivateKey) (*Identity, error) {
	pub, err := x509.MarshalPKIXPublicKey(p.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Identity{Private: p, PublicDER: pub, Public: B64Encode(pub), ID: NodeID(pub)}, nil
}
func ParsePrivateDER(b []byte) (*Identity, error) {
	v, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	p, ok := v.(*ecdh.PrivateKey)
	if !ok || p.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%w: expected X25519 private key", ErrProtocol)
	}
	return IdentityFromPrivate(p)
}
func MarshalPrivateDER(i *Identity) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(i.Private) }

func SharedKey(private *ecdh.PrivateKey, peerPublic string) ([]byte, error) {
	b, err := B64Decode(peerPublic)
	if err != nil {
		return nil, err
	}
	v, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	p, ok := v.(*ecdh.PublicKey)
	if !ok || p.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%w: expected X25519 public key", ErrProtocol)
	}
	secret, err := private.ECDH(p)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("home-mesh-v1"))
	h.Write(secret)
	return h.Sum(nil), nil
}

func Seal(key, plaintext, aad []byte) (map[string]string, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	out := a.Seal(nil, nonce, plaintext, aad)
	tagAt := len(out) - a.Overhead()
	return map[string]string{"nonce": B64Encode(nonce), "ciphertext": B64Encode(out[:tagAt]), "tag": B64Encode(out[tagAt:])}, nil
}
func Open(key []byte, sealed map[string]string, aad []byte) ([]byte, error) {
	n, e1 := B64Decode(sealed["nonce"])
	c, e2 := B64Decode(sealed["ciphertext"])
	t, e3 := B64Decode(sealed["tag"])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, fmt.Errorf("%w: invalid sealed data", ErrProtocol)
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, n, append(c, t...), aad)
}
func SealBytes(key, plaintext, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	// Fast TUN frames are binary on the wire. Do not route them through the
	// JSON helper: Base64 encode + decode here used to allocate and copy every
	// packet twice under load.
	return a.Seal(nonce, nonce, plaintext, aad), nil
}
func OpenBytes(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 28 {
		return nil, fmt.Errorf("%w: truncated encrypted payload", ErrProtocol)
	}
	a, e := chacha20poly1305.New(key)
	if e != nil {
		return nil, e
	}
	return a.Open(nil, sealed[:12], sealed[12:], aad)
}

type Packet struct {
	Type        string         `json:"type"`
	Source      string         `json:"src"`
	Destination string         `json:"dst"`
	Payload     map[string]any `json:"payload"`
	ID          string         `json:"id"`
	TTL         int            `json:"ttl"`
	Timestamp   int64          `json:"ts"`
}

func NewPacket(typ, src, dst string, payload map[string]any) Packet {
	b := make([]byte, 12)
	rand.Read(b)
	return Packet{Type: typ, Source: src, Destination: dst, Payload: payload, ID: hex.EncodeToString(b), TTL: DefaultTTL, Timestamp: time.Now().Unix()}
}
func (p Packet) DecTTL() (Packet, error) {
	if p.TTL <= 1 {
		return p, fmt.Errorf("%w: TTL expired", ErrProtocol)
	}
	p.TTL--
	return p, nil
}
func (p Packet) envelope() map[string]any {
	return map[string]any{"v": Version, "type": p.Type, "id": p.ID, "src": p.Source, "dst": p.Destination, "ttl": p.TTL, "ts": p.Timestamp, "payload": p.Payload}
}
func EncodePacket(p Packet, networkKey []byte) ([]byte, error) {
	e := p.envelope()
	data, err := CanonicalJSON(e)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, networkKey)
	m.Write(data)
	e["mac"] = B64Encode(m.Sum(nil))
	out, err := CanonicalJSON(e)
	if err == nil && len(out) > MaxDatagramSize {
		err = fmt.Errorf("%w: packet exceeds limit", ErrProtocol)
	}
	return out, err
}
func DecodePacket(data, networkKey []byte) (Packet, error) {
	if len(data) > MaxDatagramSize {
		return Packet{}, fmt.Errorf("%w: packet exceeds limit", ErrProtocol)
	}
	var e map[string]any
	if json.Unmarshal(data, &e) != nil {
		return Packet{}, fmt.Errorf("%w: malformed packet", ErrProtocol)
	}
	ms, ok := e["mac"].(string)
	if !ok {
		return Packet{}, fmt.Errorf("%w: missing MAC", ErrProtocol)
	}
	delete(e, "mac")
	got, err := B64Decode(ms)
	if err != nil {
		return Packet{}, ErrProtocol
	}
	canon, err := CanonicalJSON(e)
	if err != nil {
		return Packet{}, err
	}
	m := hmac.New(sha256.New, networkKey)
	m.Write(canon)
	if !hmac.Equal(got, m.Sum(nil)) {
		return Packet{}, fmt.Errorf("%w: authentication failed", ErrProtocol)
	}
	str := func(k string) (string, bool) { v, o := e[k].(string); return v, o }
	num := func(k string) (int64, bool) { v, o := e[k].(float64); return int64(v), o }
	typ, o1 := str("type")
	id, o2 := str("id")
	src, o3 := str("src")
	dst, o4 := str("dst")
	ttl, o5 := num("ttl")
	ts, o6 := num("ts")
	payload, o7 := e["payload"].(map[string]any)
	v, ov := num("v")
	if !(o1 && o2 && o3 && o4 && o5 && o6 && o7 && ov) || v != Version || ttl < 1 || ttl > DefaultTTL {
		return Packet{}, fmt.Errorf("%w: unsupported packet", ErrProtocol)
	}
	return Packet{typ, src, dst, payload, id, int(ttl), ts}, nil
}

// Package protocol implements the authenticated UDP wire format shared by mesh nodes.
package protocol

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version         = 1
	DefaultTTL      = 8
	MaxDatagramSize = 60000
)

var ErrProtocol = errors.New("mesh protocol error")

// LinkMeasurement is one neighbor observation as reported by a node to the
// coordinator (in /v1/telemetry and, on newer nodes, piggybacked on
// /v1/register).
type LinkMeasurement struct {
	PeerID string  `json:"peer_id"`
	RTTMS  float64 `json:"rtt_ms"`
	Up     bool    `json:"up"`
}

// B64Encode encodes bytes using the URL-safe, unpadded format used on the wire.
func B64Encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
// B64Decode decodes the URL-safe, unpadded representation used by B64Encode.
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

// NodeID derives a stable identifier from a serialized public key.
func NodeID(publicDER []byte) string {
	s := sha256.Sum256(publicDER)
	return hex.EncodeToString(s[:16])
}

// Identity holds a node key pair and its public, shareable representation.
type Identity struct {
	Private   *ecdh.PrivateKey
	PublicDER []byte
	Public    string
	ID        string
}

// NewIdentity creates a fresh X25519 identity for a mesh node.
func NewIdentity() (*Identity, error) {
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return IdentityFromPrivate(p)
}
// IdentityFromPrivate derives the public identity fields from an existing key.
func IdentityFromPrivate(p *ecdh.PrivateKey) (*Identity, error) {
	pub, err := x509.MarshalPKIXPublicKey(p.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Identity{Private: p, PublicDER: pub, Public: B64Encode(pub), ID: NodeID(pub)}, nil
}
// ParsePrivateDER loads and validates a serialized X25519 private key.
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

// SharedKey derives the symmetric peer key from the local and remote X25519 keys.
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

// Seal encrypts data and returns its nonce, ciphertext, and authentication tag.
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
// Open validates and decrypts the fields produced by Seal.
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
	// AEAD.Open panics on a wrong nonce length; malformed wire input must
	// return an error instead. Require the separately encoded tag as well.
	if len(n) != a.NonceSize() || len(t) != a.Overhead() {
		return nil, fmt.Errorf("%w: invalid nonce or tag length", ErrProtocol)
	}
	return a.Open(nil, n, append(c, t...), aad)
}
func SealBytes(key, plaintext, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return SealBytesWithAEAD(a, plaintext, aad)
}

// SealBytesWithAEAD avoids recreating the ChaCha20-Poly1305 state for every
// TUN frame when callers already cache a peer's static session key.
func SealBytesWithAEAD(a cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	// One allocation holds nonce and encrypted payload. The ciphertext is
	// appended after the nonce, so the nonce remains intact while Seal reads it.
	frame := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(frame); err != nil {
		return nil, err
	}
	// Fast TUN frames are binary on the wire. Do not route them through the
	// JSON helper: Base64 encode + decode here used to allocate and copy every
	// packet twice under load.
	return a.Seal(frame, frame[:a.NonceSize()], plaintext, aad), nil
}

// NonceSequence produces unique 96-bit ChaCha20-Poly1305 nonces for one
// sender/key pair: a random 64-bit per-session prefix and a packet counter.
// It avoids an operating-system randomness syscall for every data-plane frame.
type NonceSequence struct {
	prefix  [8]byte
	counter atomic.Uint32
}

func NewNonceSequence() (*NonceSequence, error) {
	sequence := &NonceSequence{}
	if _, err := rand.Read(sequence.prefix[:]); err != nil {
		return nil, err
	}
	return sequence, nil
}

func (s *NonceSequence) Next() ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if err := s.NextInto(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// NextInto writes the next nonce into caller-owned storage. Data-plane callers
// use it to build and encrypt a complete frame in one backing array.
func (s *NonceSequence) NextInto(nonce []byte) error {
	if len(nonce) != chacha20poly1305.NonceSize {
		return fmt.Errorf("%w: invalid nonce buffer size", ErrProtocol)
	}
	var count uint32
	for {
		previous := s.counter.Load()
		if previous == ^uint32(0) {
			return fmt.Errorf("%w: nonce sequence exhausted", ErrProtocol)
		}
		count = previous + 1
		if s.counter.CompareAndSwap(previous, count) {
			break
		}
	}
	copy(nonce, s.prefix[:])
	binary.BigEndian.PutUint32(nonce[8:], count)
	return nil
}

func SealBytesWithSequence(a cipher.AEAD, sequence *NonceSequence, plaintext, aad []byte) ([]byte, error) {
	if a.NonceSize() != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("%w: unsupported nonce size", ErrProtocol)
	}
	// Keep the nonce on the stack.  The frame itself owns the wire nonce, so
	// allocating a separate []byte for it on every TUN packet is unnecessary.
	var nonce [chacha20poly1305.NonceSize]byte
	if err := sequence.NextInto(nonce[:]); err != nil {
		return nil, err
	}
	frame := make([]byte, len(nonce), len(nonce)+len(plaintext)+a.Overhead())
	copy(frame, nonce[:])
	return a.Seal(frame, nonce[:], plaintext, aad), nil
}
func OpenBytes(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 28 {
		return nil, fmt.Errorf("%w: truncated encrypted payload", ErrProtocol)
	}
	a, e := chacha20poly1305.New(key)
	if e != nil {
		return nil, e
	}
	return OpenBytesWithAEAD(a, sealed, aad)
}

func OpenBytesWithAEAD(a cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, fmt.Errorf("%w: truncated encrypted payload", ErrProtocol)
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], aad)
}

func NewAEAD(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }

// Packet is the common control-message representation used by the overlay.
type Packet struct {
	Type        string         `json:"type"`
	Source      string         `json:"src"`
	Destination string         `json:"dst"`
	Payload     map[string]any `json:"payload"`
	ID          string         `json:"id"`
	TTL         int            `json:"ttl"`
	Timestamp   int64          `json:"ts"`
}

// NewPacket creates a packet with a random ID, default hop limit, and timestamp.
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
// DecodePacket verifies the network MAC and validates a JSON packet envelope.
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

// ---------- Compact binary keepalive format (PING/PONG) ----------
//
// The JSON envelope costs ~225 bytes per keepalive. Nodes exchange PING every
// pingInterval with every neighbor, so idle traffic is dominated by repeated
// JSON keys and hex-encoded identifiers. The compact format encodes the same
// Packet as fixed-width binary fields protected by a truncated HMAC:
//
//	offset  size  field
//	0       1     magic 0xC1
//	1       1     type: 1=PING, 2=PONG
//	2       16    source node ID (raw)
//	18      16    destination node ID (raw)
//	34      12    packet ID (raw; hex-encoded on the Packet struct)
//	46      8     unix timestamp, big endian
//	54      12    PONG only: echoed ping_id (raw)
//	last    16    HMAC-SHA256(everything before)[:16]
//
// PING encodes to CompactPingSize bytes and PONG to CompactPongSize bytes
// (~-70% versus JSON). The magic byte deliberately differs from the fast-path
// "MIP1" prefix and from '{' so receivers can demultiplex in one comparison.
// Receivers reply in the format they received, so mixed-version fleets keep
// working: old nodes still send and receive JSON, relays re-encode to JSON on
// the forwarding path.
const (
	compactMagic    = 0xC1
	compactTypePing = 1
	compactTypePong = 2
	compactHMACSize = 16
	CompactPingSize = 70
	CompactPongSize = 82
)

// IsCompact reports whether the datagram uses the binary keepalive format.
func IsCompact(data []byte) bool {
	return len(data) >= 2 && data[0] == compactMagic
}

// EncodeCompact serializes a PING or PONG packet into the binary keepalive
// format. Any other packet type fails; callers fall back to EncodePacket.
func EncodeCompact(p Packet, networkKey []byte) ([]byte, error) {
	var typ byte
	switch p.Type {
	case "PING":
		typ = compactTypePing
	case "PONG":
		typ = compactTypePong
	default:
		return nil, fmt.Errorf("%w: compact encoding supports only PING/PONG", ErrProtocol)
	}
	src, err := hex.DecodeString(p.Source)
	if err != nil || len(src) != 16 {
		return nil, fmt.Errorf("%w: source must be a 32-hex node ID", ErrProtocol)
	}
	dst, err := hex.DecodeString(p.Destination)
	if err != nil || len(dst) != 16 {
		return nil, fmt.Errorf("%w: destination must be a 32-hex node ID", ErrProtocol)
	}
	id, err := hex.DecodeString(p.ID)
	if err != nil || len(id) != 12 {
		return nil, fmt.Errorf("%w: packet ID must be a 24-hex value", ErrProtocol)
	}
	body := make([]byte, 0, CompactPongSize)
	body = append(body, compactMagic, typ)
	body = append(body, src...)
	body = append(body, dst...)
	body = append(body, id...)
	body = binary.BigEndian.AppendUint64(body, uint64(p.Timestamp))
	if typ == compactTypePong {
		if pingID, _ := p.Payload["ping_id"].(string); len(pingID) > 0 {
			raw, err := hex.DecodeString(pingID)
			if err != nil || len(raw) != 12 {
				return nil, fmt.Errorf("%w: ping_id must be a 24-hex value", ErrProtocol)
			}
			body = append(body, raw...)
		} else {
			return nil, fmt.Errorf("%w: compact PONG requires ping_id", ErrProtocol)
		}
	}
	mac := hmac.New(sha256.New, networkKey)
	mac.Write(body)
	// Sum appends the 32-byte digest; keep only the truncated prefix.
	return mac.Sum(body)[:len(body)+compactHMACSize], nil
}

// DecodeCompact parses the binary keepalive format back into the common
// Packet shape so keepalive bookkeeping (replay cache, RTT probes) works
// without caring about the wire format.
func DecodeCompact(data, networkKey []byte) (Packet, error) {
	if !IsCompact(data) {
		return Packet{}, fmt.Errorf("%w: not a compact packet", ErrProtocol)
	}
	want := CompactPingSize
	var kind string
	switch data[1] {
	case compactTypePing:
		kind = "PING"
	case compactTypePong:
		kind, want = "PONG", CompactPongSize
	default:
		return Packet{}, fmt.Errorf("%w: unknown compact type %d", ErrProtocol, data[1])
	}
	if len(data) != want {
		return Packet{}, fmt.Errorf("%w: compact packet has %d bytes, want %d", ErrProtocol, len(data), want)
	}
	mac := hmac.New(sha256.New, networkKey)
	mac.Write(data[:len(data)-compactHMACSize])
	sum := mac.Sum(nil)
	if !hmac.Equal(sum[:compactHMACSize], data[len(data)-compactHMACSize:]) {
		return Packet{}, fmt.Errorf("%w: compact authentication failed", ErrProtocol)
	}
	p := Packet{
		Type:        kind,
		Source:      hex.EncodeToString(data[2:18]),
		Destination: hex.EncodeToString(data[18:34]),
		ID:          hex.EncodeToString(data[34:46]),
		TTL:         DefaultTTL,
		Timestamp:   int64(binary.BigEndian.Uint64(data[46:54])),
	}
	if kind == "PONG" {
		p.Payload = map[string]any{"ping_id": hex.EncodeToString(data[54:66])}
	}
	return p, nil
}

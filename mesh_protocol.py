"""Wire format and cryptographic primitives for the UDP mesh overlay."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC


PROTOCOL_VERSION = 1
MAX_DATAGRAM_SIZE = 60_000
DEFAULT_TTL = 8


class ProtocolError(ValueError):
    pass


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def node_id(public_key_der: bytes) -> str:
    return hashlib.sha256(public_key_der).hexdigest()[:32]


def generate_identity() -> ECC.EccKey:
    return ECC.generate(curve="X25519")


def export_private_key(key: ECC.EccKey) -> str:
    return b64encode(key.export_key(format="DER", use_pkcs8=True))


def import_private_key(value: str) -> ECC.EccKey:
    return ECC.import_key(b64decode(value))


def export_public_key(key: ECC.EccKey) -> str:
    return b64encode(key.public_key().export_key(format="DER"))


def import_public_key(value: str) -> ECC.EccKey:
    return ECC.import_key(b64decode(value))


def shared_key(private_key: ECC.EccKey, peer_public_key: str) -> bytes:
    peer_key = import_public_key(peer_public_key)
    return key_agreement(
        static_priv=private_key,
        static_pub=peer_key,
        kdf=lambda secret: SHA256.new(b"home-mesh-v1" + secret).digest(),
    )


def seal(private_key: ECC.EccKey, destination_public_key: str, payload: bytes, aad: bytes) -> dict[str, str]:
    cipher = ChaCha20_Poly1305.new(key=shared_key(private_key, destination_public_key))
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return {"nonce": b64encode(cipher.nonce), "ciphertext": b64encode(ciphertext), "tag": b64encode(tag)}


def open_sealed(private_key: ECC.EccKey, source_public_key: str, sealed: dict[str, str], aad: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(
        key=shared_key(private_key, source_public_key), nonce=b64decode(sealed["nonce"])
    )
    cipher.update(aad)
    return cipher.decrypt_and_verify(b64decode(sealed["ciphertext"]), b64decode(sealed["tag"]))


@dataclass(frozen=True)
class Packet:
    packet_type: str
    source: str
    destination: str
    payload: dict[str, Any]
    packet_id: str
    ttl: int = DEFAULT_TTL
    timestamp: int = 0

    def __post_init__(self):
        if not self.timestamp:
            object.__setattr__(self, "timestamp", int(time.time()))

    def header(self) -> dict[str, Any]:
        return {
            "v": PROTOCOL_VERSION,
            "type": self.packet_type,
            "id": self.packet_id,
            "src": self.source,
            "dst": self.destination,
            "ttl": self.ttl,
            "ts": self.timestamp,
            "payload": self.payload,
        }

    def decrement_ttl(self) -> "Packet":
        if self.ttl <= 1:
            raise ProtocolError("TTL expired")
        return Packet(
            self.packet_type,
            self.source,
            self.destination,
            self.payload,
            self.packet_id,
            self.ttl - 1,
            self.timestamp,
        )


def create_packet(packet_type: str, source: str, destination: str, payload: dict[str, Any], ttl: int = DEFAULT_TTL) -> Packet:
    return Packet(packet_type, source, destination, payload, secrets.token_hex(12), ttl)


def encode_packet(packet: Packet, network_key: bytes) -> bytes:
    envelope = packet.header()
    envelope["mac"] = b64encode(hmac.new(network_key, canonical_json(envelope), hashlib.sha256).digest())
    data = canonical_json(envelope)
    if len(data) > MAX_DATAGRAM_SIZE:
        raise ProtocolError("packet exceeds UDP overlay limit")
    return data


def decode_packet(data: bytes, network_key: bytes) -> Packet:
    if len(data) > MAX_DATAGRAM_SIZE:
        raise ProtocolError("packet exceeds UDP overlay limit")
    try:
        envelope = json.loads(data)
        received_mac = b64decode(envelope.pop("mac"))
        expected_mac = hmac.new(network_key, canonical_json(envelope), hashlib.sha256).digest()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ProtocolError("malformed packet") from error
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ProtocolError("packet authentication failed")
    if envelope.get("v") != PROTOCOL_VERSION or not 0 < envelope.get("ttl", 0) <= DEFAULT_TTL:
        raise ProtocolError("unsupported packet")
    required = ("type", "id", "src", "dst", "payload", "ts")
    if any(key not in envelope for key in required):
        raise ProtocolError("incomplete packet")
    return Packet(
        envelope["type"], envelope["src"], envelope["dst"], envelope["payload"],
        envelope["id"], envelope["ttl"], envelope["ts"],
    )

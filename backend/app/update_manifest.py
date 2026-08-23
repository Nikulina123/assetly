"""Signed agent-update manifests.

The verification here is deliberately dependency-free and deliberately
duplicated in both endpoint agents. It is the reference implementation: if it
and an agent's copy ever disagree, the agent stops updating, so the three must
stay algorithmically identical.

RSA PKCS#1 v1.5 over SHA-256 was chosen for exactly one reason: it is
verifiable with pow() in stdlib Python and with System.Security.Cryptography
in .NET Framework. Ed25519 is a better primitive and is not available in
either without a dependency the endpoints cannot take.
"""
import base64
import hashlib
import hmac
from pathlib import Path

from app.config import UPDATES_DIR

# The ASN.1 DigestInfo prefix for SHA-256, per RFC 8017 section 9.2. The
# signature recovers to this prefix followed by the digest.
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _parse_public_key_der(der: bytes) -> tuple[int, int]:
    """Extracts (modulus, exponent) from a SubjectPublicKeyInfo DER blob.

    A minimal hand-rolled DER walk rather than an ASN.1 library, because this
    same routine has to exist in inventory_agent.py where no library is
    available -- keeping the two identical is worth more than elegance here.
    """
    def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[offset:offset + n], "big")
            offset += n
        return tag, data[offset:offset + length], offset + length

    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    _, spki, _ = read_tlv(der, 0)
    _, _algorithm, next_offset = read_tlv(spki, 0)
    _, bitstring, _ = read_tlv(spki, next_offset)
    # BIT STRING's first content octet is the count of unused trailing bits.
    rsa_der = bitstring[1:]
    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    _, rsa_seq, _ = read_tlv(rsa_der, 0)
    _, modulus, after_modulus = read_tlv(rsa_seq, 0)
    _, exponent, _ = read_tlv(rsa_seq, after_modulus)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def verify_signature(
    manifest_bytes: bytes, signature_b64: str, public_key_der_b64: str
) -> bool:
    """True when signature_b64 is a valid PKCS#1 v1.5 SHA-256 signature over
    manifest_bytes under the given public key. Never raises: any malformed
    input is a failed verification, not an error to handle at the call site."""
    try:
        signature = base64.b64decode(signature_b64)
        modulus, exponent = _parse_public_key_der(base64.b64decode(public_key_der_b64))
        key_size = (modulus.bit_length() + 7) // 8
        if len(signature) != key_size:
            return False

        recovered = pow(int.from_bytes(signature, "big"), exponent, modulus)
        encoded = recovered.to_bytes(key_size, "big")

        digest = hashlib.sha256(manifest_bytes).digest()
        suffix = _SHA256_DIGEST_INFO + digest
        expected = b"\x00\x01" + b"\xff" * (key_size - 3 - len(suffix)) + b"\x00" + suffix
        return hmac.compare_digest(encoded, expected)
    except Exception:
        return False


def load_manifest() -> tuple[bytes, str]:
    """The signed manifest and its signature, as they sit on disk.

    Returns the manifest as raw BYTES, never as a parsed object. The signature
    covers exactly these bytes, so re-serialising a parsed object -- with a
    different key order, or different whitespace -- would produce something
    the signature does not cover and no agent would accept.
    """
    manifest_path = Path(UPDATES_DIR) / "manifest.json"
    signature_path = Path(UPDATES_DIR) / "manifest.sig"
    return manifest_path.read_bytes(), signature_path.read_text().strip()

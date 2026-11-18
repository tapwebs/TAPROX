"""Pinned-IP TLS handshake and X.509 certificate inspection."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from app.services.web_inspector.url_policy import PinnedTarget

MAX_SANS = 64


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial_hex: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    sans: tuple[str, ...]
    key_algorithm: str
    key_bits: int | None
    sig_algorithm: str
    is_self_signed: bool
    is_ca: bool
    hostname_matched: bool


@dataclass(frozen=True, slots=True)
class TlsProbeResult:
    version: str | None
    cipher: str | None
    cipher_bits: int | None
    alpn: str | None
    trust_verified: bool
    trust_error: str | None
    handshake_error_code: str | None
    handshake_error: str | None
    certificate: CertificateInfo | None


def _clean_line(text: str, limit: int = 200) -> str:
    return "".join(ch for ch in text if ord(ch) >= 0x20 and ord(ch) != 0x7F)[:limit]


def _wildcard_match(pattern: str, host: str) -> bool:
    pat = pattern.lower()
    target = host.lower()
    if pat == target:
        return True
    if pat.startswith("*.") and pat.count("*") == 1:
        suffix = pat[1:]  # ".example.com"
        if target.endswith(suffix) and target.count(".") == pat.count("."):
            return len(target) > len(suffix)
    return False


def _matches_host(cert: x509.Certificate, host: str) -> bool:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san_ext = None

    if san_ext is not None:
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
        if host_ip is not None:
            return any(ip == host_ip for ip in san_ext.get_values_for_type(x509.IPAddress))
        dns_names = san_ext.get_values_for_type(x509.DNSName)
        return any(_wildcard_match(name, host) for name in dns_names)

    # RFC 6125 fallback to CN only when SAN extension is absent.
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return any(_wildcard_match(str(attr.value), host) for attr in cns)


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pub).__name__, None


def parse_der_certificate(der_bytes: bytes, *, host: str) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der_bytes)
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for name in san_ext.get_values_for_type(x509.DNSName):
            sans.append(_clean_line(name, 255))
        for ip in san_ext.get_values_for_type(x509.IPAddress):
            sans.append(str(ip))
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        pass

    key_alg, key_bits = _key_info(cert)
    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    if cert.signature_algorithm_oid._name:
        sig_alg = _clean_line(cert.signature_algorithm_oid._name, 64)

    return CertificateInfo(
        subject=_clean_line(cert.subject.rfc4514_string(), 500),
        issuer=_clean_line(cert.issuer.rfc4514_string(), 500),
        serial_hex=format(cert.serial_number, "x")[:128],
        sha256_fingerprint=hashlib.sha256(der_bytes).hexdigest(),
        not_before=cert.not_valid_before_utc.astimezone(UTC),
        not_after=cert.not_valid_after_utc.astimezone(UTC),
        sans=tuple(sans[:MAX_SANS]),
        key_algorithm=key_alg[:32],
        key_bits=key_bits,
        sig_algorithm=sig_alg,
        is_self_signed=(cert.subject == cert.issuer),
        is_ca=is_ca,
        hostname_matched=_matches_host(cert, host),
    )


def build_ssl_context(*, verify: bool, custom_ca_pem: bytes | None = None) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        if custom_ca_pem is not None:
            ctx.load_verify_locations(cadata=custom_ca_pem.decode("ascii"))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # Read-only inspection fallback ONLY to extract peer DER bytes after verified probe failed.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1", "h2"])
    return ctx


def _connect_pinned_tls(
    pinned: PinnedTarget,
    *,
    ctx: ssl.SSLContext,
    timeout_s: float,
) -> ssl.SSLSocket:
    raw_sock = socket.create_connection((pinned.pinned_ip, pinned.parsed.port), timeout=timeout_s)
    try:
        raw_sock.settimeout(timeout_s)
        return ctx.wrap_socket(raw_sock, server_hostname=pinned.parsed.host)
    except BaseException:
        raw_sock.close()
        raise


def probe_tls(
    pinned: PinnedTarget,
    *,
    timeout_s: float = 5.0,
    custom_ca_pem: bytes | None = None,
    cancel_event: threading.Event | None = None,
) -> TlsProbeResult:
    """Connect directly to pinned_ip using hostname SNI and inspect TLS + leaf certificate."""
    if cancel_event is not None and cancel_event.is_set():
        return TlsProbeResult(
            version=None,
            cipher=None,
            cipher_bits=None,
            alpn=None,
            trust_verified=False,
            trust_error=None,
            handshake_error_code="cancelled",
            handshake_error="Inspection cancelled before TLS handshake.",
            certificate=None,
        )

    # 1. Verified handshake first.
    verified_ctx = build_ssl_context(verify=True, custom_ca_pem=custom_ca_pem)
    trust_error: str | None = None
    try:
        with _connect_pinned_tls(pinned, ctx=verified_ctx, timeout_s=timeout_s) as ssock:
            cipher_info = ssock.cipher()
            der = ssock.getpeercert(binary_form=True)
            cert_info = (
                parse_der_certificate(der, host=pinned.parsed.host) if der is not None else None
            )
            return TlsProbeResult(
                version=ssock.version(),
                cipher=cipher_info[0] if cipher_info else None,
                cipher_bits=cipher_info[2] if cipher_info else None,
                alpn=ssock.selected_alpn_protocol(),
                trust_verified=True,
                trust_error=None,
                handshake_error_code=None,
                handshake_error=None,
                certificate=cert_info,
            )
    except ssl.SSLCertVerificationError as exc:
        trust_error = _clean_line(str(exc.verify_message or exc), 200)
    except ssl.SSLError as exc:
        # TLS handshake errors (e.g. protocol rejection) may fail on retry too.
        trust_error = _clean_line(str(exc), 200)
    except OSError as exc:
        return TlsProbeResult(
            version=None,
            cipher=None,
            cipher_bits=None,
            alpn=None,
            trust_verified=False,
            trust_error=None,
            handshake_error_code="tls_handshake_failed",
            handshake_error=_clean_line(f"TLS connection failed: {exc}", 200),
            certificate=None,
        )

    if cancel_event is not None and cancel_event.is_set():
        return TlsProbeResult(
            version=None,
            cipher=None,
            cipher_bits=None,
            alpn=None,
            trust_verified=False,
            trust_error=trust_error,
            handshake_error_code="cancelled",
            handshake_error="Inspection cancelled.",
            certificate=None,
        )

    # 2. Read-only CERT_NONE handshake solely to obtain peer DER certificate; no HTTP sent.
    unverified_ctx = build_ssl_context(verify=False)
    try:
        with _connect_pinned_tls(pinned, ctx=unverified_ctx, timeout_s=timeout_s) as ssock:
            cipher_info = ssock.cipher()
            der = ssock.getpeercert(binary_form=True)
            cert_info = (
                parse_der_certificate(der, host=pinned.parsed.host) if der is not None else None
            )
            return TlsProbeResult(
                version=ssock.version(),
                cipher=cipher_info[0] if cipher_info else None,
                cipher_bits=cipher_info[2] if cipher_info else None,
                alpn=ssock.selected_alpn_protocol(),
                trust_verified=False,
                trust_error=trust_error or "Certificate trust verification failed.",
                handshake_error_code=None,
                handshake_error=None,
                certificate=cert_info,
            )
    except (ssl.SSLError, OSError) as exc:
        return TlsProbeResult(
            version=None,
            cipher=None,
            cipher_bits=None,
            alpn=None,
            trust_verified=False,
            trust_error=trust_error,
            handshake_error_code="tls_handshake_failed",
            handshake_error=_clean_line(f"TLS handshake failed: {exc}", 200),
            certificate=None,
        )

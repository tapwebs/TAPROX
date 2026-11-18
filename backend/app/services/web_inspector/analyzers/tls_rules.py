"""Pure TLS and X.509 certificate findings rules (TT-WEB-TLS-001..006)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.web_inspector.analyzers import WebFinding, WebSeverity
from app.services.web_inspector.tls import CertificateInfo, TlsProbeResult

_LEGACY_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")
_WEAK_SIG_TOKENS = ("sha1", "md5", "md2", "md4")
_BASE_BLIND_SPOT = (
    "Reflects the leaf certificate and cipher negotiated by this client; "
    "other TLS versions or ciphers may still be enabled on the server."
)


def _cert_key_too_weak(cert: CertificateInfo) -> bool:
    if cert.key_bits is None:
        return False
    if cert.key_algorithm in {"RSA", "DSA"}:
        return cert.key_bits < 2048
    if cert.key_algorithm.startswith("EC"):
        return cert.key_bits < 256
    return False


def evaluate_tls(
    tls: TlsProbeResult,
    *,
    host: str,
    allow_private: bool,
    now: datetime | None = None,
) -> list[WebFinding]:
    """Evaluate TLS handshake and certificate metadata into structured findings."""
    findings: list[WebFinding] = []
    ref_now = now or datetime.now(UTC)

    if tls.version and tls.version in _LEGACY_PROTOCOLS:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-TLS-001",
                category="tls",
                severity="high",
                confidence="high",
                title="Legacy TLS protocol version negotiated",
                summary=f"The server negotiated {tls.version}, which is deprecated.",
                why=(
                    f"TLS handshake with {host} completed using {tls.version} "
                    "instead of TLS 1.2 or 1.3."
                ),
                remediation="Disable TLS 1.0 and TLS 1.1; configure TLS 1.2 and TLS 1.3 only.",
                benign_explanations=(
                    "Older embedded devices or appliances may only support legacy TLS firmware.",
                ),
                blind_spots=(_BASE_BLIND_SPOT,),
                evidence={"host": host, "tls_version": tls.version, "cipher": tls.cipher},
            )
        )

    if tls.cipher:
        upper_cipher = tls.cipher.upper()
        is_legacy_static_rsa = (
            tls.version != "TLSv1.3"
            and (upper_cipher.startswith("TLS_RSA_") or upper_cipher.startswith("AES"))
            and "ECDHE" not in upper_cipher
            and "DHE" not in upper_cipher
        )
        if any(tok in upper_cipher for tok in _WEAK_CIPHER_TOKENS) or is_legacy_static_rsa:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-TLS-006",
                    category="tls",
                    severity="medium",
                    confidence="high",
                    title="Weak or non-forward-secret cipher suite negotiated",
                    summary=(
                        f"Negotiated cipher {tls.cipher} lacks modern strength or forward secrecy."
                    ),
                    why=(
                        "The TLS handshake selected a deprecated cipher or static key-exchange "
                        "suite."
                    ),
                    remediation=(
                        "Prefer TLS 1.3 suites or ECDHE AEAD ciphers (AES-GCM / ChaCha20-Poly1305)."
                    ),
                    benign_explanations=(
                        "Legacy appliance compatibility settings can select older fallback "
                        "ciphers.",
                    ),
                    blind_spots=(_BASE_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "tls_version": tls.version,
                        "cipher": tls.cipher,
                        "cipher_bits": tls.cipher_bits,
                    },
                )
            )

    cert = tls.certificate
    if cert is not None:
        if cert.not_after < ref_now or cert.not_before > ref_now:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-TLS-002",
                    category="tls",
                    severity="high",
                    confidence="high",
                    title="TLS certificate validity period is not current",
                    summary=(
                        f"Certificate for {host} is outside its validity window "
                        f"({cert.not_before.date()} to {cert.not_after.date()})."
                    ),
                    why="The server presented an expired or not-yet-valid X.509 certificate.",
                    remediation=(
                        "Renew and deploy a valid certificate within its active date range."
                    ),
                    benign_explanations=(
                        "A staging, lab, or unmaintained local device certificate may have lapsed.",
                    ),
                    blind_spots=(_BASE_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "not_before": cert.not_before.isoformat(),
                        "not_after": cert.not_after.isoformat(),
                    },
                )
            )
        else:
            days_left = int((cert.not_after - ref_now).total_seconds() // 86400)
            if days_left <= 30:
                sev: WebSeverity = "low" if days_left <= 14 else "info"
                findings.append(
                    WebFinding(
                        rule_id="TT-WEB-TLS-004",
                        category="tls",
                        severity=sev,
                        confidence="high",
                        title="TLS certificate expiring soon",
                        summary=(
                            f"Certificate expires in {days_left} day(s) on {cert.not_after.date()}."
                        ),
                        why=(
                            "Short remaining certificate validity risks service interruption "
                            "if renewal fails."
                        ),
                        remediation="Verify automated renewal (e.g., ACME) or schedule renewal.",
                        benign_explanations=(
                            "Short-lived certificates (e.g., 90-day ACME) normally renew near "
                            "day 30.",
                        ),
                        blind_spots=(_BASE_BLIND_SPOT,),
                        evidence={
                            "host": host,
                            "days_remaining": days_left,
                            "not_after": cert.not_after.isoformat(),
                        },
                    )
                )

        if _cert_key_too_weak(cert) or any(
            t in cert.sig_algorithm.lower() for t in _WEAK_SIG_TOKENS
        ):
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-TLS-005",
                    category="tls",
                    severity="high",
                    confidence="high",
                    title="Weak certificate public key or signature algorithm",
                    summary=(
                        f"Certificate uses {cert.key_algorithm} ({cert.key_bits} bits) "
                        f"with {cert.sig_algorithm}."
                    ),
                    why=(
                        "Keys below 2048-bit RSA / 256-bit EC or SHA-1/MD5 signatures fail "
                        "modern baselines."
                    ),
                    remediation=(
                        "Re-issue the certificate with >= 2048-bit RSA or P-256 ECDSA and SHA-256."
                    ),
                    benign_explanations=(
                        "Older local devices or embedded firmware often ship with 1024-bit "
                        "factory keys.",
                    ),
                    blind_spots=(_BASE_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "key_algorithm": cert.key_algorithm,
                        "key_bits": cert.key_bits,
                        "sig_algorithm": cert.sig_algorithm,
                    },
                )
            )

    if not tls.trust_verified and tls.handshake_error_code is None:
        benign = (
            "Local LAN routers, NAS devices, and lab services commonly use self-signed "
            "or private-CA certificates."
            if allow_private
            else "An internal/private CA certificate may not be in this host's trust store."
        )
        findings.append(
            WebFinding(
                rule_id="TT-WEB-TLS-003",
                category="tls",
                severity="medium",
                confidence="high",
                title="TLS certificate trust or hostname verification failed",
                summary=f"Certificate for {host} was not trusted by the system store.",
                why=tls.trust_error or "Certificate chain or hostname could not be verified.",
                remediation="Serve a valid certificate matching the hostname from a trusted CA.",
                benign_explanations=(benign,),
                blind_spots=(
                    "Trust verification uses the local OS/Python CA bundle; custom enterprise "
                    "CAs not installed here will fail.",
                ),
                evidence={
                    "host": host,
                    "trust_error": tls.trust_error,
                    "hostname_matched": cert.hostname_matched if cert else None,
                    "is_self_signed": cert.is_self_signed if cert else None,
                },
            )
        )

    return findings

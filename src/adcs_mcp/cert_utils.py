"""X.509 certificate parsing helpers.

Wraps cryptography.x509 into small JSON-friendly dicts so tool responses stay
uniform whether the cert came from AD (userCertificate / cACertificate) or from
a CA database dump over WinRM.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID

# CRL entry revocation reason -> friendly label (RFC 5280 §5.3.1).
CRL_REASON_NAMES = {
    "unspecified": "Unspecified",
    "key_compromise": "Key Compromise",
    "ca_compromise": "CA Compromise",
    "affiliation_changed": "Affiliation Changed",
    "superseded": "Superseded",
    "cessation_of_operation": "Cessation of Operation",
    "certificate_hold": "Certificate Hold",
    "privilege_withdrawn": "Privilege Withdrawn",
    "aa_compromise": "AA Compromise",
    "remove_from_crl": "Remove from CRL",
}

# Common EKU OID -> friendly name.
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "TLS Server Authentication",
    "1.3.6.1.5.5.7.3.2": "TLS Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Email Protection",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.20.2.1": "Enrollment Agent",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival (CA Exchange)",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "1.3.6.1.4.1.311.64.1.1": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.10.3.9": "Cross CA",
}


def _load_cert(raw: bytes) -> x509.Certificate:
    if raw[:1] == b"-":
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def _load_crl(raw: bytes) -> x509.CertificateRevocationList:
    if raw.lstrip()[:1] == b"-":
        return x509.load_pem_x509_crl(raw)
    return x509.load_der_x509_crl(raw)


def _utc(cert_or_crl: Any, base: str) -> datetime | None:
    """Return a tz-aware UTC datetime for a ``*_utc`` property with a fallback.

    cryptography >= 42 exposes ``<base>_utc`` (already tz-aware). Older builds
    only expose ``<base>`` as a naive UTC datetime, so normalise it ourselves.
    """
    value = getattr(cert_or_crl, f"{base}_utc", None)
    if value is not None:
        return value
    value = getattr(cert_or_crl, base, None)
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _name_to_dict(name: x509.Name) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for attr in name:
        key = attr.oid._name if attr.oid._name else attr.oid.dotted_string
        out.setdefault(key, []).append(str(attr.value))
    return out


def _extension_dict(cert: x509.Certificate) -> dict[str, Any]:
    ext: dict[str, Any] = {}

    def _try(oid, decoder):
        try:
            e = cert.extensions.get_extension_for_oid(oid)
        except ExtensionNotFound:
            return None
        return {"critical": e.critical, **decoder(e.value)}

    def _basic(v: x509.BasicConstraints) -> dict[str, Any]:
        return {"ca": v.ca, "path_length": v.path_length}

    def _key_usage(v: x509.KeyUsage) -> dict[str, Any]:
        d = {
            "digital_signature": v.digital_signature,
            "content_commitment": v.content_commitment,
            "key_encipherment": v.key_encipherment,
            "data_encipherment": v.data_encipherment,
            "key_agreement": v.key_agreement,
            "key_cert_sign": v.key_cert_sign,
            "crl_sign": v.crl_sign,
        }
        if v.key_agreement:
            d["encipher_only"] = v.encipher_only
            d["decipher_only"] = v.decipher_only
        return d

    def _eku(v: x509.ExtendedKeyUsage) -> dict[str, Any]:
        oids = [oid.dotted_string for oid in v]
        return {"oids": oids, "names": [EKU_NAMES.get(o, o) for o in oids]}

    def _san(v: x509.SubjectAlternativeName) -> dict[str, Any]:
        return {
            "dns_names": v.get_values_for_type(x509.DNSName),
            "ip_addresses": [str(ip) for ip in v.get_values_for_type(x509.IPAddress)],
            "rfc822_names": v.get_values_for_type(x509.RFC822Name),
            "uri": v.get_values_for_type(x509.UniformResourceIdentifier),
            "other_names": [
                {"oid": o.type_id.dotted_string, "value": base64.b64encode(o.value).decode()}
                for o in v.get_values_for_type(x509.OtherName)
            ],
        }

    def _ski(v: x509.SubjectKeyIdentifier) -> dict[str, Any]:
        return {"hex": v.digest.hex()}

    def _aki(v: x509.AuthorityKeyIdentifier) -> dict[str, Any]:
        return {"hex": v.key_identifier.hex() if v.key_identifier else None}

    def _crl_dp(v: x509.CRLDistributionPoints) -> dict[str, Any]:
        return {
            "urls": [
                str(gn.value)
                for dp in v
                if dp.full_name
                for gn in dp.full_name
            ],
        }

    def _aia(v: x509.AuthorityInformationAccess) -> dict[str, Any]:
        return {
            "entries": [
                {"method": ad.access_method._name, "location": str(ad.access_location.value)}
                for ad in v
            ]
        }

    def _cert_policies(v: x509.CertificatePolicies) -> dict[str, Any]:
        return {"policy_oids": [p.policy_identifier.dotted_string for p in v]}

    for oid, decoder in [
        (ExtensionOID.BASIC_CONSTRAINTS, _basic),
        (ExtensionOID.KEY_USAGE, _key_usage),
        (ExtensionOID.EXTENDED_KEY_USAGE, _eku),
        (ExtensionOID.SUBJECT_ALTERNATIVE_NAME, _san),
        (ExtensionOID.SUBJECT_KEY_IDENTIFIER, _ski),
        (ExtensionOID.AUTHORITY_KEY_IDENTIFIER, _aki),
        (ExtensionOID.CRL_DISTRIBUTION_POINTS, _crl_dp),
        (ExtensionOID.AUTHORITY_INFORMATION_ACCESS, _aia),
        (ExtensionOID.CERTIFICATE_POLICIES, _cert_policies),
    ]:
        val = _try(oid, decoder)
        if val is not None:
            ext[oid._name if oid._name else oid.dotted_string] = val
    return ext


def parse_certificate(raw: bytes) -> dict[str, Any]:
    """Parse a DER- or PEM-encoded certificate into a JSON-friendly dict."""
    cert = _load_cert(raw)
    subject_cn = None
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        pass
    issuer_cn = None
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        pass
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_hex": format(cert.serial_number, "x"),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key_type": type(cert.public_key()).__name__,
        "public_key_size": getattr(cert.public_key(), "key_size", None),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "extensions": _extension_dict(cert),
        "pem": cert.public_bytes(Encoding.PEM).decode(),
    }


def _crl_number(crl: x509.CertificateRevocationList) -> int | None:
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except ExtensionNotFound:
        return None


def _crl_issuer_aki(crl: x509.CertificateRevocationList) -> str | None:
    try:
        aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except ExtensionNotFound:
        return None
    return aki.key_identifier.hex() if aki.key_identifier else None


def parse_crl(raw: bytes, sample_limit: int = 25) -> dict[str, Any]:
    """Parse a DER- or PEM-encoded CRL into a JSON-friendly health summary.

    Includes freshness fields (``this_update`` / ``next_update`` / ``is_expired``
    / ``seconds_until_next_update``) so callers can tell at a glance whether a
    published CRL is current, plus a capped sample of revoked entries.
    """
    crl = _load_crl(raw)
    now = datetime.now(timezone.utc)
    this_update = _utc(crl, "last_update")
    next_update = _utc(crl, "next_update")

    seconds_until_next = None
    is_expired = None
    if next_update is not None:
        seconds_until_next = (next_update - now).total_seconds()
        is_expired = seconds_until_next < 0

    issuer_cn = None
    try:
        issuer_cn = crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        pass

    revoked_count = len(crl)
    sample: list[dict[str, Any]] = []
    for entry in crl:
        if len(sample) >= max(0, sample_limit):
            break
        reason = None
        try:
            reason_ext = entry.extensions.get_extension_for_class(x509.CRLReason).value
            key = reason_ext.reason.name
            reason = CRL_REASON_NAMES.get(key, key)
        except ExtensionNotFound:
            pass
        revoked_at = _utc(entry, "revocation_date")
        sample.append(
            {
                "serial_hex": format(entry.serial_number, "x"),
                "revocation_date": revoked_at.isoformat() if revoked_at else None,
                "reason": reason,
            }
        )

    return {
        "type": "crl",
        "issuer_cn": issuer_cn,
        "issuer": _name_to_dict(crl.issuer),
        "crl_number": _crl_number(crl),
        "authority_key_identifier": _crl_issuer_aki(crl),
        "signature_algorithm": crl.signature_algorithm_oid._name,
        "this_update": this_update.isoformat() if this_update else None,
        "next_update": next_update.isoformat() if next_update else None,
        "is_expired": is_expired,
        "seconds_until_next_update": seconds_until_next,
        "revoked_count": revoked_count,
        "revoked_sample": sample,
        "revoked_sample_truncated": revoked_count > len(sample),
    }

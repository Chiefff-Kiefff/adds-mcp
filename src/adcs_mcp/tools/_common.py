"""Shared constants for ADCS tools."""

from __future__ import annotations

CA_ATTRS = [
    "cn",
    "distinguishedName",
    "displayName",
    "dNSHostName",
    "cACertificate",
    "cACertificateDN",
    "certificateTemplates",
    "flags",
    "cAConnect",
    "signatureAlgorithms",
    "whenCreated",
    "whenChanged",
]

TEMPLATE_ATTRS = [
    "cn",
    "distinguishedName",
    "displayName",
    "revision",
    "msPKI-Template-Schema-Version",
    "msPKI-Template-Minor-Revision",
    "msPKI-Cert-Template-OID",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag",
    "msPKI-RA-Signature",
    "msPKI-RA-Application-Policies",
    "msPKI-RA-Policies",
    "msPKI-Minimal-Key-Size",
    "pKIKeyUsage",
    "pKIExtendedKeyUsage",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "pKICriticalExtensions",
    "pKIDefaultCSPs",
    "pKIDefaultKeySpec",
    "pKIMaxIssuingDepth",
    "nTSecurityDescriptor",
    "flags",
    "whenCreated",
    "whenChanged",
]

TRUST_ANCHOR_ATTRS = [
    "cn",
    "distinguishedName",
    "cACertificate",
    "authorityRevocationList",
    "certificateRevocationList",
    "crossCertificatePair",
    "whenCreated",
    "whenChanged",
]

# msPKI-Certificate-Name-Flag bits.
NAME_FLAG_BITS = {
    0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
    0x00000008: "OLD_CERT_SUPPLIES_SUBJECT",
    0x00010000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    0x00400000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x00800000: "SUBJECT_ALT_REQUIRE_SPN",
    0x01000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    0x02000000: "SUBJECT_ALT_REQUIRE_UPN",
    0x04000000: "SUBJECT_ALT_REQUIRE_EMAIL",
    0x08000000: "SUBJECT_ALT_REQUIRE_DNS",
    0x10000000: "SUBJECT_REQUIRE_DNS_AS_CN",
    0x20000000: "SUBJECT_REQUIRE_EMAIL",
    0x40000000: "SUBJECT_REQUIRE_COMMON_NAME",
    0x80000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
}

# msPKI-Enrollment-Flag bits.
ENROLLMENT_FLAG_BITS = {
    0x00000001: "INCLUDE_SYMMETRIC_ALGORITHMS",
    0x00000002: "PEND_ALL_REQUESTS",
    0x00000004: "PUBLISH_TO_KRA_CONTAINER",
    0x00000008: "PUBLISH_TO_DS",
    0x00000010: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    0x00000020: "AUTO_ENROLLMENT",
    0x00000080: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    0x00000100: "USER_INTERACTION_REQUIRED",
    0x00000400: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    0x00000800: "ALLOW_ENROLL_ON_BEHALF_OF",
    0x00001000: "ADD_OCSP_NOCHECK",
    0x00002000: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    0x00004000: "NOREVOCATIONINFOINISSUEDCERTS",
    0x00008000: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    0x00020000: "ADD_TEMPLATE_NAME",
}

# msPKI-Private-Key-Flag bits (subset — most useful).
PRIVATE_KEY_FLAG_BITS = {
    0x00000001: "REQUIRE_PRIVATE_KEY_ARCHIVAL",
    0x00000010: "EXPORTABLE_KEY",
    0x00000020: "STRONG_KEY_PROTECTION_REQUIRED",
    0x00000040: "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM",
    0x00000080: "REQUIRE_SAME_KEY_RENEWAL",
    0x00000100: "USE_LEGACY_PROVIDER",
    0x00000200: "ATTEST_NONE",
    0x00000400: "ATTEST_REQUIRED",
    0x00000800: "ATTEST_PREFERRED",
    0x00001000: "ATTESTATION_WITHOUT_POLICY",
    0x00002000: "EK_TRUST_ON_USE",
    0x00004000: "EK_VALIDATE_CERT",
    0x00008000: "EK_VALIDATE_KEY",
    0x00080000: "HELLO_LOGON_KEY",
}


def decode_bit_flags(value: object, table: dict[int, str]) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    return {"raw": raw, "flags": [name for bit, name in table.items() if raw & bit]}

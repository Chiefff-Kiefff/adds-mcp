# ms-ad-mcp

**Read-only** MCP servers for the Microsoft Active Directory family, sharing
one LDAPS bind and one repository. Designed for monitoring and investigation.

| Server        | Purpose                                                                | Data sources                                      | Default port |
|---------------|------------------------------------------------------------------------|---------------------------------------------------|--------------|
| `adds-mcp`    | AD DS — users, groups, OUs, computers, GPOs, domain metadata           | LDAPS to any DC                                   | 8080         |
| `adcs-mcp`    | AD CS — CAs, templates, trust anchors, issued/pending/revoked certs    | LDAPS (AD PKI subtree) + WinRM to online issuing CAs | 8081       |
| `addns-mcp`   | AD-integrated DNS — zones, records, delegations, stale entries         | LDAPS (`DomainDnsZones` + `ForestDnsZones`)       | 8082         |

Every tool is read-only:

- `adds-mcp` opens LDAP with `read_only=True`; no tool accepts writes.
- `adcs-mcp` runs only `Get-*` PowerShell and read-only registry reads on CA hosts.
- `addns-mcp` reads DNS partitions via the same read-only LDAP client.

---

## `adds-mcp` — Active Directory Domain Services (35 tools)

| Domain               | Tools                                                                                                                                    |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Users                | `search_users`, `get_user`, `list_user_groups`, `list_locked_out_users`, `list_disabled_users`, `list_stale_users`, `list_recently_changed_users`, `list_password_never_expires` |
| Groups               | `search_groups`, `get_group`, `list_group_members` (direct or recursive), `list_empty_groups`, `list_privileged_groups`                  |
| OUs                  | `list_ous`, `get_ou`, `list_ou_children`, `get_ou_tree`                                                                                  |
| Computers            | `search_computers`, `get_computer`, `list_domain_controllers`, `list_stale_computers`, `summarize_computer_os`                           |
| Group Policy         | `list_gpos`, `get_gpo`, `find_gpo_links`, `list_links_on_ou`                                                                             |
| Domain / directory   | `get_domain_info`, `get_password_policy`, `list_fine_grained_password_policies`, `list_fsmo_roles`, `list_trusts`, `list_sites`          |
| Escape hatch         | `ldap_search` (raw filter), `get_object_by_dn`, `count_objects`                                                                          |

Decodes SIDs, GUIDs, FILETIMEs, `userAccountControl`, `groupType`, tick-interval
durations, and `gPLink`.

---

## `adcs-mcp` — Active Directory Certificate Services (24 tools)

**AD-side** (LDAPS to `CN=Public Key Services,CN=Configuration,...`):
`list_enrollment_services`, `get_enrollment_service`, `list_root_cas`,
`list_ntauth_cas`, `list_certificate_templates`, `get_certificate_template`,
`list_templates_by_eku`, `find_templates_offered_by_ca`, `list_aia_entries`,
`list_cdp_entries`, `list_kra_certificates`, `list_pki_oids`.

**WinRM-side** (PowerShell + PSPKI on each host in `ADCS_CA_HOSTS`):
`list_issued_certificates`, `list_pending_requests`, `list_failed_requests`,
`list_revoked_certificates`, `get_certificate_by_serial`,
`count_certificates_by_disposition`, `get_ca_configuration`,
`list_ca_role_holders`, `list_officer_rights`, `get_ca_certificate_chain`,
`list_ca_backup_settings`.

**Standalone**: `parse_certificate_pem` — decode any PEM or base64 DER cert
into subject/issuer/EKU/SAN/key-usage/fingerprints (no directory access
needed).

3-tier PKI: offline Root/Policy CAs aren't queried live. Use
`parse_certificate_pem` on exported certs/CRLs, then cross-check with
`list_ntauth_cas` / `list_aia_entries` / `list_root_cas` to confirm the domain
still trusts them.

---

## `addns-mcp` — AD-integrated DNS (10 tools)

| Tool                            | Description                                                              |
|---------------------------------|--------------------------------------------------------------------------|
| `list_zones`                    | Forward + reverse zones across `DomainDnsZones`/`ForestDnsZones`/legacy |
| `get_zone`                      | Zone metadata + apex SOA/NS records                                     |
| `list_records`                  | All records in a zone, optionally filtered by type or label prefix       |
| `get_record`                    | Every RR at a single node (all types)                                   |
| `list_stale_records`            | Dynamic records with aging timestamps older than N days                 |
| `list_conditional_forwarders`   | Zones configured as conditional forwarders                              |
| `list_zone_delegations`         | NS-delegated child zones under a parent                                 |
| `search_by_name`                | Cross-zone label substring search                                       |
| `search_by_ip`                  | Forward (A/AAAA) + reverse (PTR) lookups for any IPv4/IPv6 address      |

Decodes the binary `dnsRecord` blob format for A, AAAA, CNAME, NS, PTR, MX,
SRV, TXT, SOA, plus record aging timestamps.

---

## Cross-server flows an agent can compose

- Ask `adds-mcp.get_user` for a computer's owner → pass their SAM to
  `adcs-mcp.list_issued_certificates --requester` to see what certs they hold.
- Ask `adcs-mcp.get_ca_configuration` for the CDP URI → resolve the hostname
  with `addns-mcp.search_by_name` to confirm what IP the CRL DP resolves to
  inside the domain.
- Ask `adds-mcp.list_stale_computers` for machines quiet for 90d → for each,
  `addns-mcp.search_by_name` to see whether stale DNS records still exist.

---

## Configuration

All three servers share `ADDS_*` (LDAPS bind). `adcs-mcp` additionally needs
`ADCS_*` (WinRM). Copy `.env.example` → `.env` and fill in real values.

## Installation

```bash
pip install -e .            # adds-mcp + addns-mcp (LDAP only)
pip install -e ".[adcs]"    # adds all three, including WinRM support
```

## Running

```bash
adds-mcp    # HTTP :8080 /mcp
adcs-mcp    # HTTP :8081 /mcp
addns-mcp   # HTTP :8082 /mcp
```

Docker (three separate images sharing the source tree):

```bash
docker build -t adds-mcp  -f Dockerfile        .
docker build -t adcs-mcp  -f Dockerfile.adcs   .
docker build -t addns-mcp -f Dockerfile.addns  .

docker run --rm -p 8080:8080 --env-file .env adds-mcp
docker run --rm -p 8081:8081 --env-file .env adcs-mcp
docker run --rm -p 8082:8082 --env-file .env addns-mcp
```

## Repository layout

```
src/
  adds_mcp/          # AD DS
    __init__.py  config.py  client.py  formatting.py  server.py
    tools/           # users, groups, ous, computers, gpos, domain, search

  adcs_mcp/          # AD CS (reuses adds_mcp.client for LDAPS)
    __init__.py  config.py  ldap_source.py  winrm_source.py
    cert_utils.py  server.py
    tools/           # cas, templates, trust, issued, admin, parsing

  addns_mcp/         # AD-integrated DNS (reuses adds_mcp.client for LDAPS)
    __init__.py  config.py  ldap_source.py  records.py  server.py
    tools/           # zones, records, search
```

## Security notes

- Use dedicated least-privilege service accounts.
  - `adds-mcp` / `addns-mcp` / `adcs-mcp` (AD-side): any authenticated domain
    user has enough rights for most tools.
  - `adcs-mcp` (WinRM-side): grant only the Auditor role on each issuing CA;
    that's enough for read tools.
- LDAPS is required by default; TLS validation and CA bundle configurable via
  `ADDS_TLS_VALIDATE` and `ADDS_CA_CERT_FILE`.
- All LDAP filter input is escaped with an RFC 4515-compliant helper.
- WinRM prefers Kerberos (`ADCS_WINRM_AUTH=kerberos`) with a keytab in
  production.

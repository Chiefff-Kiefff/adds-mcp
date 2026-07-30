# hg-directory-mcp

A pair of **read-only** MCP servers for monitoring and investigation of a
Microsoft directory + PKI environment:

| Server        | Purpose                                             | Data sources                    | Default port |
|---------------|-----------------------------------------------------|---------------------------------|--------------|
| `adds-mcp`    | Active Directory Domain Services (users, groups, OUs, computers, GPOs, domain metadata) | LDAPS to any DC                 | 8080         |
| `adcs-mcp`    | Active Directory Certificate Services (CAs, templates, trust anchors, issued certs)     | LDAPS (AD PKI subtree) + WinRM to each online issuing CA | 8081         |

Both servers refuse to mutate anything: `adds-mcp` opens LDAP with
`read_only=True` and neither exposes any tool that accepts a write. `adcs-mcp`
runs only `Get-*` and read-only registry reads on the CA hosts.

---

## `adds-mcp` — Active Directory

35 read-only tools grouped by object type:

| Domain               | Tools                                                                                                                                    |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Users                | `search_users`, `get_user`, `list_user_groups`, `list_locked_out_users`, `list_disabled_users`, `list_stale_users`, `list_recently_changed_users`, `list_password_never_expires` |
| Groups               | `search_groups`, `get_group`, `list_group_members` (direct or recursive), `list_empty_groups`, `list_privileged_groups`                  |
| OUs                  | `list_ous`, `get_ou`, `list_ou_children`, `get_ou_tree` (nested hierarchy)                                                               |
| Computers            | `search_computers`, `get_computer`, `list_domain_controllers`, `list_stale_computers`, `summarize_computer_os`                           |
| Group Policy Objects | `list_gpos`, `get_gpo`, `find_gpo_links`, `list_links_on_ou`                                                                             |
| Domain / directory   | `get_domain_info`, `get_password_policy`, `list_fine_grained_password_policies`, `list_fsmo_roles`, `list_trusts`, `list_sites`          |
| Escape hatch         | `ldap_search` (raw filter), `get_object_by_dn`, `count_objects`                                                                          |

Every attribute is decoded before it leaves the tool: SIDs, GUIDs, FILETIMEs,
`userAccountControl`, `groupType`, tick-interval durations, and `gPLink`.

---

## `adcs-mcp` — Active Directory Certificate Services

Tools are split by data source. AD-side tools work as soon as you have LDAPS
to any DC and the `ADDS_*` vars set. WinRM-side tools additionally require the
`ADCS_*` vars and WinRM listeners on each issuing CA.

### AD-side (LDAPS to `CN=Public Key Services,CN=Configuration,DC=...`)

| Tool                            | Description                                                          |
|---------------------------------|----------------------------------------------------------------------|
| `list_enrollment_services`      | Every Enterprise CA published in the domain                          |
| `get_enrollment_service`        | Detailed attributes for a single Enterprise CA                       |
| `list_root_cas`                 | Root CA certificates published as trust anchors                      |
| `list_ntauth_cas`               | Contents of `CN=NTAuthCertificates` (CAs trusted for AD auth)        |
| `list_certificate_templates`    | All templates, with flag decoding                                    |
| `get_certificate_template`      | One template by displayName / cn / OID / DN                          |
| `list_templates_by_eku`         | Templates that include a given EKU OID                               |
| `find_templates_offered_by_ca`  | Templates a specific Enterprise CA is configured to issue            |
| `list_aia_entries`              | Authority Information Access entries in AD                           |
| `list_cdp_entries`              | CRL Distribution Points and published CRLs in AD                     |
| `list_kra_certificates`         | Key Recovery Agent certificates in AD                                |
| `list_pki_oids`                 | Custom OIDs registered under `CN=OID`                                |

### WinRM-side (PowerShell / PSPKI on each online issuing CA)

| Tool                              | Description                                                        |
|-----------------------------------|--------------------------------------------------------------------|
| `list_issued_certificates`        | Certificate DB rows with disposition = issued                      |
| `list_pending_requests`           | Requests awaiting officer approval                                 |
| `list_failed_requests`            | Failed / denied requests                                           |
| `list_revoked_certificates`       | Revoked entries                                                    |
| `get_certificate_by_serial`       | Full row + raw cert for a single serial                            |
| `count_certificates_by_disposition` | Grouped counts across the CA DB                                  |
| `get_ca_configuration`            | CRL/AIA/CDP settings, allowed templates, publication URIs          |
| `list_ca_role_holders`            | CA ACL decoded (CA Admins, Certificate Managers, Auditors, …)      |
| `list_officer_rights`             | Per-template certificate manager rights                            |
| `get_ca_certificate_chain`        | The CA's own certificate chain (PEM)                               |
| `list_ca_backup_settings`         | Registry-level CA config from `HKLM\...\CertSvc\Configuration`     |

### Standalone

| Tool                    | Description                                                              |
|-------------------------|--------------------------------------------------------------------------|
| `parse_certificate_pem` | Decode any PEM or base64 DER cert into JSON (SAN, EKU, key usage, chain) |

### 3-tier PKI notes

- **Tier 0 (offline Root)** and **Tier 1 (offline Policy)** aren't queried
  directly — there's no live endpoint. Use `parse_certificate_pem` to inspect
  any offline root/intermediate cert or CRL you export from them, and
  cross-reference them with `list_ntauth_cas` / `list_aia_entries` /
  `list_root_cas` to verify the domain still trusts them.
- **Tier 2 (online Issuing CAs)** are the target of the WinRM-backed tools.
  Provide their hostnames in `ADCS_CA_HOSTS` and grant the WinRM service
  account read rights to the CA (typically membership in the CA's built-in
  Auditor role on each issuing CA).

---

## Requirements

- Python 3.11+
- LDAPS reachable from wherever the servers run
- For `adcs-mcp`: WinRM 5986 (HTTPS) reachable to each entry in
  `ADCS_CA_HOSTS`, plus a WinRM service account with read rights on the CA

## Configuration

Configuration is loaded from environment variables (`.env` supported). See
`.env.example` for the full list.

`ADDS_*` variables are read by **both** servers (they share the LDAPS bind).
`ADCS_*` variables are read only by `adcs-mcp`.

## Running

Install the package (add `[adcs]` extra for WinRM support):

```bash
pip install -e .            # adds-mcp only
pip install -e ".[adcs]"    # adds-mcp + adcs-mcp
```

Run either server:

```bash
adds-mcp    # HTTP :8080, endpoint /mcp
adcs-mcp    # HTTP :8081, endpoint /mcp
```

Docker (two separate images):

```bash
docker build -t adds-mcp -f Dockerfile      .
docker build -t adcs-mcp -f Dockerfile.adcs .

docker run --rm -p 8080:8080 --env-file .env adds-mcp
docker run --rm -p 8081:8081 --env-file .env adcs-mcp
```

## Repository layout

```
src/
  adds_mcp/          # AD DS server
    __init__.py
    config.py
    client.py        # ldap3 wrapper, read_only=True, filter/DN escaping
    formatting.py    # SID/GUID/FILETIME/UAC/groupType decoders
    server.py
    tools/           # users, groups, ous, computers, gpos, domain, search

  adcs_mcp/          # ADCS server (reuses adds_mcp.client for LDAPS)
    __init__.py
    config.py
    ldap_source.py   # Points reused ldap client at CN=Public Key Services
    winrm_source.py  # pypsrp WinRM PowerShell runner (optional)
    cert_utils.py    # X.509 parsing (cryptography)
    server.py
    tools/           # cas, templates, trust, issued, admin, parsing
```

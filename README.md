# adds-mcp

A **read-only** Model Context Protocol server for Active Directory. Designed for
monitoring and investigation workflows: it exposes users, groups, OUs, computers,
GPOs, and domain metadata as MCP tools an LLM agent can query safely.

The server binds to LDAPS with a dedicated least-privilege service account, uses
only `SEARCH` operations, and refuses to expose any mutating LDAP verbs.

## What it can query

| Domain               | Tools                                                                                                                                    |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Users                | `search_users`, `get_user`, `list_user_groups`, `list_locked_out_users`, `list_disabled_users`, `list_stale_users`, `list_recently_changed_users`, `list_password_never_expires` |
| Groups               | `search_groups`, `get_group`, `list_group_members` (direct or recursive), `list_empty_groups`, `list_privileged_groups`                  |
| OUs                  | `list_ous`, `get_ou`, `list_ou_children`, `get_ou_tree` (nested hierarchy)                                                               |
| Computers            | `search_computers`, `get_computer`, `list_domain_controllers`, `list_stale_computers`, `summarize_computer_os`                           |
| Group Policy Objects | `list_gpos`, `get_gpo`, `find_gpo_links`, `list_links_on_ou`                                                                             |
| Domain / directory   | `get_domain_info`, `get_password_policy`, `list_fine_grained_password_policies`, `list_fsmo_roles`, `list_trusts`, `list_sites`          |
| Escape hatch         | `ldap_search` (raw filter), `get_object_by_dn`, `count_objects`                                                                          |

Every attribute is decoded before it leaves the tool:

- `objectSid` → `S-1-5-21-...` strings
- `objectGUID` → canonical GUID strings
- `lastLogonTimestamp`, `pwdLastSet`, `accountExpires` → ISO-8601 UTC
- `userAccountControl` → decoded flag list + booleans (`disabled`, `locked_out`, …)
- `groupType` → `{scope: GLOBAL|DOMAIN_LOCAL|UNIVERSAL, security: bool, ...}`
- `lockoutDuration` / `maxPwdAge` → ISO-8601 durations
- `gPLink` → parsed list of GPO links with enforced/disabled flags

## Requirements

- Python 3.11+
- Network access to a domain controller on port 636 (LDAPS) or 3269 (GC LDAPS)
- A read-only bind account. Any authenticated domain user has enough rights for
  the majority of queries; some (e.g. `msDS-PasswordSettings` for PSOs) need
  additional read rights.

## Configuration

Configuration is loaded from environment variables (or a `.env` file in the CWD).

| Variable                     | Required | Description                                                       |
|------------------------------|----------|-------------------------------------------------------------------|
| `ADDS_SERVERS`               | yes      | Comma-separated DC hostnames                                      |
| `ADDS_PORT`                  | no       | LDAPS port (default `636`)                                        |
| `ADDS_BIND_DN`               | yes      | Full DN of the read-only service account                          |
| `ADDS_BIND_PASSWORD`         | yes      | Password for the service account                                  |
| `ADDS_BASE_DN`               | yes      | Default search base (e.g. `DC=corp,DC=example,DC=com`)            |
| `ADDS_DOMAIN`                | no       | DNS/NetBIOS domain name for display                               |
| `ADDS_TLS_VALIDATE`          | no       | `true` (default) / `false` — validate DC cert                     |
| `ADDS_CA_CERT_FILE`          | no       | Path to a CA bundle for TLS validation                            |
| `ADDS_HTTP_HOST`             | no       | HTTP bind host (default `0.0.0.0`)                                |
| `ADDS_HTTP_PORT`             | no       | HTTP bind port (default `8080`)                                   |
| `ADDS_MAX_PAGE_SIZE`         | no       | Hard cap on rows per tool call (default `500`)                    |
| `ADDS_DEFAULT_PAGE_SIZE`     | no       | Default page size for LDAP paged searches (default `50`)          |
| `ADDS_QUERY_TIMEOUT_SECONDS` | no       | Per-query timeout (default `30`)                                  |
| `ADDS_TRANSPORT`             | no       | `streamable-http` (default) or `stdio`                            |
| `ADDS_LOG_LEVEL`             | no       | Python logging level (default `INFO`)                             |

Copy `.env.example` to `.env` and fill in real values.

## Running

Local dev (streamable HTTP on `:8080`):

```bash
pip install -e .
adds-mcp
```

Docker:

```bash
docker build -t adds-mcp .
docker run --rm -p 8080:8080 --env-file .env adds-mcp
```

The server exposes the MCP streamable-HTTP endpoint at `/mcp`.

## Security notes

- The server never issues LDAP `add`, `modify`, `delete`, or `modifyDN` operations.
  `read_only=True` is set on the ldap3 `Connection`, and none of the tools accept
  write parameters.
- Use a dedicated service account. Do not reuse a domain-admin credential.
- LDAPS is required by default; set `ADDS_TLS_VALIDATE=false` only for lab work.
- All LDAP filter inputs from tools are escaped with an RFC 4515-compliant helper
  before hitting the server.
- Result sets are capped by `ADDS_MAX_PAGE_SIZE` to keep responses bounded.

## Repository layout

```
src/adds_mcp/
  __init__.py
  config.py         # Pydantic settings from env
  client.py         # ldap3 wrapper: pooled LDAPS, paged searches, filter/DN escaping
  formatting.py     # SID / GUID / FILETIME / UAC / groupType decoders
  server.py         # FastMCP entrypoint (streamable-http by default)
  tools/
    _common.py      # Shared attribute sets
    users.py
    groups.py
    ous.py
    computers.py
    gpos.py
    domain.py
    search.py       # Raw ldap_search + get_object_by_dn + count_objects
```

# Policy reference

A network definition is one YAML (or JSON) document with five sections.

| Section | Purpose |
|---|---|
| `network` | `name`, `overlay_cidr` (private or CGNAT), `listen_port`, `default_action` (must be `deny`) |
| `groups` | Named groups. `sensitive: true` forces explicit ports and a posture check on any policy that targets the group |
| `posture_checks` | Device requirements evaluated against the **source** peer: `min_client_version`, `allowed_os`, `require_disk_encryption` |
| `peers` | Overlay members: `name`, `address`, `groups`, `os`, `client_version`, `disk_encrypted`, optional `public_key`, `endpoint`, `routing_peer`, `routes` |
| `policies` | Allow rules: `sources`, `destinations`, `protocol` (`tcp`/`udp`/`icmp`/`all`), `ports`, `bidirectional`, `posture_checks`, `expires`, `enabled` |

`All` is a reserved built-in group meaning every peer. Anything not matched by an enabled,
unexpired policy whose posture checks pass is denied.

## Validation codes

| Code | Severity | Rule |
|---|---|---|
| ZT001 | error | `default_action` is not `deny` |
| ZT002 | error | Overlay CIDR invalid or publicly routable |
| ZT003 | error | Peer address invalid, outside overlay, duplicated, or the network/broadcast address |
| ZT004 | error / warning | Unknown or reserved group; empty group; peer with no group |
| ZT005 | error | Policy references unknown groups, has no sources/destinations, or is `All -> All` |
| ZT006 | error / warning | Invalid protocol or ports; all-ports access (error when the target is sensitive) |
| ZT007 | error | Sensitive destination without a posture check |
| ZT008 | error | Unknown posture check |
| ZT009 | error | A `private_key` field is present (the value is never printed) |
| ZT010 | error | `public_key` is neither a placeholder nor a base64 32-byte key |
| ZT011 | error | Policy expired or `expires` is not `YYYY-MM-DD` |
| ZT012 | error | Admin/data ports (SSH, RDP, etcd, Kubernetes API, databases) exposed to `All` |
| ZT013 | error | Duplicate policy name |
| ZT014 | warning | Bidirectional access into a sensitive group |
| ZT015 | error | Routes on a non-routing peer, default route, invalid route, or route overlapping the overlay |
| ZT016 | warning | Disabled policy or a populated group that no policy uses |
| ZT017 | error | `listen_port` outside 1024-65535 |
| ZT018 | error | `endpoint` is not `host:port` |

Exit codes: `validate` returns 0 (clean), 1 (errors), 2 (warnings with `--strict`).
`decide` returns 0 when allowed and 3 when denied.

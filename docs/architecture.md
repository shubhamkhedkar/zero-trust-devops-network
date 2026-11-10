# Architecture

## Layers

1. **Identity and transport (WireGuard).** Every peer has a key pair generated on the host.
   A peer only accepts packets from public keys listed in its `[Peer]` sections, and
   `AllowedIPs` pins each key to one overlay address (plus routed subnets for routing peers).
   ztnet lists a peer only when some policy lets traffic flow in either direction, so
   unrelated peers cannot even complete a handshake.
2. **Authorisation (nftables).** WireGuard has no notion of ports. The generated
   `table inet ztnet` on each host accepts only the source address, protocol and ports a
   policy grants, then drops everything else arriving on `wg0`.
3. **Device posture.** Policies can require a minimum client version, an OS allow-list and
   disk encryption on the source device. A failing device loses access without any policy edit.
4. **Control plane (NetBird, optional).** `netbird-policies.json` mirrors the policy objects of
   NetBird's management API (groups, rules, posture checks), so the same definition can be
   reviewed in Git and then applied through NetBird by an operator. ztnet never calls that API.

## Request flow for `ztnet decide`

```mermaid
sequenceDiagram
    participant C as Caller (CLI / CI job / API)
    participant E as Decision engine
    participant P as Policy file (Git)
    C->>E: src, dst, protocol, port
    E->>P: load peers, groups, policies
    loop each enabled, unexpired policy
        E->>E: group match (incl. bidirectional)
        E->>E: protocol and port match
        E->>E: source posture checks
    end
    alt a policy matches and posture passes
        E-->>C: allowed + policy name
    else policy matched but posture failed
        E-->>C: denied + posture failures
    else
        E-->>C: denied (default deny)
    end
```

## Example topology

`ztnet render` writes `topology.mmd`; the example network renders to roughly:

```mermaid
flowchart LR
    eng[platform-engineers] -->|tcp 22| bastion
    eng -->|tcp 443,6443| k8sdev[k8s-dev]
    eng -->|tcp 443| vpc[vpc-gateways] --> subnet[(10.20.0.0/16)]
    bastion -->|tcp 6443| k8sprod[k8s-prod]
    bastion -->|tcp 5432| db[(databases-prod)]
    ci[ci-runners] -->|tcp 443,5000| reg[artifact-registry]
    ci -->|tcp 6443| k8sdev
    ci -->|tcp 6443 + posture| k8sprod
    k8sprod -->|tcp 5432| db
    obs[observability] -->|tcp 9100,9187,10250| k8sprod
    obs --> db
```

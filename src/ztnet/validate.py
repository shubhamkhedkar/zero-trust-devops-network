"""Static zero-trust checks for a network definition.

Every check returns findings instead of raising, so a single run reports
everything that needs fixing. Secret values are never echoed.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import ipaddress
import re
from dataclasses import asdict, dataclass

from .model import PROTOCOLS, Network, Policy, port_range

ALL_GROUP = "All"
CGNAT = ipaddress.ip_network("100.64.0.0/10")
ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    2379: "etcd",
    6443: "Kubernetes API",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
}
PLACEHOLDER = re.compile(r"^<[^<>]+>$|^\$\{[A-Z0-9_]+\}$")
ENDPOINT = re.compile(r"^[A-Za-z0-9.\-\[\]:]+:\d{1,5}$")


@dataclass(frozen=True)
class Finding:
    severity: str  # "error" | "warning"
    code: str
    subject: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "findings": [f.as_dict() for f in self.findings],
        }


def _is_valid_public_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def policy_expired(policy: Policy, today: dt.date) -> bool:
    if not policy.expires:
        return False
    return dt.date.fromisoformat(policy.expires) < today


def _group_exists(net: Network, name: str) -> bool:
    return name == ALL_GROUP or name in net.groups


def validate(net: Network, today: dt.date | None = None) -> Report:
    today = today or dt.date.today()
    out: list[Finding] = []

    def err(code: str, subject: str, msg: str) -> None:
        out.append(Finding("error", code, subject, msg))

    def warn(code: str, subject: str, msg: str) -> None:
        out.append(Finding("warning", code, subject, msg))

    # --- network ---------------------------------------------------------
    if net.default_action != "deny":
        err("ZT001", net.name, "default_action must be 'deny'; zero trust never allows by default")
    overlay = None
    try:
        overlay = net.overlay
        if not (overlay.is_private or (overlay.version == 4 and overlay.subnet_of(CGNAT))):
            err("ZT002", net.overlay_cidr, "overlay CIDR must be private (RFC 1918/ULA) or CGNAT")
    except ValueError as exc:
        err("ZT002", net.overlay_cidr, f"invalid overlay CIDR: {exc}")
    if not 1024 <= net.listen_port <= 65535:
        err("ZT017", net.name, "listen_port must be between 1024 and 65535")

    # --- groups / posture --------------------------------------------------
    if ALL_GROUP in net.groups:
        err("ZT004", ALL_GROUP, f"'{ALL_GROUP}' is a reserved built-in group and cannot be defined")
    for name in net.groups:
        if not net.members(name):
            warn("ZT004", name, "group has no peers")

    # --- peers -------------------------------------------------------------
    seen_addr: dict[str, str] = {}
    for name in net.private_key_peers:
        err("ZT009", name, "peer definition contains a private_key; keys must stay on the host")
    for peer in net.peers.values():
        try:
            addr = ipaddress.ip_address(peer.address)
        except ValueError:
            err("ZT003", peer.name, f"invalid address {peer.address!r}")
            continue
        if overlay is not None:
            if addr not in overlay:
                err("ZT003", peer.name, f"address {addr} is outside overlay {overlay}")
            elif overlay.num_addresses > 2 and addr in (
                overlay.network_address,
                overlay.broadcast_address,
            ):
                err("ZT003", peer.name, f"address {addr} is the network/broadcast address")
        if str(addr) in seen_addr:
            err("ZT003", peer.name, f"address {addr} already used by {seen_addr[str(addr)]}")
        seen_addr[str(addr)] = peer.name
        if not peer.groups:
            warn("ZT004", peer.name, "peer belongs to no group and can never be reached")
        for g in peer.groups:
            if g not in net.groups:
                err("ZT004", peer.name, f"unknown group {g!r}")
        if peer.public_key and not PLACEHOLDER.match(peer.public_key):
            if not _is_valid_public_key(peer.public_key):
                err("ZT010", peer.name, "public_key is not a base64 32-byte WireGuard key")
        if peer.endpoint and not ENDPOINT.match(peer.endpoint):
            err("ZT018", peer.name, f"endpoint {peer.endpoint!r} must be host:port")
        if peer.routes and not peer.routing_peer:
            err("ZT015", peer.name, "routes are only allowed on routing_peer: true")
        for route in peer.routes:
            try:
                rnet = ipaddress.ip_network(route, strict=True)
            except ValueError:
                err("ZT015", peer.name, f"invalid route {route!r}")
                continue
            if rnet.prefixlen == 0:
                err("ZT015", peer.name, "default route 0.0.0.0/0 is not allowed via a routing peer")
            if overlay is not None and rnet.version == overlay.version and rnet.overlaps(overlay):
                err("ZT015", peer.name, f"route {rnet} overlaps the overlay network")

    # --- policies ----------------------------------------------------------
    names: set[str] = set()
    referenced: set[str] = set()
    for pol in net.policies:
        if pol.name in names:
            err("ZT013", pol.name, "duplicate policy name")
        names.add(pol.name)
        for g in (*pol.sources, *pol.destinations):
            referenced.add(g)
            if not _group_exists(net, g):
                err("ZT005", pol.name, f"unknown group {g!r}")
        if not pol.sources or not pol.destinations:
            err("ZT005", pol.name, "policy needs at least one source and one destination group")
        broad_src = ALL_GROUP in pol.sources
        broad_dst = ALL_GROUP in pol.destinations
        if broad_src and broad_dst:
            err("ZT005", pol.name, "All -> All is an implicit allow-any; scope the groups")
        if pol.protocol not in PROTOCOLS:
            err("ZT006", pol.name, f"protocol must be one of {', '.join(PROTOCOLS)}")
            continue
        if pol.protocol == "all" and (broad_src or broad_dst):
            err("ZT006", pol.name, "protocol 'all' may not be combined with the All group")
        if pol.protocol in ("icmp", "all") and pol.ports:
            err("ZT006", pol.name, f"ports are not valid with protocol {pol.protocol}")
        ranges: list[tuple[int, int]] = []
        for spec in pol.ports:
            try:
                ranges.append(port_range(spec))
            except ValueError:
                err("ZT006", pol.name, f"invalid port spec {spec!r}")
        sensitive_dst = [g for g in pol.destinations if g in net.groups and net.groups[g].sensitive]
        if pol.protocol in ("tcp", "udp") and not pol.ports:
            if sensitive_dst:
                err("ZT006", pol.name, "all-ports access to a sensitive group; list explicit ports")
            else:
                warn("ZT006", pol.name, "no ports listed, every port is reachable")
        if sensitive_dst and not pol.posture_checks:
            err("ZT007", pol.name, f"access to sensitive {sensitive_dst} requires a posture check")
        if sensitive_dst and pol.bidirectional:
            warn("ZT014", pol.name, "bidirectional access into a sensitive group widens exposure")
        for check in pol.posture_checks:
            if check not in net.posture_checks:
                err("ZT008", pol.name, f"unknown posture check {check!r}")
        if broad_src:
            for low, high in ranges:
                for port, label in ADMIN_PORTS.items():
                    if low <= port <= high:
                        err("ZT012", pol.name, f"{label} ({port}) is exposed to the All group")
        if pol.expires:
            try:
                if policy_expired(pol, today):
                    err("ZT011", pol.name, f"policy expired on {pol.expires}; remove it")
            except ValueError:
                err("ZT011", pol.name, f"expires must be YYYY-MM-DD, got {pol.expires!r}")
        if not pol.enabled:
            warn("ZT016", pol.name, "policy is disabled; delete it if no longer needed")

    for name in net.groups:
        if name not in referenced and net.members(name):
            warn("ZT016", name, "group is not referenced by any policy")

    return Report(tuple(out))

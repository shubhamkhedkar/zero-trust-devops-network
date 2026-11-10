"""Default-deny access decision engine."""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field

from .model import Network, Peer, Policy, PostureCheck, port_range
from .validate import ALL_GROUP, policy_expired


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy: str | None = None
    posture_failures: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["posture_failures"] = list(self.posture_failures)
        return data


def _version(text: str | None) -> tuple[int, ...]:
    if not text:
        return ()
    parts = []
    for chunk in str(text).lstrip("v").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


def posture_failures(peer: Peer, check: PostureCheck) -> list[str]:
    failures = []
    if check.min_client_version and _version(peer.client_version) < _version(
        check.min_client_version
    ):
        failures.append(
            f"{check.name}: client {peer.client_version or 'unknown'} < {check.min_client_version}"
        )
    if check.allowed_os and peer.os not in check.allowed_os:
        failures.append(f"{check.name}: os {peer.os} not in {list(check.allowed_os)}")
    if check.require_disk_encryption and not peer.disk_encrypted:
        failures.append(f"{check.name}: disk encryption required")
    return failures


def _in(peer: Peer, groups: tuple[str, ...]) -> bool:
    return ALL_GROUP in groups or any(g in groups for g in peer.groups)


def _port_ok(policy: Policy, protocol: str, port: int | None) -> bool:
    if policy.protocol != "all" and policy.protocol != protocol:
        return False
    if protocol == "icmp" or not policy.ports:
        return True
    if port is None:
        return False
    return any(lo <= port <= hi for lo, hi in (port_range(p) for p in policy.ports))


def matches(policy: Policy, src: Peer, dst: Peer) -> bool:
    forward = _in(src, policy.sources) and _in(dst, policy.destinations)
    reverse = policy.bidirectional and _in(src, policy.destinations) and _in(dst, policy.sources)
    return forward or reverse


def decide(
    net: Network,
    src: str,
    dst: str,
    protocol: str = "tcp",
    port: int | None = None,
    today: dt.date | None = None,
) -> Decision:
    today = today or dt.date.today()
    protocol = protocol.lower()
    if src not in net.peers:
        return Decision(False, f"unknown source peer {src!r}")
    if dst not in net.peers:
        return Decision(False, f"unknown destination peer {dst!r}")
    if src == dst:
        return Decision(False, "source and destination are the same peer")
    s, d = net.peers[src], net.peers[dst]
    blocked: list[str] = []
    for pol in net.policies:
        if not pol.enabled or not matches(pol, s, d) or not _port_ok(pol, protocol, port):
            continue
        try:
            if policy_expired(pol, today):
                continue
        except ValueError:
            continue
        failures = [
            f
            for name in pol.posture_checks
            if name in net.posture_checks
            for f in posture_failures(s, net.posture_checks[name])
        ]
        missing = [n for n in pol.posture_checks if n not in net.posture_checks]
        failures += [f"{n}: posture check not defined" for n in missing]
        if failures:
            blocked.extend(failures)
            continue
        return Decision(True, f"allowed by policy {pol.name!r}", pol.name)
    if blocked:
        return Decision(
            False, "matching policy found but source failed posture checks", None, tuple(blocked)
        )
    return Decision(False, f"default {net.default_action}: no policy matches")


def reachable_pairs(net: Network, today: dt.date | None = None) -> set[tuple[str, str]]:
    """Directed (src, dst) pairs that at least one policy permits on some port."""
    today = today or dt.date.today()
    pairs: set[tuple[str, str]] = set()
    for pol in net.policies:
        try:
            if not pol.enabled or policy_expired(pol, today):
                continue
        except ValueError:
            continue
        for s in net.peers.values():
            for d in net.peers.values():
                if s.name == d.name or not matches(pol, s, d):
                    continue
                checks = [net.posture_checks.get(n) for n in pol.posture_checks]
                if any(c is None or posture_failures(s, c) for c in checks):
                    continue
                pairs.add((s.name, d.name))
    return pairs

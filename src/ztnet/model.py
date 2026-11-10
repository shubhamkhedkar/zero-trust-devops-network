"""Typed in-memory model of a zero-trust overlay network definition."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

PROTOCOLS = ("tcp", "udp", "icmp", "all")


@dataclass(frozen=True)
class PostureCheck:
    name: str
    min_client_version: str | None = None
    allowed_os: tuple[str, ...] = ()
    require_disk_encryption: bool = False


@dataclass(frozen=True)
class Peer:
    name: str
    address: str
    groups: tuple[str, ...]
    os: str = "linux"
    client_version: str | None = None
    disk_encrypted: bool = False
    public_key: str | None = None
    endpoint: str | None = None
    routing_peer: bool = False
    routes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Group:
    name: str
    description: str = ""
    sensitive: bool = False


@dataclass(frozen=True)
class Policy:
    name: str
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    protocol: str = "tcp"
    ports: tuple[str, ...] = ()
    bidirectional: bool = False
    enabled: bool = True
    posture_checks: tuple[str, ...] = ()
    expires: str | None = None
    description: str = ""


@dataclass
class Network:
    name: str
    overlay_cidr: str
    listen_port: int = 51820
    default_action: str = "deny"
    groups: dict[str, Group] = field(default_factory=dict)
    peers: dict[str, Peer] = field(default_factory=dict)
    policies: list[Policy] = field(default_factory=list)
    posture_checks: dict[str, PostureCheck] = field(default_factory=dict)
    # Names of peers whose definition embedded a private key (value is never stored).
    private_key_peers: list[str] = field(default_factory=list)

    @property
    def overlay(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.overlay_cidr, strict=True)

    def members(self, group: str) -> list[Peer]:
        return [p for p in self.peers.values() if group in p.groups]


def port_range(spec: str) -> tuple[int, int]:
    """Parse '443' or '8000-8100' into an inclusive (low, high) tuple."""
    text = str(spec).strip()
    if "-" in text:
        low_s, high_s = text.split("-", 1)
        low, high = int(low_s), int(high_s)
    else:
        low = high = int(text)
    if not (1 <= low <= high <= 65535):
        raise ValueError(f"port spec out of range: {spec!r}")
    return low, high

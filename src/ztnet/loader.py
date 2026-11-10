"""Load a network definition from YAML or JSON into the typed model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .model import Group, Network, Peer, Policy, PostureCheck


class LoadError(ValueError):
    """Raised when the document cannot be parsed into a network model."""


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str | int):
        return (str(value),)
    return tuple(str(v) for v in value)


def parse(doc: dict[str, Any]) -> Network:
    if not isinstance(doc, dict):
        raise LoadError("network document must be a mapping")
    try:
        net = doc["network"]
        network = Network(
            name=str(net["name"]),
            overlay_cidr=str(net["overlay_cidr"]),
            listen_port=int(net.get("listen_port", 51820)),
            default_action=str(net.get("default_action", "deny")).lower(),
        )
    except (KeyError, TypeError) as exc:
        raise LoadError(f"missing required network field: {exc}") from exc

    for name, spec in (doc.get("groups") or {}).items():
        spec = spec or {}
        network.groups[str(name)] = Group(
            name=str(name),
            description=str(spec.get("description", "")),
            sensitive=bool(spec.get("sensitive", False)),
        )

    for name, spec in (doc.get("posture_checks") or {}).items():
        spec = spec or {}
        network.posture_checks[str(name)] = PostureCheck(
            name=str(name),
            min_client_version=spec.get("min_client_version"),
            allowed_os=_tuple(spec.get("allowed_os")),
            require_disk_encryption=bool(spec.get("require_disk_encryption", False)),
        )

    for item in doc.get("peers") or []:
        try:
            peer = Peer(
                name=str(item["name"]),
                address=str(item["address"]),
                groups=_tuple(item.get("groups")),
                os=str(item.get("os", "linux")).lower(),
                client_version=item.get("client_version"),
                disk_encrypted=bool(item.get("disk_encrypted", False)),
                public_key=item.get("public_key"),
                endpoint=item.get("endpoint"),
                routing_peer=bool(item.get("routing_peer", False)),
                routes=_tuple(item.get("routes")),
            )
        except (KeyError, TypeError) as exc:
            raise LoadError(f"peer is missing a required field: {exc}") from exc
        if peer.name in network.peers:
            raise LoadError(f"duplicate peer name: {peer.name}")
        if "private_key" in item:
            network.private_key_peers.append(peer.name)
        network.peers[peer.name] = peer

    for item in doc.get("policies") or []:
        try:
            expires = item.get("expires")
            network.policies.append(
                Policy(
                    name=str(item["name"]),
                    sources=_tuple(item["sources"]),
                    destinations=_tuple(item["destinations"]),
                    protocol=str(item.get("protocol", "tcp")).lower(),
                    ports=_tuple(item.get("ports")),
                    bidirectional=bool(item.get("bidirectional", False)),
                    enabled=bool(item.get("enabled", True)),
                    posture_checks=_tuple(item.get("posture_checks")),
                    expires=str(expires) if expires is not None else None,
                    description=str(item.get("description", "")),
                )
            )
        except (KeyError, TypeError) as exc:
            raise LoadError(f"policy is missing a required field: {exc}") from exc
    return network


def loads(text: str, fmt: str = "yaml") -> Network:
    try:
        doc = json.loads(text) if fmt == "json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise LoadError(f"could not parse {fmt}: {exc}") from exc
    return parse(doc)


def load(path: str | Path) -> Network:
    p = Path(path)
    fmt = "json" if p.suffix.lower() == ".json" else "yaml"
    return loads(p.read_text(encoding="utf-8"), fmt)

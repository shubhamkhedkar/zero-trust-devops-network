import datetime as dt
from pathlib import Path

import pytest

from ztnet.loader import load

ROOT = Path(__file__).resolve().parent.parent
TODAY = dt.date(2026, 11, 10)


@pytest.fixture
def today():
    return TODAY


@pytest.fixture
def network():
    return load(ROOT / "examples" / "devops-network.yaml")


@pytest.fixture
def insecure():
    return load(ROOT / "examples" / "insecure-network.yaml")


def base_doc():
    return {
        "network": {"name": "t", "overlay_cidr": "100.64.0.0/24", "default_action": "deny"},
        "groups": {"a": {}, "b": {}, "secure": {"sensitive": True}},
        "posture_checks": {"pc": {"min_client_version": "0.30.0", "allowed_os": ["linux"]}},
        "peers": [
            {"name": "p1", "address": "100.64.0.10", "groups": ["a"], "client_version": "0.31.0"},
            {"name": "p2", "address": "100.64.0.11", "groups": ["b"], "client_version": "0.31.0"},
            {"name": "p3", "address": "100.64.0.12", "groups": ["secure"]},
        ],
        "policies": [
            {"name": "a-to-b", "sources": ["a"], "destinations": ["b"], "ports": ["443"]},
            {
                "name": "a-to-secure",
                "sources": ["a"],
                "destinations": ["secure"],
                "ports": ["5432"],
                "posture_checks": ["pc"],
            },
        ],
    }

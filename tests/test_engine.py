import pytest
from conftest import base_doc

from ztnet.engine import decide, reachable_pairs
from ztnet.loader import parse


@pytest.mark.parametrize(
    ("src", "dst", "proto", "port", "allowed"),
    [
        ("shubham-laptop", "bastion-01", "tcp", 22, True),
        ("oncall-laptop", "bastion-01", "tcp", 22, False),  # outdated client
        ("oncall-laptop", "bastion-01", "icmp", None, True),
        ("bastion-01", "prod-db-01", "tcp", 5432, True),
        ("bastion-01", "prod-db-01", "tcp", 22, False),
        ("prod-db-01", "bastion-01", "tcp", 5432, False),  # not bidirectional
        ("gha-runner-01", "k8s-prod-api", "tcp", 6443, True),
        ("gha-runner-01", "prod-db-01", "tcp", 5432, False),
        ("shubham-laptop", "prod-db-01", "tcp", 5432, False),
        ("prometheus-01", "prod-db-01", "tcp", 9187, True),
        ("shubham-laptop", "k8s-prod-api", "tcp", 6443, True),  # break-glass until 2027-06-30
    ],
)
def test_example_decisions(network, today, src, dst, proto, port, allowed):
    assert decide(network, src, dst, proto, port, today).allowed is allowed


def test_posture_failure_reported(network, today):
    result = decide(network, "oncall-laptop", "bastion-01", "tcp", 22, today)
    assert result.posture_failures
    assert "0.27.4" in result.posture_failures[0]


def test_unknown_peers_denied(network, today):
    assert not decide(network, "ghost", "bastion-01", "tcp", 22, today).allowed
    assert not decide(network, "bastion-01", "ghost", "tcp", 22, today).allowed
    assert not decide(network, "bastion-01", "bastion-01", "tcp", 22, today).allowed


def test_expired_policy_does_not_allow(today):
    doc = base_doc()
    doc["policies"][0]["expires"] = "2020-01-01"
    assert not decide(parse(doc), "p1", "p2", "tcp", 443, today).allowed


def test_disabled_policy_does_not_allow(today):
    doc = base_doc()
    doc["policies"][0]["enabled"] = False
    assert not decide(parse(doc), "p1", "p2", "tcp", 443, today).allowed


def test_bidirectional(today):
    doc = base_doc()
    doc["policies"][0]["bidirectional"] = True
    assert decide(parse(doc), "p2", "p1", "tcp", 443, today).allowed


def test_port_ranges_and_protocol(today):
    doc = base_doc()
    doc["policies"][0]["ports"] = ["8000-8100"]
    net = parse(doc)
    assert decide(net, "p1", "p2", "tcp", 8050, today).allowed
    assert not decide(net, "p1", "p2", "tcp", 8101, today).allowed
    assert not decide(net, "p1", "p2", "udp", 8050, today).allowed
    assert not decide(net, "p1", "p2", "tcp", None, today).allowed


def test_reachable_pairs_respect_posture(network, today):
    pairs = reachable_pairs(network, today)
    assert ("shubham-laptop", "bastion-01") in pairs
    assert ("prod-db-01", "shubham-laptop") not in pairs

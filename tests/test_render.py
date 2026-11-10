import json

from ztnet.render import (
    access_matrix,
    mermaid_topology,
    netbird_policies,
    nftables_rules,
    render_all,
    wireguard_config,
)


def test_wireguard_has_no_private_key(network, today):
    conf = wireguard_config(network, "bastion-01", today)
    assert "PrivateKey" not in conf
    assert "PostUp = wg set %i private-key /etc/wireguard/%i.key" in conf


def test_wireguard_peers_follow_policy(network, today):
    conf = wireguard_config(network, "prod-db-01", today)
    assert "100.92.2.10/32" in conf  # bastion
    assert "100.92.6.10/32" in conf  # k8s prod
    assert "100.92.3.10/32" not in conf  # gha runner has no path to the DB


def test_routing_peer_routes_in_allowed_ips(network, today):
    conf = wireguard_config(network, "shubham-laptop", today)
    assert "AllowedIPs = 100.92.9.10/32, 10.20.0.0/16" in conf
    assert "Endpoint = vpc-router.example.com:51820" in conf


def test_nftables_default_drop_and_ports(network, today):
    rules = nftables_rules(network, "prod-db-01", today)
    assert 'counter drop comment "default deny"' in rules
    assert "ip saddr 100.92.2.10 tcp dport { 5432 } accept" in rules
    assert "100.92.3.10" not in rules


def test_nftables_skips_posture_failures(network, today):
    rules = nftables_rules(network, "bastion-01", today)
    assert "ip saddr 100.92.1.11 tcp" not in rules  # oncall-laptop fails posture for SSH
    assert "ip saddr 100.92.1.11 meta l4proto icmp accept" in rules


def test_netbird_policy_shape(network, today):
    policies = netbird_policies(network, today)
    names = [p["name"] for p in policies]
    assert "break-glass-prod-k8s" in names
    rule = policies[0]["rules"][0]
    assert set(rule) >= {"sources", "destinations", "protocol", "ports", "action"}
    assert rule["action"] == "accept"


def test_matrix_and_mermaid(network, today):
    assert "| registry-01 |" in access_matrix(network, today)
    assert mermaid_topology(network, today).startswith("flowchart LR")


def test_render_all_writes_files(network, today, tmp_path):
    files = render_all(network, tmp_path, today)
    assert len(files) == 2 * len(network.peers) + 3
    json.loads((tmp_path / "netbird-policies.json").read_text())

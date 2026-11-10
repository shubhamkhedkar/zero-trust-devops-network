import datetime as dt

import pytest
from conftest import base_doc

from ztnet.loader import parse
from ztnet.validate import validate


def codes(report, severity="error"):
    return {f.code for f in report.findings if f.severity == severity}


def test_example_network_is_clean(network, today):
    report = validate(network, today)
    assert report.ok
    assert report.warnings == []


def test_insecure_example_fails_every_class(insecure, today):
    report = validate(insecure, today)
    assert not report.ok
    expected = {
        "ZT001",
        "ZT002",
        "ZT003",
        "ZT004",
        "ZT005",
        "ZT006",
        "ZT007",
        "ZT009",
        "ZT011",
        "ZT012",
        "ZT015",
    }
    assert expected <= codes(report)


def test_private_key_value_never_echoed(insecure, today):
    text = str(validate(insecure, today).as_dict())
    assert "REDACTED-EXAMPLE" not in text


def test_base_doc_is_clean(today):
    assert validate(parse(base_doc()), today).ok


def test_address_outside_overlay(today):
    doc = base_doc()
    doc["peers"][0]["address"] = "10.0.0.1"
    assert "ZT003" in codes(validate(parse(doc), today))


def test_network_address_rejected(today):
    doc = base_doc()
    doc["peers"][0]["address"] = "100.64.0.0"
    assert "ZT003" in codes(validate(parse(doc), today))


def test_sensitive_needs_posture(today):
    doc = base_doc()
    del doc["policies"][1]["posture_checks"]
    assert "ZT007" in codes(validate(parse(doc), today))


def test_unknown_posture_check(today):
    doc = base_doc()
    doc["policies"][1]["posture_checks"] = ["missing"]
    assert "ZT008" in codes(validate(parse(doc), today))


def test_all_ports_warning_for_normal_group(today):
    doc = base_doc()
    del doc["policies"][0]["ports"]
    report = validate(parse(doc), today)
    assert report.ok
    assert "ZT006" in codes(report, "warning")


@pytest.mark.parametrize("port", ["22", "3389", "6443", "5000-7000"])
def test_admin_ports_from_all_group(port, today):
    doc = base_doc()
    doc["policies"][0] = {"name": "x", "sources": ["All"], "destinations": ["b"], "ports": [port]}
    assert "ZT012" in codes(validate(parse(doc), today))


def test_icmp_with_ports_rejected(today):
    doc = base_doc()
    doc["policies"][0]["protocol"] = "icmp"
    assert "ZT006" in codes(validate(parse(doc), today))


@pytest.mark.parametrize("spec", ["0", "70000", "90-10", "http"])
def test_bad_port_specs(spec, today):
    doc = base_doc()
    doc["policies"][0]["ports"] = [spec]
    assert "ZT006" in codes(validate(parse(doc), today))


def test_expiry(today):
    doc = base_doc()
    doc["policies"][0]["expires"] = "2026-11-09"
    assert "ZT011" in codes(validate(parse(doc), today))
    doc["policies"][0]["expires"] = "2026-11-10"
    assert validate(parse(doc), today).ok
    doc["policies"][0]["expires"] = "next week"
    assert "ZT011" in codes(validate(parse(doc), today))


def test_example_break_glass_expires_mid_2027(network):
    assert "ZT011" in codes(validate(network, dt.date(2027, 7, 1)))


def test_bad_public_key(today):
    doc = base_doc()
    doc["peers"][0]["public_key"] = "not-a-key"
    assert "ZT010" in codes(validate(parse(doc), today))
    doc["peers"][0]["public_key"] = "A" * 43 + "="  # 32 bytes of base64
    assert validate(parse(doc), today).ok
    doc["peers"][0]["public_key"] = "<PUBLIC_KEY:p1>"
    assert validate(parse(doc), today).ok


def test_route_overlapping_overlay(today):
    doc = base_doc()
    doc["peers"][1].update(routing_peer=True, routes=["100.64.0.0/25"])
    assert "ZT015" in codes(validate(parse(doc), today))


def test_reserved_all_group(today):
    doc = base_doc()
    doc["groups"]["All"] = {}
    assert "ZT004" in codes(validate(parse(doc), today))


def test_duplicate_policy_names(today):
    doc = base_doc()
    doc["policies"].append(dict(doc["policies"][0]))
    assert "ZT013" in codes(validate(parse(doc), today))


def test_unreferenced_group_warns(today):
    doc = base_doc()
    doc["groups"]["c"] = {}
    doc["peers"].append({"name": "p4", "address": "100.64.0.20", "groups": ["c"]})
    assert "ZT016" in codes(validate(parse(doc), today), "warning")

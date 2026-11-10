import pytest
from conftest import base_doc

from ztnet.loader import LoadError, loads, parse


def test_example_loads(network):
    assert network.name == "platform-overlay"
    assert len(network.peers) == 11
    assert network.peers["vpc-router-01"].routes == ("10.20.0.0/16",)


def test_missing_network_block():
    with pytest.raises(LoadError):
        parse({"peers": []})


def test_duplicate_peer_rejected():
    doc = base_doc()
    doc["peers"].append(dict(doc["peers"][0]))
    with pytest.raises(LoadError, match="duplicate peer"):
        parse(doc)


def test_invalid_yaml():
    with pytest.raises(LoadError):
        loads("network: [unclosed")


def test_private_key_value_is_not_stored():
    doc = base_doc()
    doc["peers"][0]["private_key"] = "should-never-be-kept"
    net = parse(doc)
    assert net.private_key_peers == ["p1"]
    assert "should-never-be-kept" not in repr(net)


def test_scalar_groups_are_normalised():
    doc = base_doc()
    doc["peers"][0]["groups"] = "a"
    assert parse(doc).peers["p1"].groups == ("a",)

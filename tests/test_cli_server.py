import json
import threading
import urllib.error
import urllib.request

import pytest
from conftest import ROOT, base_doc

from ztnet.cli import main
from ztnet.server import build_server

GOOD = str(ROOT / "examples" / "devops-network.yaml")
BAD = str(ROOT / "examples" / "insecure-network.yaml")


def test_cli_validate_exit_codes(capsys):
    assert main(["validate", GOOD]) == 0
    assert main(["validate", BAD]) == 1
    assert "ZT001" in capsys.readouterr().out


def test_cli_validate_json(capsys):
    main(["validate", GOOD, "--json"])
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_decide(capsys):
    assert (
        main(["decide", GOOD, "--src", "bastion-01", "--dst", "prod-db-01", "--port", "5432"]) == 0
    )
    assert (
        main(["decide", GOOD, "--src", "gha-runner-01", "--dst", "prod-db-01", "--port", "5432"])
        == 3
    )


def test_cli_render_refuses_invalid(tmp_path):
    assert main(["render", BAD, "--out", str(tmp_path)]) == 1
    assert not any(tmp_path.iterdir())


def test_cli_render(tmp_path, capsys):
    assert main(["render", GOOD, "--out", str(tmp_path)]) == 0
    assert (tmp_path / "wireguard" / "bastion-01.conf").exists()


def test_cli_missing_file():
    assert main(["validate", "/nonexistent.yaml"]) == 1


@pytest.fixture
def server(network):
    srv = build_server(network, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def test_server_health_and_decide(server):
    with urllib.request.urlopen(f"{server}/healthz", timeout=5) as resp:
        assert json.loads(resp.read())["status"] == "ok"
    result = _post(
        f"{server}/v1/decide",
        {"src": "shubham-laptop", "dst": "bastion-01", "protocol": "tcp", "port": 22},
    )
    assert result["allowed"] is True


def test_server_validate_candidate(server):
    doc = base_doc()
    doc["network"]["default_action"] = "allow"
    report = _post(f"{server}/v1/validate", doc)
    assert report["ok"] is False


def test_server_rejects_bad_input(server):
    req = urllib.request.Request(
        f"{server}/v1/decide", data=b"{not json", headers={"Content-Type": "application/json"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 400
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/nope", timeout=5)
    assert exc.value.code == 404

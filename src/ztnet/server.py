"""Local policy decision service (stdlib only).

Binds to 127.0.0.1 by default. It answers questions about a policy file; it
never changes a network, contacts NetBird, or touches WireGuard interfaces.
"""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import __version__
from .engine import decide
from .loader import LoadError, loads
from .model import Network
from .render import access_matrix, netbird_policies
from .validate import validate

MAX_BODY = 256 * 1024
log = logging.getLogger("ztnet.server")


def make_handler(network: Network) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"ztnet/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # route through logging
            log.info("%s %s", self.address_string(), fmt % args)

        def _send(self, status: int, payload: Any, ctype: str = "application/json") -> None:
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self) -> dict[str, Any] | None:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "body required (max 256 KiB)"})
                return None
            try:
                data = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
                return None
            if not isinstance(data, dict):
                self._send(HTTPStatus.BAD_REQUEST, {"error": "JSON object expected"})
                return None
            return data

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send(HTTPStatus.OK, {"status": "ok", "network": network.name})
            elif self.path == "/v1/policy/report":
                self._send(HTTPStatus.OK, validate(network).as_dict())
            elif self.path == "/v1/policy/netbird":
                self._send(HTTPStatus.OK, netbird_policies(network))
            elif self.path == "/v1/matrix":
                self._send(HTTPStatus.OK, access_matrix(network), "text/markdown; charset=utf-8")
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/v1/decide":
                data = self._json_body()
                if data is None:
                    return
                port = data.get("port")
                try:
                    port = int(port) if port is not None else None
                except (TypeError, ValueError):
                    self._send(HTTPStatus.BAD_REQUEST, {"error": "port must be an integer"})
                    return
                result = decide(
                    network,
                    str(data.get("src", "")),
                    str(data.get("dst", "")),
                    str(data.get("protocol", "tcp")),
                    port,
                )
                self._send(HTTPStatus.OK, result.as_dict())
            elif self.path == "/v1/validate":
                data = self._json_body()
                if data is None:
                    return
                try:
                    candidate = loads(json.dumps(data), "json")
                except LoadError as exc:
                    self._send(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})
                    return
                self._send(HTTPStatus.OK, validate(candidate).as_dict())
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    return Handler


def build_server(
    network: Network, host: str = "127.0.0.1", port: int = 8080
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(network))

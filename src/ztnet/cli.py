"""Command line entry point: ztnet validate | decide | render | serve."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__
from .engine import decide
from .loader import LoadError, load
from .render import render_all
from .validate import validate


def _cmd_validate(args: argparse.Namespace) -> int:
    report = validate(load(args.policy))
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        for f in report.findings:
            print(f"{f.severity.upper():7} {f.code} {f.subject}: {f.message}")
        print(f"\n{len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    if report.errors:
        return 1
    return 2 if args.strict and report.warnings else 0


def _cmd_decide(args: argparse.Namespace) -> int:
    result = decide(load(args.policy), args.src, args.dst, args.protocol, args.port)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.allowed else 3


def _cmd_render(args: argparse.Namespace) -> int:
    net = load(args.policy)
    report = validate(net)
    if not report.ok:
        print(
            "refusing to render: policy has validation errors (run 'ztnet validate')",
            file=sys.stderr,
        )
        return 1
    for path in render_all(net, args.out):
        print(path)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .server import build_server

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    net = load(args.policy)
    server = build_server(net, args.host, args.port)
    logging.info(
        "ztnet decision service on http://%s:%s (network %s)", args.host, args.port, net.name
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ztnet", description=__doc__)
    parser.add_argument("--version", action="version", version=f"ztnet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="run zero-trust checks on a policy file")
    v.add_argument("policy")
    v.add_argument("--json", action="store_true")
    v.add_argument("--strict", action="store_true", help="exit 2 when warnings exist")
    v.set_defaults(func=_cmd_validate)

    d = sub.add_parser("decide", help="evaluate one access request")
    d.add_argument("policy")
    d.add_argument("--src", required=True)
    d.add_argument("--dst", required=True)
    d.add_argument("--protocol", default="tcp", choices=["tcp", "udp", "icmp"])
    d.add_argument("--port", type=int)
    d.set_defaults(func=_cmd_decide)

    r = sub.add_parser("render", help="render WireGuard/nftables/NetBird/matrix artifacts")
    r.add_argument("policy")
    r.add_argument("--out", default="out")
    r.set_defaults(func=_cmd_render)

    s = sub.add_parser("serve", help="run the local decision API")
    s.add_argument("--policy", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=_cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (LoadError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

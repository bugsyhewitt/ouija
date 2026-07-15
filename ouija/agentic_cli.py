"""ouija agentic CLI — the agentic/RAG/MCP fuzzer command line (Packet 02).

A *separate* entry point (``ouija-agentic``) from the v0.1 single-endpoint scanner
(``ouija``), so the existing CLI and its 400+ tests are untouched. Article II
(CLI Interface Mandate): all agentic functionality is reachable here — JSON in,
JSON out.

Subcommands map to the §13 verbs:

* ``list-probes`` — print the probe catalog (safe).
* ``scan-mcp``    — §8 MCP-server fuzzing.
* ``scan-rag``    — §7 RAG-poisoning.
* ``fuzz-agent``  — §9 excessive-agency + §7 tool-result injection.

Safety (§15) is enforced here exactly as in the MCP server: an active verb refuses
without ``--confirm`` and refuses a target not on the allow-list (``--allow`` /
``--allow-file``). ``--lab`` runs the verb against the in-repo deliberately-
vulnerable fixtures (headless self-test) and implicitly allow-lists only loopback.

Exit codes:
  0  scan completed (any findings); list-probes
  1  scan completed AND at least one CONFIRMED finding (CI-gateable)
  2  target refused (not allow-listed)
  3  usage / runtime error / missing --confirm on an active verb
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from ouija import __version__
from ouija.agentic_scan import (
    fuzz_agent_target,
    scan_mcp_target,
    scan_rag_target,
)
from ouija.agentic_report import to_h1md, to_sarif
from ouija.allowlist import AllowlistError, load_allowlist
from ouija.asitax import probe_catalog
from ouija.findings import group_by_owasp

EXIT_OK = 0
EXIT_CONFIRMED = 1
EXIT_REFUSED = 2
EXIT_ERROR = 3

_ETHICS = (
    "ouija sends adversarial payloads to live LLM/agent/MCP endpoints. This costs "
    "money, may violate provider ToS, and must only ever hit targets you own or "
    "are authorized to test. Active verbs require --confirm and an allow-listed "
    "target; the OOB collector is local by default. There is no bypass (§15)."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ouija-agentic",
        description="ouija — the agentic / RAG / tool-call / MCP-server fuzzer. "
        "Points at a deployed AI application and proves whether an attacker can "
        "make it do something it shouldn't, with a data-flow success oracle. "
        + _ETHICS,
    )
    parser.add_argument("--version", action="version",
                        version=f"ouija-agentic {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list-probes (safe)
    sp = sub.add_parser("list-probes",
                        help="Print ouija's probe families + OWASP ASI/LLM map (safe).")
    sp.add_argument("--format", choices=["json", "table"], default="json", dest="fmt")

    # shared active-verb args
    def add_active_args(p, *, target_flag: str, target_help: str) -> None:
        p.add_argument(target_flag, dest="target", metavar="URL", default=None,
                       help=target_help)
        p.add_argument("--confirm", action="store_true",
                       help="Authorize this ACTIVE verb to send adversarial traffic.")
        p.add_argument("--lab", action="store_true",
                       help="Run against the in-repo deliberately-vulnerable lab "
                            "fixture (headless self-test; loopback only).")
        p.add_argument("--allow", action="append", default=[], metavar="HOST[:PORT]",
                       help="Add a host to the allow-list (repeatable).")
        p.add_argument("--allow-file", default=None, metavar="PATH",
                       help="Newline-delimited allow-list file.")
        p.add_argument("--repeats", type=int, default=20, metavar="N",
                       help="ASR/CI repeat count per landed probe (default 20).")
        p.add_argument("--format", choices=["json", "h1md", "sarif"], default="json",
                       dest="fmt")

    sm = sub.add_parser("scan-mcp", help="Fuzz a target MCP server (§8).")
    add_active_args(sm, target_flag="--url", target_help="MCP server URL.")
    sm.add_argument("--token", default=None, help="Bearer token for the MCP server.")

    sr = sub.add_parser("scan-rag", help="Fuzz a RAG pipeline (§7).")
    add_active_args(sr, target_flag="--endpoint", target_help="RAG query endpoint URL.")

    fa = sub.add_parser("fuzz-agent", help="Fuzz a tool-using agent (§9/§7).")
    add_active_args(fa, target_flag="--endpoint", target_help="Agent endpoint URL.")

    return parser


def _resolve_allowlist(args) -> list:
    entries: list = []
    if getattr(args, "allow_file", None):
        try:
            with open(args.allow_file, encoding="utf-8") as fh:
                entries += load_allowlist(fh.read())
        except OSError as exc:
            raise _CliError(f"could not read --allow-file: {exc}")
    if getattr(args, "allow", None):
        entries += load_allowlist(args.allow)
    if getattr(args, "lab", False):
        # The lab only ever targets loopback; allow-list it implicitly.
        entries += load_allowlist(["127.0.0.1"])
    return entries


class _CliError(Exception):
    pass


def _render(report, fmt: str = "json") -> str:
    if fmt == "h1md":
        return to_h1md(report)
    if fmt == "sarif":
        return to_sarif(report)
    grouped = group_by_owasp(report.findings)
    return json.dumps({
        "tool": "ouija",
        "version": __version__,
        "verb": report.verb,
        "target": report.target,
        "summary": {
            "total": len(report.findings),
            "confirmed": len(report.confirmed()),
            "detected": len(report.detected()),
            "by_owasp": {k: len(v) for k, v in grouped.items()},
        },
        "findings": report.findings,
    }, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "list-probes":
        cat = probe_catalog()
        if args.fmt == "json":
            print(json.dumps(cat, indent=2))
        else:
            for f in cat:
                asi = ",".join(f["asi"]) or "-"
                llm = ",".join(f["llm"]) or "-"
                flag = " [stub]" if f["stub"] else ""
                print(f"{f['key']:<28} {asi:<14} {llm:<8} {f['title']}{flag}")
        return EXIT_OK

    # Active verbs: gate first.
    if not args.confirm and not args.lab:
        print("error: this verb is ACTIVE and sends adversarial traffic. Pass "
              "--confirm to authorize (and ensure the target is allow-listed), or "
              "--lab to run the headless lab self-test.", file=sys.stderr)
        return EXIT_ERROR

    try:
        allowlist = _resolve_allowlist(args)
    except _CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.lab and not args.target:
        print("error: a target URL is required (or use --lab).", file=sys.stderr)
        return EXIT_ERROR

    try:
        report = asyncio.run(_dispatch(args, allowlist))
    except AllowlistError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 — surface cleanly
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(_render(report, fmt=getattr(args, "fmt", "json")))
    # CI gate: a CONFIRMED data-flow finding breaks the build.
    return EXIT_CONFIRMED if report.confirmed() else EXIT_OK


async def _dispatch(args, allowlist):
    if args.cmd == "scan-mcp":
        return await scan_mcp_target(
            url=args.target, token=getattr(args, "token", None),
            allowlist=allowlist, lab_target=args.lab, repeats=args.repeats)
    if args.cmd == "scan-rag":
        return await scan_rag_target(
            query_url=args.target, allowlist=allowlist,
            lab_target=args.lab, repeats=args.repeats)
    if args.cmd == "fuzz-agent":
        return await fuzz_agent_target(
            endpoint=args.target, allowlist=allowlist,
            lab_target=args.lab, repeats=args.repeats)
    raise _CliError(f"unknown command {args.cmd!r}")


if __name__ == "__main__":
    raise SystemExit(main())

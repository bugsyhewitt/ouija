"""ouija command-line interface.

Article II (CLI Interface Mandate): all functionality is reachable from this
CLI — text/JSON in, text/JSON out.

Exit codes:
  0  scan completed (findings may or may not be present)
  2  target out of scope (refused before any request is sent)
  3  usage / runtime error
"""

from __future__ import annotations

import argparse
import sys

from ouija import __version__
from ouija.corpus import ATTACK_SETS, load_attack_set
from ouija.report import render
from ouija.scanner import run_scan
from ouija.scope import ScopeError, assert_in_scope

EXIT_OK = 0
EXIT_OUT_OF_SCOPE = 2
EXIT_ERROR = 3

_ETHICS = (
    "ouija only tests a single endpoint you are explicitly authorized to test. "
    "You are responsible for staying in scope. Provide a --scope-file listing "
    "the authorized host(s); ouija refuses targets that are not in it."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ouija",
        description="A bug-bounty-aligned LLM endpoint fuzzer. "
        "Finds ship-able findings against a single in-scope LLM HTTP endpoint "
        "and emits bug-bounty-formatted reports. " + _ETHICS,
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="HTTP(S) URL of the LLM endpoint to test (single target per run).",
    )
    parser.add_argument(
        "--scope-file",
        required=True,
        metavar="PATH",
        help="Path to a newline-delimited scope file of authorized host[:port] "
        "entries. The target must be in scope or ouija exits with code 2.",
    )
    parser.add_argument(
        "--attack-set",
        choices=list(ATTACK_SETS),
        default="all",
        help="Which attack corpus to run (default: all).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "h1md"],
        default="json",
        dest="fmt",
        help="Output format: json or HackerOne-style markdown (default: json).",
    )
    parser.add_argument(
        "--api-key-env",
        metavar="ENV_VAR",
        default=None,
        help="Name of the environment variable holding the auth token to send "
        "to the target as a Bearer token (the value is read from the env, "
        "never passed on the command line).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Max in-flight requests to the target (default: 5).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ouija {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Scope gate — refuse before sending any request.
    try:
        assert_in_scope(args.target, args.scope_file)
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_OUT_OF_SCOPE

    try:
        loaded = load_attack_set(args.attack_set)
    except (ValueError, OSError) as exc:
        print(f"error: failed to load attack set: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = run_scan(
            target=args.target,
            attack_set_name=args.attack_set,
            loaded=loaded,
            api_key_env=args.api_key_env,
            concurrency=args.concurrency,
        )
    except Exception as exc:  # noqa: BLE001 — surface any transport error cleanly
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(render(result, args.fmt))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

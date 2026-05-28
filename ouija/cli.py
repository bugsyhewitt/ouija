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
import json
import sys

from ouija import __version__
from ouija.client import ResponsePathError, parse_response_path
from ouija.corpus import ATTACK_SETS, load_attack_set
from ouija.indirect import DEFAULT_INJECT_VIA, INJECT_VIA_MODES
from ouija.mutate import DEFAULT_MUTATOR_SET, MUTATOR_SETS
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
        "--request-template",
        metavar="JSON",
        default=None,
        dest="request_template",
        help=(
            'JSON request body template. Must be valid JSON containing the '
            'placeholder value "{prompt}" (quoted) which ouija replaces with '
            'each attack prompt before sending. Use this when the target does '
            'not accept the default {\"prompt\": \"...\"} shape. Example for '
            'OpenAI-style endpoints: '
            '\'{"messages": [{"role": "user", "content": "{prompt}"}]}\'. '
            "The prompt value is JSON-encoded before insertion so embedded "
            "quotes and newlines are escaped correctly."
        ),
    )
    parser.add_argument(
        "--response-path",
        metavar="PATH",
        default=None,
        dest="response_path",
        help=(
            "Dotted/bracket selector pinning where the reply text lives in the "
            "target's JSON response, e.g. 'choices.0.message.content' or "
            "'data[0].text'. Use this with --request-template when the target "
            "returns a non-standard response shape; without it ouija guesses the "
            "reply field heuristically and may silently read nothing. Integer "
            "segments are list indices; everything else is a dict key."
        ),
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Send each mutated prompt N times (default: 1 to preserve cost). "
            "Recommended: 3-5. Defeats LLM non-determinism: an attack that "
            "succeeds on any attempt is a reportable finding with a hit-rate "
            "(e.g. '3/5 attempts succeeded')."
        ),
    )
    parser.add_argument(
        "--mutators",
        choices=list(MUTATOR_SETS),
        default=DEFAULT_MUTATOR_SET,
        dest="mutators",
        help=(
            "Which mutator family to apply to each attack prompt. 'surface' "
            "(default) runs the four phrasing variants (base/polite/urgent/"
            "wrapped). 'all' additionally runs encoding/obfuscation mutators "
            "(base64, ROT13, leetspeak, zero-width injection, HTML-comment "
            "smuggling) that probe whether a guardrail can be bypassed by "
            "changing the payload's representation. 'all' roughly doubles the "
            "number of requests, so it is opt-in for cost."
        ),
    )
    parser.add_argument(
        "--inject-via",
        choices=list(INJECT_VIA_MODES),
        default=DEFAULT_INJECT_VIA,
        dest="inject_via",
        help=(
            "Injection channel. 'direct' (default) sends each attack as the user "
            "prompt (v0.1 behaviour). 'document', 'webpage', and 'email' instead "
            "nest the attack inside data the endpoint is asked to process (a "
            "document to summarize, a fetched web page, a support email) — the "
            "higher-severity indirect-injection variant behind EchoLeak and the "
            "Gemini/Copilot 2025 exploits. The attack (and any exfil canary) is "
            "preserved verbatim inside the envelope, so detection is unchanged."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ouija {__version__}",
    )
    return parser


_TEMPLATE_PLACEHOLDER = '"{prompt}"'


class _TemplateError(Exception):
    """Raised by _validate_request_template on invalid input."""


def _validate_request_template(raw: str) -> str:
    """Validate *raw* as a JSON request template; return it unchanged on success.

    Raises :exc:`_TemplateError` with a human-readable message on failure:
    - not valid JSON
    - does not contain the required ``"{prompt}"`` placeholder
    """
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _TemplateError(
            f'--request-template is not valid JSON: {exc}'
        ) from exc

    if _TEMPLATE_PLACEHOLDER not in raw:
        raise _TemplateError(
            f'--request-template must contain the placeholder '
            f'{_TEMPLATE_PLACEHOLDER} (as a quoted JSON string value)'
        )

    return raw


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Validate request template if provided.
    request_template: str | None = None
    if args.request_template is not None:
        try:
            request_template = _validate_request_template(args.request_template)
        except _TemplateError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    # Validate response path if provided (fail fast before any request).
    if args.response_path is not None:
        try:
            parse_response_path(args.response_path)
        except ResponsePathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

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
            request_template=request_template,
            response_path=args.response_path,
            repeats=args.repeats,
            mutator_set=args.mutators,
            inject_via=args.inject_via,
        )
    except Exception as exc:  # noqa: BLE001 — surface any transport error cleanly
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(render(result, args.fmt))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

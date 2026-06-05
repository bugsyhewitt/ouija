"""ouija command-line interface.

Article II (CLI Interface Mandate): all functionality is reachable from this
CLI — text/JSON in, text/JSON out.

Exit codes:
  0  scan completed; no findings met the --fail-on threshold (or it is "none")
  1  scan completed; at least one finding met the --fail-on threshold
  2  target out of scope (refused before any request is sent)
  3  usage / runtime error
"""

from __future__ import annotations

import argparse
import json
import sys

from ouija import __version__
from ouija.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from ouija.client import ResponsePathError, parse_response_path
from ouija.corpus import ATTACK_SETS, load_attack_set
from ouija.gate import FAIL_ON_CHOICES, FAIL_ON_NONE, gate_exit_code
from ouija.indirect import DEFAULT_INJECT_VIA, INJECT_VIA_MODES
from ouija.mutate import DEFAULT_MUTATOR_SET, MUTATOR_SETS
from ouija.notify import NotifyError, send_notification, validate_notify_url
from ouija.plan import build_plan, render_plan
from ouija.report import render
from ouija.scanner import run_scan
from ouija.scope import ScopeError, assert_in_scope

EXIT_OK = 0
EXIT_FINDINGS = 1
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
        choices=["json", "jsonl", "csv", "h1md", "html", "markdown-table", "slack", "pagerduty", "opsgenie", "victorops", "jira", "sarif"],
        default="json",
        dest="fmt",
        help=(
            "Output format: 'json' (structured machine-readable single document, "
            "default), 'jsonl' (newline-delimited / streaming JSON — one compact "
            "record per line: a 'scan' header, one 'finding' per line, then a "
            "'summary' footer, each tagged with a \"record\" discriminator — so a "
            "log shipper, `jq -c`, or a `while read` loop can consume each record "
            "without buffering the whole report), 'csv' (one header row plus one "
            "row per finding, RFC-4180 quoted and severity-sorted — paste it "
            "straight into a spreadsheet / ticket importer to sort, filter, and "
            "assign findings; the header is emitted even on a zero-finding run), "
            "'h1md' (HackerOne-style markdown), 'html' (a single self-contained "
            "HTML document with embedded CSS and no external assets — redirect it "
            "to report.html and open it in any browser, attach it to a ticket, or "
            "hand it to a non-technical stakeholder; all attacker-influenced "
            "values are HTML-escaped so a captured <script> response cannot "
            "execute when the report is viewed), 'markdown-table' (a compact "
            "one-screen GitHub-flavoured-markdown table — header row plus one row "
            "per finding, severity-sorted, pipe-escaped — that renders inline in "
            "a GitHub issue, PR comment, README, or any GitHub-flavoured-"
            "markdown surface; the answer to 'what did the scan find?' at a "
            "glance, with full evidence available in 'json'/'h1md'), 'slack' "
            "(a Slack Block Kit JSON payload — header + run summary + one "
            "section block per finding, wrapped in a severity-coloured "
            "attachment; pipe it directly into a Slack incoming webhook "
            "via `curl --data @-`, since Slack's 'mrkdwn' dialect does NOT "
            "render the GFM tables 'markdown-table' produces), 'pagerduty' "
            "(a PagerDuty Events API v2 enqueue payload — single aggregated "
            "event whose `payload.severity` is mapped from the top finding's "
            "severity, with per-finding details under `payload.custom_details` "
            "and a stable `dedup_key` derived from the scan's target+attack-set "
            "so re-scanning the same target updates the same incident; "
            "`routing_key` is emitted as the literal placeholder string "
            "`YOUR_PAGERDUTY_ROUTING_KEY` for the operator to substitute "
            "before POSTing to https://events.pagerduty.com/v2/enqueue, or "
            "the scan is suppressed entirely on a zero-finding run "
            "(`event_action: resolve` against the same dedup_key) so a clean "
            "rerun closes the prior incident automatically), 'opsgenie' "
            "(an OpsGenie Alert API v2 create-alert payload — single "
            "aggregated alert per scan whose `priority` is mapped 1:1 from "
            "the top finding's severity (critical→P1 … info→P5), with "
            "per-finding records under `details.findings` and a stable "
            "`alias` derived from target+attack-set so re-scanning the same "
            "target updates the same alert; the GenieKey is supplied via "
            "the `Authorization: GenieKey <key>` HTTP HEADER at curl time "
            "(NOT a body field, unlike `pagerduty`), and a zero-finding run "
            "emits a Close-Alert payload against the same alias so a clean "
            "rerun closes the prior alert automatically), 'victorops' "
            "(a VictorOps / Splunk On-Call REST integration payload — single "
            "aggregated event per scan whose `message_type` is mapped from "
            "the top finding's severity (critical/high→CRITICAL, "
            "medium→WARNING, low/info→INFO), with per-finding records under "
            "`ouija_findings` and a stable `entity_id` derived from "
            "target+attack-set so re-scanning the same target updates the "
            "same incident; both the VictorOps API key and routing key are "
            "supplied via the integration URL path at curl time (NOT body "
            "fields), and a zero-finding run emits a `message_type: "
            "RECOVERY` payload against the same entity_id so a clean rerun "
            "auto-recovers the prior incident), 'jira' "
            "(a Jira Cloud REST API v3 Create Issue JSON body — a single "
            "aggregated issue per scan with an ADF description (Atlassian "
            "Document Format, Jira Cloud's native rich-text schema), "
            "`priority` mapped from the top finding's severity "
            "(critical→Highest, high→High, medium→Medium, low/info→Low), "
            "and `fields.project.key` / `fields.issuetype.name` emitted as "
            "placeholder strings for the operator to substitute before "
            "POSTing to "
            "https://<domain>.atlassian.net/rest/api/3/issue — the bearer "
            "token travels in the Authorization header at curl time, not in "
            "the payload body), or 'sarif' "
            "(SARIF 2.1.0 for GitHub code-scanning / CI security dashboards). "
            "SARIF maps each attack category to a rule and each finding to a "
            "result with a GitHub-compatible security-severity; pair it with "
            "--fail-on to both gate the build and upload alerts."
        ),
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
        "--multi-turn",
        action="store_true",
        dest="multi_turn",
        help=(
            "Multi-turn / Crescendo conversational attack mode. Instead of the "
            "stateless single-shot probes, ouija drives scripted escalation "
            "ladders that open benign and steer the target across several "
            "conversation turns until it complies — the Crescendo/GOAT technique "
            "that defeats single-turn guardrails (success rates jump from ~4%% "
            "single-turn to ~78%% multi-turn against hardened targets). Each "
            "ladder is reported as at most one finding carrying the full "
            "transcript and the turn number where compliance occurred. This mode "
            "sends conversation history as a messages array, so it works against "
            "OpenAI/Anthropic-style endpoints out of the box (use "
            "--request-template with a \"{messages}\" placeholder to wrap the "
            "array in custom fields). It ignores --attack-set, --mutators, "
            "--repeats, and --inject-via, which are single-shot concepts."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES),
        default=FAIL_ON_NONE,
        dest="fail_on",
        help=(
            "CI/CD gating: exit with code 1 when at least one finding is at or "
            "above this severity. Choices (ascending): info, low, medium, high, "
            "critical, none (default). 'none' preserves the historical "
            "exit-0-on-completion behaviour. The report is still printed either "
            "way; only the exit code changes — so a pipeline can `ouija ... "
            "--fail-on high` and break the build on a high/critical finding while "
            "still archiving the report. Scope (2) and usage/runtime (3) errors "
            "take precedence over this gate."
        ),
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        default=None,
        dest="baseline",
        help=(
            "Suppress already-triaged findings. PATH is a baseline file (one "
            "finding ID per line, '#' comments allowed, or a saved 'ouija "
            "--format json' report). Any finding whose stable ID is in the "
            "baseline is dropped from the report AND excluded from the "
            "--fail-on gate, so a rerun surfaces — and a pipeline breaks on — "
            "only genuinely new findings. Create one with --write-baseline."
        ),
    )
    parser.add_argument(
        "--write-baseline",
        metavar="PATH",
        default=None,
        dest="write_baseline",
        help=(
            "Snapshot this run's finding IDs to PATH (one per line) for use as "
            "a --baseline on later runs. Writes after suppression, so chaining "
            "--baseline OLD --write-baseline NEW yields the new accepted set. "
            "The report is still printed and the exit code is unchanged."
        ),
    )
    parser.add_argument(
        "--notify",
        metavar="URL",
        default=None,
        dest="notify",
        help=(
            "Webhook alerting: after the scan completes, POST a compact JSON "
            "summary of the run (target, request count, finding count, top "
            "severity, and a per-finding id/severity/category/title roll-up) to "
            "this http(s) URL — e.g. a Slack/Teams incoming-webhook proxy, a "
            "ticketing intake, or a CI fan-out endpoint. The POST carries a "
            "bounded digest, NOT the full report (no raw prompts, response "
            "excerpts, or transcripts), so attack payloads and exfil canaries "
            "are not spilled into a chat channel — read the --format json report "
            "for the evidence. Delivery is best-effort and NON-fatal: a bad URL, "
            "timeout, or non-2xx response prints a warning to stderr but does NOT "
            "change the exit code (the --fail-on gate remains the build verdict). "
            "Skipped entirely in --plan mode (no scan, nothing to notify)."
        ),
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        dest="plan",
        help=(
            "Dry-run / report-only mode: print exactly what the scan WILL send — "
            "the total request count, the per-attack-set breakdown (patterns x "
            "variants x repeats), and the mode (single-shot vs multi-turn) — "
            "WITHOUT sending a single request to the target. The scope gate still "
            "runs first, so a plan is only ever produced for an in-scope host. "
            "Pair with '--format json' for a machine-readable plan to feed CI / "
            "triage tooling (sizing a run, gating on request budget, change "
            "review); any other --format prints a human-readable summary. The "
            "request count it reports matches the real run exactly, so you can "
            "size cost/blast-radius before spending requests against production. "
            "Honours --attack-set, --mutators, --repeats, --inject-via, and "
            "--multi-turn; exits 0."
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

    # Validate the notify webhook URL (if any) before scanning so a malformed
    # URL fails fast — before spending any request against the target.
    if args.notify is not None:
        try:
            validate_notify_url(args.notify)
        except NotifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    # Load the baseline (if any) before scanning so a bad path fails fast,
    # before any request is sent.
    baseline_ids: set[str] = set()
    if args.baseline is not None:
        try:
            baseline_ids = load_baseline(args.baseline)
        except BaselineError as exc:
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

    # Dry-run / report-only mode: enumerate what the scan WOULD send and exit,
    # sending nothing. All fail-fast validation above (template, response-path,
    # baseline path, scope) has already run, so a plan only previews a valid,
    # in-scope run. No network is touched here.
    if args.plan:
        plan = build_plan(
            target=args.target,
            attack_set_name=args.attack_set,
            loaded=loaded,
            repeats=args.repeats,
            mutator_set=args.mutators,
            inject_via=args.inject_via,
            multi_turn=args.multi_turn,
        )
        print(render_plan(plan, args.fmt))
        return EXIT_OK

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
            multi_turn=args.multi_turn,
        )
    except Exception as exc:  # noqa: BLE001 — surface any transport error cleanly
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Suppress baselined (already-triaged) findings before rendering/gating, so
    # the report and the --fail-on gate both see only genuinely new findings.
    if baseline_ids:
        outcome = apply_baseline(result, baseline_ids)
        result = outcome.result
        if outcome.suppressed:
            print(
                f"suppressed {outcome.suppressed} finding(s) via baseline "
                f"{args.baseline}",
                file=sys.stderr,
            )

    # Snapshot the (post-suppression) finding IDs for use as a future baseline.
    if args.write_baseline is not None:
        try:
            count = write_baseline(result, args.write_baseline)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(
            f"wrote {count} finding ID(s) to baseline {args.write_baseline}",
            file=sys.stderr,
        )

    print(render(result, args.fmt))

    # Fire the webhook (if configured) on the post-suppression result, so the
    # alert reflects exactly what the operator sees in the report. Best-effort
    # and NON-fatal: a delivery failure is a side-channel problem and must not
    # change the security exit code that the --fail-on gate computes below.
    if args.notify is not None:
        try:
            status = send_notification(args.notify, result)
            print(
                f"notified {args.notify} (HTTP {status})",
                file=sys.stderr,
            )
        except Exception as exc:  # noqa: BLE001 — webhook is a non-fatal side channel
            print(
                f"warning: --notify webhook delivery failed: {exc}",
                file=sys.stderr,
            )

    return gate_exit_code(
        result,
        args.fail_on,
        ok_code=EXIT_OK,
        findings_code=EXIT_FINDINGS,
    )


if __name__ == "__main__":
    raise SystemExit(main())

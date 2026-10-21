"""CLI entry point: `python -m src.cli <command>`.

Commands
--------
identity   Verify AWS identity (STS) and print non-secret configuration.
scan       Read-only discovery + evidence + classification; writes reports.
validate   Validate reports/inventory.json against the JSON Schema.
report     Generate reports/report.md from existing artifacts.
test-fixtures  Run offline (synthetic-fixture) discovery/classification tests.
test-live  Run explicitly enabled live read-only tests (requires --enable-live-tests;
           cost-incurring checks additionally require --enable-model-invocation).

Safety: read-only by default. No resource creation, mutation, model invocation,
or trail enabling happens unless the matching explicit flag is passed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_ACTIVITY_DAYS,
    DEFAULT_REGION,
    ScanConfig,
    parse_regions,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="AWS AI discovery agent and AI system registry (read-only POC).",
    )
    parser.add_argument(
        "--profile", default=None,
        help="AWS profile name (default: AWS_PROFILE env or default credential chain)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("identity", help="Verify AWS identity via STS GetCallerIdentity")

    p_scan = sub.add_parser("scan", help="Run read-only AI resource discovery")
    p_scan.add_argument("--regions", default=DEFAULT_REGION,
                        help="Comma separated Regions (default: %(default)s)")
    p_scan.add_argument("--activity-days", type=int, default=DEFAULT_ACTIVITY_DAYS,
                        help="CloudTrail observation window in days (default: %(default)s)")
    p_scan.add_argument("--services", default=None,
                        help="Comma separated adapter names (default: all). "
                             "Available: bedrock,sagemaker,tags,glue,application")
    p_scan.add_argument("--report-dir", default="reports")
    p_scan.add_argument("--no-merge", action="store_true",
                        help="Do not merge with a previous reports/inventory.json")
    p_scan.add_argument("--skip-activity", action="store_true",
                        help="Skip CloudTrail activity evidence collection")

    p_val = sub.add_parser("validate", help="Validate inventory against the schema")
    p_val.add_argument("--report-dir", default="reports")
    p_val.add_argument("--inventory", default=None, help="Path to inventory file")

    p_rep = sub.add_parser("report", help="Generate a Markdown scan report")
    p_rep.add_argument("--report-dir", default="reports")

    p_fix = sub.add_parser(
        "test-fixtures",
        help="Run offline discovery/classification tests with synthetic AWS responses",
    )
    p_fix.add_argument("--report-dir", default="reports")

    p_live = sub.add_parser(
        "test-live",
        help="Run live AWS tests (read-only unless cost flags are also given)",
    )
    p_live.add_argument("--enable-live-tests", action="store_true",
                        help="Required opt-in for any live test execution")
    p_live.add_argument("--enable-model-invocation", action="store_true",
                        help="Second opt-in required for cost-incurring model calls "
                             "(Test B). Never enabled by default.")
    p_live.add_argument("--regions", default=DEFAULT_REGION)
    p_live.add_argument("--report-dir", default="reports")
    return parser


def _config_from_args(args: argparse.Namespace, **overrides: Any) -> ScanConfig:
    kwargs: dict[str, Any] = {
        "profile": args.profile,
        "report_dir": getattr(args, "report_dir", "reports"),
    }
    if hasattr(args, "regions"):
        kwargs["regions"] = parse_regions(args.regions)
    kwargs.update(overrides)
    return ScanConfig(**kwargs)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_identity(args: argparse.Namespace) -> int:
    from .aws_identity import format_identity, get_identity

    config = _config_from_args(args)
    result = get_identity(config)
    print(format_identity(result))
    if not result.success:
        print("\nFix authentication before running scans "
              "(aws configure / aws sso login). No secrets are printed by this tool.")
        return 2
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .governance import analyze_gaps
    from .registry import (
        load_previous_inventory,
        merge_with_previous,
        records_from_document,
        refresh_scan_counts,
    )
    from .reporting import (
        validate_inventory,
        write_evidence,
        write_markdown_report,
        write_reports,
        write_validation_report,
    )
    from .scanner import build_scan_metadata, run_scan

    services = [s.strip() for s in args.services.split(",")] if args.services else None
    activity_days = 0 if args.skip_activity else args.activity_days
    config = _config_from_args(args, services=services, activity_days=activity_days)

    print(f"Scan {config.scan_id}")
    print(f"  regions : {', '.join(config.regions)}")
    print(f"  window  : {activity_days} days" if activity_days else "  window  : activity evidence disabled")
    print(f"  profile : {config.profile or '(default chain)'}")
    print("  mode    : read-only\n")

    result = run_scan(config, progress=lambda m: print(f"  · {m}"))
    document = result.registry.to_document(
        build_scan_metadata(result),
        [e.as_dict() for e in result.errors],
        [c.as_dict() for c in result.coverage],
    )

    if not args.no_merge:
        previous = load_previous_inventory(Path(config.report_dir) / "inventory.json")
        if previous:
            document = merge_with_previous(document, previous)
            document["scan"]["merged_with_previous"] = True
            print("  · merged with previous inventory (stable record IDs)")

    # The inventory may now hold more records than this scan discovered, so
    # the summary counters and the governance gaps must be derived from the
    # merged document rather than from the fresh scan's registry alone.
    refresh_scan_counts(document)
    validation_errors = validate_inventory(document)
    gaps = analyze_gaps(records_from_document(document))
    paths = write_reports(document, config, gaps=gaps)
    write_evidence([e.as_dict() for e in result.events], config)
    write_validation_report(document, config, validation_errors)
    write_markdown_report(document, gaps, config)

    print(f"\nRecords: {document['scan']['records_total']}  "
          f"Resources: {document['scan']['resources_discovered']}  "
          f"Errors: {document['scan']['error_count']}")
    print(f"Classifications: {json.dumps(document['scan']['classification_counts'])}")
    print(f"Schema valid: {'yes' if not validation_errors else 'NO — see schema_validation.json'}")
    for path in paths.values():
        print(f"  wrote {path}")
    if validation_errors:
        for err in validation_errors[:5]:
            print(f"  SCHEMA ERROR: {err}", file=sys.stderr)
        return 3
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from .reporting import validate_inventory, write_validation_report

    config = _config_from_args(args)
    inventory_path = Path(args.inventory) if args.inventory else Path(args.report_dir) / "inventory.json"
    if not inventory_path.exists():
        print(f"ERROR: {inventory_path} not found. Run `python -m src.cli scan` first.")
        return 2
    document = json.loads(inventory_path.read_text())
    errors = validate_inventory(document)
    write_validation_report(document, config, errors)
    if errors:
        print(f"INVALID: {len(errors)} schema error(s) in {inventory_path}")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"VALID: {inventory_path} conforms to inventory.schema.json "
          f"(schema_version {document.get('schema_version')})")
    print(f"  records: {len(document.get('records', []))}  "
          f"errors: {len(document.get('errors', []))}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .governance import analyze_gaps
    from .registry import records_from_document, refresh_scan_counts
    from .reporting import write_markdown_report

    config = _config_from_args(args)
    report_dir = Path(args.report_dir)
    inventory_path = report_dir / "inventory.json"
    if not inventory_path.exists():
        print(f"ERROR: {inventory_path} not found. Run `python -m src.cli scan` first.")
        return 2
    document = json.loads(inventory_path.read_text())
    # Derive the counters from the records actually present so the rendered
    # report can never disagree with the inventory it describes.
    refresh_scan_counts(document)
    gaps = analyze_gaps(records_from_document(document))
    test_results = None
    tr_path = report_dir / "test_results.json"
    if tr_path.exists():
        try:
            test_results = json.loads(tr_path.read_text())
        except json.JSONDecodeError:
            test_results = None
    path = write_markdown_report(document, gaps, config, test_results)
    print(f"Wrote {path}")
    return 0


def cmd_test_fixtures(args: argparse.Namespace) -> int:
    from .offline import run_offline_suite

    config = _config_from_args(args)
    results = run_offline_suite(config)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skipped")
    payload = {
        "suite": "offline_fixtures",
        "generated_at": results[0].timestamp if results else None,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "scenarios": [r.as_dict() for r in results],
    }
    out = Path(config.report_dir) / "test_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if out.exists():
        try:
            existing = json.loads(out.read_text())
        except json.JSONDecodeError:
            existing = {}
    existing_offline = payload
    existing.update({"offline": existing_offline})
    if "total" not in existing:
        existing.update({"total": len(results), "passed": passed, "failed": failed, "skipped": skipped})
    else:
        # Recompute totals as offline + live blocks.
        offline = existing.get("offline", {})
        live = existing.get("live")
        existing["total"] = offline.get("total", 0) + (live or {}).get("total", 0)
        existing["passed"] = offline.get("passed", 0) + (live or {}).get("passed", 0)
        existing["failed"] = offline.get("failed", 0) + (live or {}).get("failed", 0)
        existing["skipped"] = offline.get("skipped", 0) + (live or {}).get("skipped", 0)
    out.write_text(json.dumps(existing, indent=2, default=str))

    print(f"\nOffline fixture suite: {passed} passed, {failed} failed, {skipped} skipped "
          f"(of {len(results)})")
    for r in results:
        marker = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP"}[r.status]
        print(f"  [{marker}] {r.name}: {r.actual}")
    print(f"\nWrote {out}")
    return 0 if failed == 0 else 1


def cmd_test_live(args: argparse.Namespace) -> int:
    from .live_tests import run_live_suite

    if not args.enable_live_tests:
        print("Live tests are disabled by default.")
        print("Re-run with --enable-live-tests to execute read-only live checks.")
        print("Cost-incurring checks additionally require --enable-model-invocation.")
        return 2

    config = _config_from_args(
        args,
        regions=parse_regions(args.regions),
        enable_live_tests=True,
        enable_model_invocation=args.enable_model_invocation,
    )
    results = run_live_suite(config)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skipped")

    out = Path(config.report_dir) / "test_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {}
    if out.exists():
        try:
            payload = json.loads(out.read_text())
        except json.JSONDecodeError:
            payload = {}
    payload["live"] = {
        "suite": "live",
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "scenarios": [r.as_dict() for r in results],
    }
    offline = payload.get("offline", {})
    payload["total"] = offline.get("total", 0) + len(results)
    payload["passed"] = offline.get("passed", 0) + passed
    payload["failed"] = offline.get("failed", 0) + failed
    payload["skipped"] = offline.get("skipped", 0) + skipped
    out.write_text(json.dumps(payload, indent=2, default=str))

    print(f"\nLive suite: {passed} passed, {failed} failed, {skipped} skipped")
    for r in results:
        marker = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP"}[r.status]
        print(f"  [{marker}] {r.name}: {r.actual}")
    print(f"\nWrote {out}")
    return 0 if failed == 0 else 1


COMMANDS = {
    "identity": cmd_identity,
    "scan": cmd_scan,
    "validate": cmd_validate,
    "report": cmd_report,
    "test-fixtures": cmd_test_fixtures,
    "test-live": cmd_test_live,
}


def main(argv: list[str] | None = None) -> int:
    import logging

    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.getLogger("ai_discovery").setLevel(getattr(logging, args.log_level))
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

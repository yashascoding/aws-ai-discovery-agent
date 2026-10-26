"""Report generation: inventory, summary, errors, evidence, gaps, markdown.

Artifacts (all under the configured report directory, git-ignored):
- inventory.json            complete structured inventory (schema validated)
- inventory.csv             tabular inventory (one row per record)
- summary.json              scan statistics
- scan_errors.json          permission failures and partial-scan errors
- governance_gaps.json      missing governance fields + follow-up actions
- evidence/cloudtrail-events.json  sanitized activity evidence (metadata only)
- report.md                 readable Markdown summary
- test_results.json         test/acceptance results (written by the test runner)
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .config import ScanConfig, utcnow
from .registry import SCHEMA_VERSION, Registry

SCHEMA_PATH = Path(__file__).parent / "schemas" / "inventory.schema.json"


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_inventory(document: dict[str, Any]) -> list[str]:
    """Validate an inventory document against the JSON Schema.

    Returns a list of error strings; empty list means valid.
    """
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema package is not installed; cannot validate"]

    schema = json.loads(SCHEMA_PATH.read_text())
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    messages = []
    for err in errors[:50]:
        path = "/" + "/".join(str(p) for p in err.absolute_path)
        messages.append(f"{path}: {err.message}")
    return messages


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
CSV_COLUMNS = [
    "record_id",
    "classification",
    "usage_status",
    "confidence",
    "aws_service",
    "resource_type",
    "resource_kind",
    "resource_name",
    "ai_system_name",
    "aws_account_id",
    "aws_region",
    "resource_arn",
    "model_provider",
    "foundation_model_id",
    "technology_category",
    "creation_time",
    "last_modified_time",
    "last_observed_activity_time",
    "last_successful_invocation_time",
    "invocation_count_in_window",
    "calling_principal",
    "system_owner",
    "business_owner",
    "intended_purpose",
    "deployment_environment",
    "data_classification",
    "personal_data_involved",
    "human_review_status",
    "missing_metadata_fields",
    "evidence_ids",
    "detection_method",
    "record_version",
    "first_seen_scan",
    "last_seen_scan",
    "usage_measurement_count",
    "reported_cost_total",
    "finding_count",
]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str, ensure_ascii=False))


def write_reports(
    document: dict[str, Any],
    config: ScanConfig,
    *,
    gaps: dict[str, Any] | None = None,
    extra_errors: list[dict[str, Any]] | None = None,
) -> dict[str, Path]:
    """Write all report artifacts; returns {artifact_name: path}."""
    report_dir = Path(config.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = report_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}

    inventory_path = report_dir / "inventory.json"
    inventory_path.write_text(json.dumps(document, indent=2, default=str, ensure_ascii=False))
    paths["inventory.json"] = inventory_path

    # CSV
    csv_path = report_dir / "inventory.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for record in document.get("records", []):
            row = dict(record)
            row["confidence"] = record.get("classification_confidence")
            row["missing_metadata_fields"] = "; ".join(
                record.get("missing_metadata_fields", [])
            )
            row["evidence_ids"] = "; ".join(
                e.get("evidence_id", "") for e in record.get("evidence", [])
            )
            row["detection_method"] = "; ".join(record.get("detection_method", []))
            row["usage_measurement_count"] = len(record.get("usage_measurements", []))
            row["reported_cost_total"] = round(
                sum(float(c.get("amount") or 0) for c in record.get("cost_records", [])), 6
            )
            row["finding_count"] = len(record.get("findings", []))
            writer.writerow(row)
    paths["inventory.csv"] = csv_path

    # Summary
    summary = {
        "generated_at": utcnow().isoformat(),
        "schema_version": SCHEMA_VERSION,
        **document.get("scan", {}),
        "coverage": document.get("coverage", []),
        "artifact_files": sorted(p.name for p in report_dir.glob("*") if p.is_file()),
    }
    summary_path = report_dir / "summary.json"
    _write_json(summary_path, summary)
    paths["summary.json"] = summary_path

    # Errors
    errors_path = report_dir / "scan_errors.json"
    _write_json(
        errors_path,
        {
            "generated_at": utcnow().isoformat(),
            "scan_id": config.scan_id,
            "error_count": len(document.get("errors", [])),
            "interpretation_note": (
                "An access_denied error means discovery could not establish "
                "whether resources exist; it must NOT be read as absence of "
                "resources."
            ),
            "errors": document.get("errors", []),
        },
    )
    paths["scan_errors.json"] = errors_path

    # Governance gaps
    if gaps is not None:
        gaps_path = report_dir / "governance_gaps.json"
        _write_json(gaps_path, gaps)
        paths["governance_gaps.json"] = gaps_path

    # Usage, cost, findings, and coverage artifacts. These are always written so
    # downstream consumers never have to guess whether collection was disabled.
    usage = document.get("usage_measurements", [])
    usage_path = report_dir / "usage_measurements.json"
    _write_json(usage_path, {
        "generated_at": utcnow().isoformat(),
        "scan_id": config.scan_id,
        "measurement_count": len(usage),
        "interpretation_note": (
            "A missing metric or datapoint is not zero usage. Service-scoped "
            "measurements are never attributed to a specific resource."
        ),
        "measurements": usage,
    })
    paths["usage_measurements.json"] = usage_path

    usage_csv = report_dir / "usage_measurements.csv"
    with usage_csv.open("w", newline="", encoding="utf-8") as fh:
        fields = [
            "measurement_id", "service", "namespace", "metric_name", "statistic",
            "scope", "resource_id", "datapoint_count", "total", "average",
            "maximum", "latest_value", "latest_timestamp", "collection_status",
            "attribution_confidence",
        ]
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for measurement in usage:
            writer.writerow(measurement)
    paths["usage_measurements.csv"] = usage_csv

    costs = document.get("cost_records", [])
    cost_summary = (document.get("scan", {}).get("cost_collection") or {})
    cost_path = report_dir / "costs.json"
    _write_json(cost_path, {
        "generated_at": utcnow().isoformat(),
        "scan_id": config.scan_id,
        **cost_summary,
        "record_count": len(costs),
        "records": costs,
    })
    paths["costs.json"] = cost_path

    costs_csv = report_dir / "costs.csv"
    with costs_csv.open("w", newline="", encoding="utf-8") as fh:
        fields = [
            "cost_record_id", "source", "period_start", "period_end", "service_name",
            "category", "region", "usage_type", "amount", "currency", "record_type",
            "estimated", "attribution_confidence", "resource_id", "limitation",
        ]
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(costs)
    paths["costs.csv"] = costs_csv

    findings = document.get("findings", [])
    findings_path = report_dir / "findings.json"
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        counts[severity] = counts.get(severity, 0) + 1
    _write_json(findings_path, {
        "generated_at": utcnow().isoformat(),
        "scan_id": config.scan_id,
        "finding_count": len(findings),
        "severity_counts": counts,
        "interpretation_note": (
            "Findings are advisory and evidence-bound. A missing telemetry finding "
            "means usage could not be measured; it does not mean zero usage."
        ),
        "findings": findings,
    })
    paths["findings.json"] = findings_path

    findings_csv = report_dir / "findings.csv"
    with findings_csv.open("w", newline="", encoding="utf-8") as fh:
        fields = [
            "finding_id", "finding_type", "severity", "title", "service", "region",
            "resource_id", "capability_keys", "confidence", "recommendation",
        ]
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            row["capability_keys"] = "; ".join(finding.get("capability_keys", []))
            writer.writerow(row)
    paths["findings.csv"] = findings_csv

    capabilities = document.get("capabilities", [])
    status_counts: dict[str, int] = {}
    for cap in capabilities:
        status = cap.get("discovery_status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    coverage_path = report_dir / "coverage_report.json"
    _write_json(coverage_path, {
        "generated_at": utcnow().isoformat(),
        "scan_id": config.scan_id,
        "capability_count": len(capabilities),
        "discovery_status_counts": status_counts,
        "scorecard": [
            {
                "service": cap.get("display_name"),
                "key": cap.get("key"),
                "category": cap.get("category"),
                "discovery": cap.get("discovery_status"),
                "usage": cap.get("usage_status"),
                "billing": cap.get("billing_status"),
                "reason": cap.get("status_reason"),
            }
            for cap in capabilities
        ],
    })
    paths["coverage_report.json"] = coverage_path

    coverage_csv = report_dir / "coverage_report.csv"
    with coverage_csv.open("w", newline="", encoding="utf-8") as fh:
        fields = [
            "key", "display_name", "category", "adapter", "discovery_status",
            "usage_status", "billing_status", "resource_count",
            "usage_measurement_count", "cost_record_count", "reported_cost",
            "status_reason",
        ]
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(capabilities)
    paths["coverage_report.csv"] = coverage_csv

    # Evidence (sanitized)
    evidence_events = (config.report_dir + "/evidence/cloudtrail-events.json")
    evidence_path = Path(evidence_events)
    paths["evidence/cloudtrail-events.json"] = evidence_path
    return paths


def write_evidence(events: list[dict[str, Any]], config: ScanConfig) -> Path:
    evidence_dir = Path(config.report_dir) / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / "cloudtrail-events.json"
    _write_json(
        path,
        {
            "generated_at": utcnow().isoformat(),
            "observation_window_days": config.activity_days,
            "sanitization": (
                "Metadata only: event ids, names, times, callers, and target "
                "identifiers. Prompt bodies, model outputs, and request payloads "
                "are never stored."
            ),
            "event_count": len(events),
            "events": events,
        },
    )
    return path


def write_validation_report(
    document: dict[str, Any], config: ScanConfig, errors: list[str]
) -> Path:
    path = Path(config.report_dir) / "schema_validation.json"
    _write_json(
        path,
        {
            "validated_at": utcnow().isoformat(),
            "schema": str(SCHEMA_PATH.name),
            "valid": not errors,
            "error_count": len(errors),
            "errors": errors,
        },
    )
    return path


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #
def render_markdown_report(
    document: dict[str, Any],
    gaps: dict[str, Any],
    test_results: dict[str, Any] | None = None,
) -> str:
    scan = document.get("scan", {})
    records = document.get("records", [])
    counts = scan.get("classification_counts", {})
    usage = scan.get("usage_status_counts", {})

    lines: list[str] = []
    lines.append("# AWS AI Discovery — Scan Report")
    lines.append("")
    lines.append(f"- **Scan ID:** `{scan.get('scan_id')}`")
    lines.append(f"- **Generated:** {scan.get('finished_at') or utcnow().isoformat()}")
    lines.append(f"- **Account:** `{scan.get('account_id')}`")
    lines.append(f"- **Caller:** `{scan.get('caller_arn')}`")
    lines.append(f"- **Regions requested:** {', '.join(scan.get('regions_requested', []))}")
    lines.append(f"- **Regions scanned:** {', '.join(scan.get('regions_scanned', [])) or 'none'}")
    lines.append(f"- **Duration:** {scan.get('duration_seconds')}s (read-only)")
    lines.append(f"- **Observation window:** {scan.get('observation_window', {}).get('activity_days')} days")
    lines.append("")

    lines.append("## Discovery summary")
    lines.append("")
    lines.append(f"- Resources discovered: **{scan.get('resources_discovered')}**")
    lines.append(f"- Registry records: **{scan.get('records_total')}**")
    lines.append(
        f"- Activity events (CloudTrail): **{scan.get('activity_evidence_events')}**"
    )
    lines.append(f"- Errors / blocked operations: **{scan.get('error_count')}**")
    lines.append("")
    lines.append("| Classification | Records |")
    lines.append("|---|---|")
    for key in (
        "CONFIRMED_AI_ACTIVITY",
        "CONFIGURED_AI_RESOURCE",
        "POTENTIAL_AI_USAGE",
        "INACTIVE_OR_STALE",
        "UNKNOWN",
    ):
        lines.append(f"| {key} | {counts.get(key, 0)} |")
    lines.append("")
    lines.append("| Usage status | Records |")
    lines.append("|---|---|")
    for key, value in sorted(usage.items()):
        lines.append(f"| {key} | {value} |")
    lines.append("")

    # Highlighted records (non-catalogue).
    notable = [
        r
        for r in records
        if r.get("resource_kind") != "catalog"
        and r.get("classification") != "UNKNOWN"
    ]
    notable.sort(key=lambda r: (r.get("classification") != "CONFIRMED_AI_ACTIVITY", r.get("record_id", "")))
    lines.append("## AI registry highlights (catalogue entries excluded)")
    lines.append("")
    if not notable:
        lines.append("_No account-specific AI resources or activity evidence in this scan._")
        lines.append("")
    else:
        lines.append("| Record | Classification | Usage | Type | Evidence |")
        lines.append("|---|---|---|---|---|")
        for r in notable[:25]:
            evidence_bits = [
                e.get("evidence_id", "")[:14] for e in (r.get("evidence") or [])[:2]
            ]
            lines.append(
                f"| `{r.get('record_id')}` {r.get('resource_name') or ''} "
                f"| {r.get('classification')} | {r.get('usage_status')} "
                f"| {r.get('resource_type')} | {', '.join(evidence_bits) or '—'} |"
            )
        lines.append("")

    # Usage / cost / findings coverage
    caps = document.get("capabilities", [])
    if caps:
        lines.append("## Collection coverage")
        lines.append("")
        lines.append("| Service | Category | Discovery | Usage | Billing | Reason |")
        lines.append("|---|---|---|---|---|---|")
        for cap in caps[:60]:
            reason = (cap.get("status_reason") or "—").replace("|", "\\|")[:90]
            lines.append(
                f"| {cap.get('display_name')} | {cap.get('category')} "
                f"| {cap.get('discovery_status')} | {cap.get('usage_status')} "
                f"| {cap.get('billing_status')} | {reason} |"
            )
        if len(caps) > 60:
            lines.append("")
            lines.append(f"_... {len(caps) - 60} more in `coverage_report.json`._")
        lines.append("")

    usage = document.get("usage_measurements", [])
    costs = document.get("cost_records", [])
    findings = document.get("findings", [])
    if usage or costs or findings:
        lines.append("## Usage, cost, and findings")
        lines.append("")
        usage_summary = scan.get("usage_collection", {}) or {}
        cost_summary = scan.get("cost_collection", {}) or {}
        lines.append(f"- CloudWatch status: **{usage_summary.get('status')}** "
                     f"({usage_summary.get('measurement_count', len(usage))} measurements)")
        if usage_summary.get("reason"):
            lines.append(f"- Usage note: {usage_summary.get('reason')}")
        lines.append(f"- Cost status: **{cost_summary.get('status')}** "
                     f"({cost_summary.get('record_count', len(costs))} records)")
        if cost_summary.get("reason"):
            lines.append(f"- Cost note: {cost_summary.get('reason')}")
        if cost_summary.get("mapped_reported_amount") is not None:
            lines.append(
                f"- Positive reported mapped cost: **{cost_summary.get('currency')} "
                f"{cost_summary.get('mapped_reported_amount')}**; unattributed portion: "
                f"**{cost_summary.get('unattributed_reported_amount')}**"
            )
        if cost_summary.get("data_through"):
            lines.append(f"- Billing data through: **{cost_summary.get('data_through')}**")
        lines.append(f"- Findings: **{len(findings)}**")
        lines.append("")
        if findings:
            lines.append("| Severity | Finding | Service | Resource |")
            lines.append("|---|---|---|---|")
            for finding in findings[:20]:
                title = str(finding.get("title", "")).replace("|", "\\|")[:90]
                lines.append(
                    f"| {finding.get('severity')} | {title} | {finding.get('service') or '—'} "
                    f"| {finding.get('resource_id') or '—'} |"
                )
            if len(findings) > 20:
                lines.append("")
                lines.append(f"_... {len(findings) - 20} more in `findings.json`._")
            lines.append("")

    lines.append("## Governance gaps (ISO/IEC 42001-oriented)")
    lines.append("")
    lines.append(f"- Records analyzed: **{gaps.get('records_analyzed')}**")
    excluded = gaps.get("catalog_records_excluded", 0)
    if excluded:
        lines.append(
            f"- Catalogue entries excluded from per-record gaps: **{excluded}** "
            "(AWS-provided availability, not organizational AI systems)"
        )
    relevant = max((gaps.get("records_analyzed") or 0) - excluded, 0)
    lines.append(f"- Account-specific AI records assessed: **{relevant}**")
    lines.append(
        f"- Fully documented records: **{gaps.get('records_fully_documented')}**"
    )
    lines.append(f"- Pending human review: **{gaps.get('records_pending_review')}**")
    pc = gaps.get("priority_counts", {})
    lines.append(
        f"- Gap priorities — high: **{pc.get('high', 0)}**, "
        f"medium: **{pc.get('medium', 0)}**, low: **{pc.get('low', 0)}**"
    )
    if relevant == 0:
        lines.append("")
        lines.append(
            "_No account-specific AI resources were discovered in this scan, so "
            "there are no governance gaps to report. Re-run after deploying or "
            "invoking AI resources, or broaden `--regions`._"
        )
    lines.append("")
    fc = gaps.get("field_completeness", {})
    worst = sorted(
        (v for v in fc.values() if isinstance(v, dict)),
        key=lambda v: v.get("coverage_pct", 100),
    )[:8]
    if worst and relevant > 0:
        lines.append("| Governance field | Coverage | Missing |")
        lines.append("|---|---|---|")
        for item in worst:
            lines.append(
                f"| {item.get('label')} | {item.get('coverage_pct')}% | {item.get('missing')} |"
            )
        lines.append("")

    lines.append("## Errors and coverage limitations")
    lines.append("")
    errors = document.get("errors", [])
    if not errors:
        lines.append("_No API errors recorded in this scan._")
        lines.append("")
    else:
        lines.append("| Service | Operation | Region | Type | Message |")
        lines.append("|---|---|---|---|---|")
        for err in errors[:30]:
            msg = str(err.get("message", "")).replace("|", "\\|")[:120]
            lines.append(
                f"| {err.get('service')} | {err.get('operation')} | "
                f"{err.get('region') or '—'} | {err.get('error_type')} | {msg} |"
            )
        if len(errors) > 30:
            lines.append("")
            lines.append(f"_... {len(errors) - 30} more in `scan_errors.json`._")
        lines.append("")
    lines.append(
        "> Access-denied errors mean the scan could not establish whether "
        "resources exist — not that they are absent."
    )
    lines.append("")

    if test_results:
        lines.append("## Test results")
        lines.append("")
        lines.append(
            f"- Total: **{test_results.get('total')}**, "
            f"passed: **{test_results.get('passed')}**, "
            f"failed: **{test_results.get('failed')}**, "
            f"skipped: **{test_results.get('skipped')}**"
        )
        lines.append("")

    lines.append("## Scope and limitations")
    lines.append("")
    lines.append(
        "- Bedrock foundation-model listings are catalogue metadata "
        "(availability), not usage."
    )
    lines.append(
        "- CloudTrail Event History covers 90 days; invocation data events "
        "must be operator-enabled, so absence of events is not proof of non-use."
    )
    lines.append(
        "- CloudWatch metrics may be disabled, delayed, or available only at "
        "service level; missing datapoints are reported as such, never as zero."
    )
    lines.append(
        "- Cost Explorer reports billed cost at service/Region level. Amounts "
        "are not allocated to individual resources unless a resource-level "
        "billing identifier was present."
    )
    lines.append(
        "- Findings, including idle and low-utilization candidates, are advisory "
        "and require owner validation before remediation."
    )
    lines.append(
        "- This report supports AI inventory/governance activities relevant to "
        "ISO/IEC 42001 but does not assert compliance or certification."
    )
    lines.append(
        "- Catalogue entries with no activity evidence are classified "
        "UNKNOWN by design (never as organizational AI usage)."
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(
    document: dict[str, Any],
    gaps: dict[str, Any],
    config: ScanConfig,
    test_results: dict[str, Any] | None = None,
) -> Path:
    path = Path(config.report_dir) / "report.md"
    path.write_text(render_markdown_report(document, gaps, test_results))
    return path

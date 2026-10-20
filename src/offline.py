"""Offline test suite: full discovery pipeline against synthetic AWS fixtures.

Runs the REAL adapters, registry, classification, and schema validation with
zero AWS calls. Every artifact is written under reports/offline/ and every
scenario records setup, expected vs actual results, evidence location, and
limitations. Nothing here is a live AWS result and is never presented as one.

Scenarios covered (mapping to the test plan):
  A  AI model catalogue (no activity)      -> catalog is never "in use"
  D  Application-level AI association      -> lambda config inference
  E  Ownership/governance tag metadata     -> tags captured + gaps found
  F  Negative control                      -> ordinary resources not flagged
  G  Missing permissions                   -> scan continues, errors recorded
  H  Duplicate/failed/historical events    -> dedupe, window, success vs fail
  I  Multi-Region + pagination             -> no duplicates, coverage report
  J  Empty environment                     -> valid schema-compliant reports
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import ScanConfig, new_scan_id, utcnow
from .governance import analyze_gaps
from .registry import RegistryRecord, make_record_id
from .reporting import validate_inventory
from .scanner import build_scan_metadata, run_scan
from .testkit import (
    default_fixture_map,
    empty_fixture_map,
    fixture_session,
    access_denied,
)


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    setup: str
    command: str
    expected: str
    actual: str
    status: str  # pass | fail | skipped
    evidence: str = ""
    limitations: str = ""
    timestamp: str = field(default_factory=lambda: utcnow().isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "setup": self.setup,
            "command": self.command,
            "expected": self.expected,
            "actual": self.actual,
            "status": self.status,
            "evidence": self.evidence,
            "limitations": self.limitations,
            "timestamp": self.timestamp,
        }


def _config(
    report_dir: str,
    regions: list[str],
    activity_days: int,
    services: list[str] | None = None,
) -> ScanConfig:
    return ScanConfig(
        profile="synthetic-fixtures",
        regions=regions,
        activity_days=activity_days,
        report_dir=report_dir,
        scan_id=new_scan_id(),
        services=services,
    )


def _run(
    config: ScanConfig,
    fixture_map: dict[str, dict[str, Any]] | None = None,
    errors: dict[tuple[str, str], Exception] | None = None,
    paginated: dict[str, set[str]] | None = None,
) -> tuple[dict[str, Any], list[RegistryRecord]]:
    def factory(_config: ScanConfig):
        return fixture_session(fixture_map, errors=errors, paginated=paginated)

    result = run_scan(config, session_factory=factory)
    document = result.registry.to_document(
        build_scan_metadata(result),
        [e.as_dict() for e in result.errors],
        [c.as_dict() for c in result.coverage],
    )
    return document, list(result.registry.records)


def _save(doc: dict[str, Any], report_dir: str, scenario_id: str) -> str:
    out = Path(report_dir) / f"scenario_{scenario_id}_inventory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, default=str))
    return str(out)


def _record(doc: dict[str, Any], **criteria: str) -> dict[str, Any] | None:
    for rec in doc.get("records", []):
        if all(rec.get(k) == v for k, v in criteria.items()):
            return rec
    return None


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
def scenario_a_catalogue(report_dir: str) -> ScenarioResult:
    """Test A: catalogue metadata collected; availability != usage."""
    cfg = _config(report_dir, ["ap-south-1"], activity_days=0)
    doc, _ = _run(cfg)
    evidence = _save(doc, report_dir, "A")
    catalog = [r for r in doc["records"] if r.get("resource_kind") == "catalog"]
    wrongly_active = [
        r for r in catalog
        if r.get("classification") != "UNKNOWN" or r.get("usage_status") != "unknown"
    ]
    confirmed_any = [
        r for r in doc["records"] if r.get("classification") == "CONFIRMED_AI_ACTIVITY"
    ]
    # Regression guard: AWS-managed (system-defined) inference profiles are
    # catalogue availability, while application-created ones are account
    # resources that must stay in the organizational inventory.
    system_profile = [
        r for r in catalog if r.get("resource_type") == "bedrock_inference_profile"
    ]
    app_profiles = [
        r for r in doc["records"]
        if r.get("resource_type") == "bedrock_inference_profile"
        and r.get("resource_kind") != "catalog"
    ]
    system_profile_ok = bool(system_profile) and bool(app_profiles)
    schema_errors = validate_inventory(doc)
    ok = (
        len(catalog) >= 3
        and not wrongly_active
        and not confirmed_any
        and system_profile_ok
        and not schema_errors
    )
    return ScenarioResult(
        scenario_id="A",
        name="AI model catalogue",
        setup="Synthetic Bedrock catalogue (3 foundation models + 1 system-defined inference profile), activity evidence disabled",
        command="python -m src.cli test-fixtures",
        expected=(
            ">=3 catalogue entries collected; every catalogue record classified "
            "UNKNOWN/unknown (never as organizational AI usage); system-defined "
            "inference profiles catalogue-only while application profiles remain "
            "account resources; schema valid"
        ),
        actual=(
            f"catalog_records={len(catalog)}, wrongly_active={len(wrongly_active)}, "
            f"confirmed={len(confirmed_any)}, system_profile_catalog={len(system_profile)}, "
            f"app_profiles={len(app_profiles)}, schema_errors={len(schema_errors)}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations="Synthetic catalogue; live catalogue contents vary by Region/account.",
    )


def scenario_d_lambda_association(report_dir: str) -> ScenarioResult:
    """Test D: inferred application association vs direct evidence."""
    cfg = _config(report_dir, ["ap-south-1"], activity_days=0)
    doc, _ = _run(cfg)
    evidence = _save(doc, report_dir, "D")
    ai_fn = _record(doc, resource_name="claims-summarizer")
    plain_fn = _record(doc, resource_name="image-resizer")
    ok = bool(
        ai_fn
        and ai_fn.get("classification") == "POTENTIAL_AI_USAGE"
        and "static_configuration_association" in (ai_fn.get("detection_method") or [])
        and plain_fn is None
    )
    actual = (
        f"ai_fn={ai_fn.get('classification') if ai_fn else None}, "
        f"ai_fn_methods={ai_fn.get('detection_method') if ai_fn else None}, "
        f"plain_fn_present={plain_fn is not None}"
    )
    return ScenarioResult(
        scenario_id="D",
        name="Application-level AI association",
        setup=(
            "Synthetic Lambda fixtures: claims-summarizer has BEDROCK_MODEL_ID "
            "env key; image-resizer has no AI indicators"
        ),
        command="python -m src.cli test-fixtures",
        expected=(
            "AI-keyed function -> POTENTIAL_AI_USAGE from static configuration; "
            "ordinary function absent from registry"
        ),
        actual=actual,
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations=(
            "Static configuration is never runtime proof; keyword coverage is "
            "documented in src/discovery/application.py."
        ),
    )


def scenario_e_governance_tags(report_dir: str) -> ScenarioResult:
    """Test E: governance tags captured; missing ownership/purpose identified."""
    cfg = _config(report_dir, ["ap-south-1"], activity_days=0)
    doc, records = _run(cfg)
    evidence = _save(doc, report_dir, "E")
    endpoint = _record(doc, resource_name="fraud-scoring-endpoint")
    gaps = analyze_gaps(records)
    gap = next(
        (g for g in gaps["gaps"] if g["record_id"] == (endpoint or {}).get("record_id")),
        None,
    )
    ok = bool(
        endpoint
        and endpoint.get("tags", {}).get("AI-System") == "Claims Fraud Scoring"
        and endpoint.get("intended_purpose") == "Score insurance claims for fraud risk"
        and endpoint.get("system_owner") == "risk-analytics@corp.example"
        and endpoint.get("data_classification") == "confidential"
        and "data_categories" in (endpoint.get("missing_metadata_fields") or [])
        and gap is not None
        and gap["missing_fields"]
    )
    actual = (
        f"tags={len(endpoint.get('tags', {})) if endpoint else 0}, "
        f"purpose={bool(endpoint and endpoint.get('intended_purpose'))}, "
        f"owner={endpoint.get('system_owner') if endpoint else None}, "
        f"missing={len(gap['missing_fields']) if gap else 'n/a'}"
    )
    gaps_path = Path(report_dir) / "scenario_E_governance_gaps.json"
    gaps_path.write_text(json.dumps(gaps, indent=2, default=str))
    return ScenarioResult(
        scenario_id="E",
        name="Ownership and governance metadata",
        setup=(
            "Synthetic tags AI-System/Owner/BusinessPurpose/DataClassification "
            "on the SageMaker endpoint fixture"
        ),
        command="python -m src.cli test-fixtures",
        expected=(
            "Tags populate registry governance fields; remaining unknown fields "
            "reported as governance gaps with follow-up actions"
        ),
        actual=actual,
        status="pass" if ok else "fail",
        evidence=f"{evidence}; {gaps_path}",
        limitations="Tag values are human-asserted claims, not verified facts.",
    )


def scenario_f_negative_control(report_dir: str) -> ScenarioResult:
    """Test F: ordinary resources are not classified as AI systems."""
    cfg = _config(report_dir, ["ap-south-1"], activity_days=0)
    doc, _ = _run(cfg)
    evidence = _save(doc, report_dir, "F")
    confirmed = [r for r in doc["records"] if r.get("classification") == "CONFIRMED_AI_ACTIVITY"]
    configured_lambda = [
        r for r in doc["records"]
        if r.get("resource_type") == "lambda_function"
        and r.get("classification") in {"CONFIRMED_AI_ACTIVITY", "CONFIGURED_AI_RESOURCE"}
    ]
    untagged_s3 = [
        r for r in doc["records"]
        if r.get("aws_service") == "s3" and "AI-System" not in (r.get("tags") or {})
    ]
    plain_fn = _record(doc, resource_name="image-resizer")
    ok = not confirmed and not configured_lambda and not untagged_s3 and plain_fn is None
    return ScenarioResult(
        scenario_id="F",
        name="Negative control",
        setup="Ordinary Lambda (image-resizer) + no-activity scan + non-AI tagged resources",
        command="python -m src.cli test-fixtures",
        expected=(
            "No CONFIRMED classifications without activity; ordinary resources "
            "absent or UNKNOWN, never AI-confirmed/configured"
        ),
        actual=(
            f"confirmed={len(confirmed)}, configured_lambda={len(configured_lambda)}, "
            f"untagged_s3={len(untagged_s3)}, plain_fn_present={plain_fn is not None}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations="Keyword rules can produce false positives/negatives in real code.",
    )


def scenario_g_missing_permissions(report_dir: str) -> ScenarioResult:
    """Test G: AccessDenied on Bedrock; scan continues and records errors."""
    regions = ["ap-south-1"]
    errors = {
        ("bedrock", r): access_denied("ListFoundationModels") for r in regions
    }
    errors.update(
        {("bedrock-agent", r): access_denied("ListAgents", "bedrock-agent") for r in regions}
    )
    cfg = _config(report_dir, regions, activity_days=0)
    doc, _ = _run(cfg, errors=errors)
    evidence = _save(doc, report_dir, "G")
    denied = [
        e for e in doc["errors"]
        if e.get("error_type") == "access_denied"
    ]
    sagemaker_records = [r for r in doc["records"] if r.get("aws_service") == "sagemaker"]
    bedrock_records = [r for r in doc["records"] if r.get("aws_service", "").startswith("bedrock")]
    coverage = doc.get("coverage", [])
    bedrock_blocked = any(
        "bedrock" in (c.get("services_failed") or []) or
        any("bedrock" in (n or "") for n in (c.get("notes") or []))
        for c in coverage
    )
    ok = bool(denied and sagemaker_records and not bedrock_records and bedrock_blocked)
    return ScenarioResult(
        scenario_id="G",
        name="Missing permissions",
        setup="Bedrock/bedrock-agent clients raise AccessDeniedException; SageMaker allowed",
        command="python -m src.cli test-fixtures",
        expected=(
            "Scan completes with partial results; access_denied errors recorded; "
            "SageMaker resources still discovered; blocked Bedrock NOT reported as empty"
        ),
        actual=(
            f"access_denied_errors={len(denied)}, sagemaker_records={len(sagemaker_records)}, "
            f"bedrock_records={len(bedrock_records)}, bedrock_blocked_in_coverage={bedrock_blocked}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations=(
            "Simulated denial via fixtures; live denial messages vary by policy "
            "and resource-level permissions."
        ),
    )


def scenario_h_activity_events(report_dir: str) -> ScenarioResult:
    """Test H: dedupe, window filtering, failed vs successful invocations."""
    cfg = _config(report_dir, ["ap-south-1"], activity_days=30)
    doc, records = _run(cfg)
    evidence = _save(doc, report_dir, "H")
    scan = doc["scan"]
    event_count = scan.get("activity_evidence_events", 0)
    event_ids = {
        e.get("event_id")
        for r in doc["records"]
        for e in []  # ids live on records; use evidence file instead
    }
    claude = next(
        (r for r in doc["records"] if r.get("foundation_model_id", "") and "claude-haiku" in r.get("foundation_model_id", "")),
        None,
    )
    endpoint = _record(doc, resource_name="fraud-scoring-endpoint")
    train = _record(doc, resource_name="fraud-model-train-001")
    old_present = False
    for rec in records:
        for ts in (rec.last_invocation_time, rec.last_observed_activity_time):
            if ts and "T" in str(ts):
                try:
                    if (datetime.now(timezone.utc) - datetime.fromisoformat(str(ts))).days > 90:
                        old_present = True
                except ValueError:
                    pass
    ok = bool(
        event_count == 3  # duplicate collapsed, old event outside window
        and claude
        and claude.get("classification") == "CONFIRMED_AI_ACTIVITY"
        and claude.get("usage_status") == "confirmed"
        and endpoint
        and endpoint.get("classification") == "CONFIRMED_AI_ACTIVITY"
        and endpoint.get("usage_status") == "configured_but_unverified"
        and train
        and train.get("creator_or_last_actor") == "arn:aws:iam::111122223333:role/MLOpsPipelineRole"
        and not old_present
    )
    return ScenarioResult(
        scenario_id="H",
        name="Duplicate, failed, and historical events",
        setup=(
            "Synthetic CloudTrail events: duplicate InvokeModel id, failed "
            "InvokeEndpoint, CreateTrainingJob management event, 120-day-old event"
        ),
        command="python -m src.cli test-fixtures",
        expected=(
            "3 events after dedupe+window (5 wrappers - 1 duplicate - 1 old); "
            "successful invoke -> confirmed; failed-only -> attempted-not-verified; "
            "creator captured from management event; no stale-timestamp records"
        ),
        actual=(
            f"events={event_count}, claude={claude.get('classification') if claude else None}"
            f"/{claude.get('usage_status') if claude else None}, "
            f"endpoint={endpoint.get('classification') if endpoint else None}"
            f"/{endpoint.get('usage_status') if endpoint else None}, "
            f"creator={train.get('creator_or_last_actor') if train else None}, "
            f"old_present={old_present}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations=(
            "CloudTrail Event History is 90-day, throttled, and excludes "
            "operator-disabled data events; ingestion delay applies."
        ),
    )


def scenario_i_multi_region_pagination(report_dir: str) -> ScenarioResult:
    """Test I: multiple Regions + paginated responses without duplicates."""
    regions = ["ap-south-1", "us-east-1"]
    cfg = _config(report_dir, regions, activity_days=0)
    doc, records = _run(
        cfg,
        paginated={"sagemaker": {"list_models", "list_endpoints"}},
    )
    evidence = _save(doc, report_dir, "I")
    ids = [r.get("record_id") for r in doc["records"]]
    names = {r.get("resource_name") for r in doc["records"]}
    coverage = doc.get("coverage", [])
    scanned = [c.get("region") for c in coverage if c.get("status") == "scanned"]
    ok = bool(
        len(ids) == len(set(ids))
        and "fraud-detection-model" in names
        and "churn-predictor" in names
        and set(regions) == set(scanned)
    )
    return ScenarioResult(
        scenario_id="I",
        name="Multi-Region and pagination",
        setup="Two Regions; SageMaker list_models served as 2 paginated pages",
        command="python -m src.cli test-fixtures",
        expected=(
            "Models from both pages discovered; both Regions scanned; no duplicate "
            "record IDs; coverage lists both Regions as scanned"
        ),
        actual=(
            f"records={len(ids)}, unique_ids={len(set(ids))}, "
            f"both_pages={'fraud-detection-model' in names and 'churn-predictor' in names}, "
            f"scanned={sorted(scanned)}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations=(
            "Region availability and service enablement differ per account; "
            "unscanned Regions are reported as errors, never as empty."
        ),
    )


def scenario_j_empty_environment(report_dir: str) -> ScenarioResult:
    """Test J: zero resources still yields valid, schema-compliant reports."""
    regions = ["ap-south-1", "us-east-1"]
    cfg = _config(report_dir, regions, activity_days=30)
    doc, _ = _run(cfg, fixture_map=empty_fixture_map())
    evidence = _save(doc, report_dir, "J")
    schema_errors = validate_inventory(doc)
    scan = doc["scan"]
    ok = bool(
        not schema_errors
        and scan.get("records_total") == 0
        and scan.get("error_count") == 0
        and set(regions).issubset(set(scan.get("regions_scanned", [])))
    )
    return ScenarioResult(
        scenario_id="J",
        name="Empty environment",
        setup="All synthetic APIs succeed with zero resources and zero events",
        command="python -m src.cli test-fixtures",
        expected=(
            "Inventory with 0 records, 0 errors, schema-valid, both Regions scanned"
        ),
        actual=(
            f"records={scan.get('records_total')}, errors={scan.get('error_count')}, "
            f"schema_errors={len(schema_errors)}, scanned={scan.get('regions_scanned')}"
        ),
        status="pass" if ok else "fail",
        evidence=evidence,
        limitations="Empty results can also occur from over-restrictive IAM (see scenario G).",
    )


SCENARIOS: list[Callable[[str], ScenarioResult]] = [
    scenario_a_catalogue,
    scenario_d_lambda_association,
    scenario_e_governance_tags,
    scenario_f_negative_control,
    scenario_g_missing_permissions,
    scenario_h_activity_events,
    scenario_i_multi_region_pagination,
    scenario_j_empty_environment,
]


def run_offline_suite(config: ScanConfig) -> list[ScenarioResult]:
    report_dir = str(Path(config.report_dir) / "offline")
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    results: list[ScenarioResult] = []
    for scenario in SCENARIOS:
        try:
            results.append(scenario(report_dir))
        except Exception as exc:  # noqa: BLE001 - report, never crash the suite
            results.append(
                ScenarioResult(
                    scenario_id=getattr(scenario, "__name__", "unknown"),
                    name=getattr(scenario, "__name__", "unknown"),
                    setup="error during scenario execution",
                    command="python -m src.cli test-fixtures",
                    expected="scenario executes",
                    actual=f"{type(exc).__name__}: {exc}",
                    status="fail",
                    evidence="",
                    limitations="",
                )
            )
    return results

"""Live test suite: explicitly opt-in, read-only by default.

Safety rules enforced here:
- Runs only when --enable-live-tests is passed.
- Uses read-only API calls (list/describe/get-caller-identity).
- Test B (model invocation) additionally requires --enable-model-invocation
  AND is still skipped by default: it must be approved per run.
- Test C (SageMaker resource creation) and Test E mutation (tagging a test
  resource) are NEVER executed automatically: they would create/modify AWS
  resources or incur cost. They stay documented as skipped.

Skipped scenarios are recorded with reasons — never silently dropped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .aws_identity import create_session, get_identity
from .config import ScanConfig, utcnow
from .discovery import ADAPTERS
from .errors import classify_exception, error_message
from .scanner import build_scan_metadata, run_scan


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    setup: str
    command: str
    expected: str
    actual: str
    status: str
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


def _save(document: dict[str, Any], report_dir: str, scenario_id: str) -> str:
    out = Path(report_dir) / f"scenario_{scenario_id}_inventory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, default=str))
    return str(out)


def _read_only_scan(config: ScanConfig) -> dict[str, Any]:
    result = run_scan(config)
    document = result.registry.to_document(
        build_scan_metadata(result),
        [e.as_dict() for e in result.errors],
        [c.as_dict() for c in result.coverage],
    )
    _save(document, config.report_dir, "LIVE")
    return document


def scenario_live_identity(config: ScanConfig) -> ScenarioResult:
    identity = get_identity(config)
    ok = identity.success and bool(identity.account_id)
    return ScenarioResult(
        scenario_id="LIVE-IDENT",
        name="Live STS identity verification",
        setup=f"profile={config.profile}, region={config.regions[0]}",
        command="python -m src.cli test-live --enable-live-tests",
        expected="GetCallerIdentity succeeds; account id and ARN returned",
        actual=(
            f"account={identity.account_id}, arn={identity.caller_arn}, "
            f"error={identity.error}"
        ),
        status="pass" if ok else "fail",
        evidence="reports/test_results.json",
        limitations="Requires valid local AWS credentials; no secrets are printed.",
    )


def scenario_live_a_catalogue(config: ScanConfig) -> ScenarioResult:
    """Test A (live): real Bedrock catalogue in the configured Region."""
    doc = _read_only_scan(config)
    catalog = [
        r for r in doc["records"]
        if r.get("resource_kind") == "catalog"
        and r.get("aws_region") == config.regions[0]
    ]
    wrongly_active = [
        r for r in catalog
        if r.get("classification") != "UNKNOWN"
    ]
    bedrock_denied = any(
        e.get("service") == "bedrock" and e.get("error_type") == "access_denied"
        for e in doc["errors"]
    )
    if bedrock_denied and not catalog:
        status = "fail"
        actual = "Bedrock ListFoundationModels denied; catalogue not collected"
    elif not catalog and doc["errors"]:
        status = "fail"
        actual = f"no catalogue entries; errors={len(doc['errors'])}"
    else:
        status = "pass" if not wrongly_active else "fail"
        actual = (
            f"catalog_records={len(catalog)}, wrongly_active={len(wrongly_active)}, "
            f"errors_in_scan={doc['scan'].get('error_count')}"
        )
    return ScenarioResult(
        scenario_id="LIVE-A",
        name="Live AI model catalogue",
        setup=f"Real Bedrock ListFoundationModels in {config.regions[0]} (read-only)",
        command="python -m src.cli test-live --enable-live-tests",
        expected="Catalogue entries collected; none classified as organizational AI usage",
        actual=actual,
        status=status,
        evidence="reports/scenario_LIVE_inventory.json",
        limitations=(
            "Catalogue contents depend on Region and model-access status; "
            "Live results depend on the account's Region and model access."
        ),
    )


def scenario_live_d_lambda_association(config: ScanConfig) -> ScenarioResult:
    """Test D (live): Lambda AI association scan (read-only)."""
    scan_config = ScanConfig(
        profile=config.profile,
        regions=config.regions,
        activity_days=0,
        report_dir=config.report_dir,
        services=["application"],
    )
    doc = _read_only_scan(scan_config)
    lambda_records = [r for r in doc["records"] if r.get("aws_service") == "lambda"]
    inferred = [
        r for r in lambda_records if r.get("classification") == "POTENTIAL_AI_USAGE"
    ]
    wrong_confirmed = [
        r for r in lambda_records
        if r.get("classification") == "CONFIRMED_AI_ACTIVITY"
    ]
    denied = any(
        e.get("service") == "lambda" and e.get("error_type") == "access_denied"
        for e in doc["errors"]
    )
    status = "fail" if wrong_confirmed else ("pass" if not denied else "fail")
    return ScenarioResult(
        scenario_id="LIVE-D",
        name="Live application-level AI association",
        setup=f"Lambda ListFunctions in {config.regions[0]} (read-only, no code inspection)",
        command="python -m src.cli test-live --enable-live-tests",
        expected=(
            "AI-associated Lambdas -> POTENTIAL_AI_USAGE only; no Lambda classified "
            "as CONFIRMED without CloudTrail evidence"
        ),
        actual=(
            f"lambda_records={len(lambda_records)}, potential={len(inferred)}, "
            f"wrongly_confirmed={len(wrong_confirmed)}, denied={denied}"
        ),
        status=status,
        evidence="reports/scenario_LIVE_inventory.json",
        limitations="Keyword-based association can miss obfuscated AI usage.",
    )


def scenario_live_f_negative_control(config: ScanConfig) -> ScenarioResult:
    """Test F (live): no activity events => nothing classified CONFIRMED."""
    scan_config = ScanConfig(
        profile=config.profile,
        regions=config.regions,
        activity_days=0,
        report_dir=config.report_dir,
    )
    doc = _read_only_scan(scan_config)
    confirmed = [r for r in doc["records"] if r.get("classification") == "CONFIRMED_AI_ACTIVITY"]
    status = "pass" if not confirmed else "fail"
    return ScenarioResult(
        scenario_id="LIVE-F",
        name="Live negative control",
        setup="Full read-only scan with activity evidence disabled",
        command="python -m src.cli test-live --enable-live-tests",
        expected="Zero CONFIRMED_AI_ACTIVITY records when no activity evidence is collected",
        actual=f"confirmed={len(confirmed)} of {doc['scan'].get('records_total')} records",
        status=status,
        evidence="reports/scenario_LIVE_inventory.json",
        limitations="Only validates classification without evidence, not with partial evidence.",
    )


def scenario_live_i_multi_region(config: ScanConfig) -> ScenarioResult:
    """Test I (live): multi-Region read-only coverage (if >1 Region configured)."""
    if len(config.regions) < 2:
        return ScenarioResult(
            scenario_id="LIVE-I",
            name="Live multi-Region coverage",
            setup=f"regions configured: {config.regions}",
            command="python -m src.cli test-live --enable-live-tests --regions ap-south-1,us-east-1",
            expected=">=2 Regions configured for a multi-Region coverage check",
            actual=f"only {len(config.regions)} region(s) configured; scenario not applicable",
            status="skipped",
            evidence="reports/test_results.json",
            limitations="Re-run with --regions listing at least two enabled Regions.",
        )
    doc = _read_only_scan(config)
    ids = [r.get("record_id") for r in doc["records"]]
    scanned = [c.get("region") for c in doc.get("coverage", []) if c.get("status") == "scanned"]
    ok = len(ids) == len(set(ids)) and set(scanned) == set(config.regions)
    return ScenarioResult(
        scenario_id="LIVE-I",
        name="Live multi-Region coverage",
        setup=f"Read-only scan across {', '.join(config.regions)}",
        command="python -m src.cli test-live --enable-live-tests --regions <r1>,<r2>",
        expected="All configured Regions scanned (or reported as errors); no duplicate record IDs",
        actual=f"records={len(ids)}, unique={len(set(ids))}, scanned={sorted(scanned)}",
        status="pass" if ok else "fail",
        evidence="reports/scenario_LIVE_inventory.json",
        limitations="Regions where services are unavailable appear in errors, not as empty results.",
    )


def scenario_skipped_b_model_invocation(config: ScanConfig) -> ScenarioResult:
    if config.enable_model_invocation:
        return ScenarioResult(
            scenario_id="LIVE-B",
            name="Actual Bedrock inference",
            setup="--enable-model-invocation passed",
            command="python -m src.cli test-live --enable-live-tests --enable-model-invocation",
            expected="one minimal, harmless InvokeModel; metadata only recorded",
            actual="NOT IMPLEMENTED FOR AUTOMATION: invocation is cost-incurring and "
                   "must be performed and reviewed by the operator manually",
            status="skipped",
            evidence="reports/test_results.json",
            limitations="Model access, cost, and prompt/response handling require explicit human control.",
        )
    return ScenarioResult(
        scenario_id="LIVE-B",
        name="Actual Bedrock inference",
        setup="no invocation flags",
        command="python -m src.cli test-live --enable-live-tests --enable-model-invocation",
        expected="skipped unless second explicit opt-in is provided",
        actual="skipped: --enable-model-invocation not passed (cost/consent gate)",
        status="skipped",
        evidence="reports/test_results.json",
        limitations="Prompt/response content is never stored by design.",
    )


def scenario_skipped_c_sagemaker_resource(config: ScanConfig) -> ScenarioResult:
    return ScenarioResult(
        scenario_id="LIVE-C",
        name="SageMaker test resource",
        setup="no resource creation is ever performed by this tool",
        command="n/a (manual approval required)",
        expected="create or reuse the smallest practical non-production SageMaker resource",
        actual="skipped: automatic resource creation prohibited by safety rules",
        status="skipped",
        evidence="reports/test_results.json",
        limitations="Real-time endpoints cost money; use manual approval + cleanup script.",
    )


def scenario_skipped_e_tag_mutation(config: ScanConfig) -> ScenarioResult:
    return ScenarioResult(
        scenario_id="LIVE-E",
        name="Ownership tags on a test resource (mutation)",
        setup="tagging requires write permissions and an approved test resource",
        command="n/a (manual approval required)",
        expected="tags written to an approved test resource then discovered",
        actual="skipped: write operation requires an operator-approved test resource",
        status="skipped",
        evidence="reports/test_results.json",
        limitations="Live write-path validation requires operator-approved resources.",
    )


def scenario_live_g_permission_report(config: ScanConfig) -> ScenarioResult:
    """Test G (live): report permission gaps observed during the live scan."""
    scan_config = ScanConfig(
        profile=config.profile,
        regions=config.regions,
        activity_days=config.activity_days,
        report_dir=config.report_dir,
    )
    doc = _read_only_scan(scan_config)
    denied = [e for e in doc["errors"] if e.get("error_type") == "access_denied"]
    unsupported = [e for e in doc["errors"] if e.get("error_type") == "unsupported"]
    # The pass criterion is honest reporting, not absence of errors.
    note_present = doc["scan"].get("error_count") == len(doc["errors"])
    return ScenarioResult(
        scenario_id="LIVE-G",
        name="Live permission/error visibility",
        setup="full live scan; access denied and unsupported ops must be visible",
        command="python -m src.cli test-live --enable-live-tests",
        expected=(
            "AccessDenied/unsupported errors enumerated per service+Region; "
            "scan completes; blocked results never reported as empty"
        ),
        actual=(
            f"access_denied={len(denied)}, unsupported={len(unsupported)}, "
            f"total_errors={doc['scan'].get('error_count')}, "
            f"records={doc['scan'].get('records_total')}"
        ),
        status="pass" if note_present else "fail",
        evidence="reports/scan_errors.json",
        limitations="Error visibility depends on which APIs the identity can reach.",
    )


def run_live_suite(config: ScanConfig) -> list[ScenarioResult]:
    results: list[ScenarioResult] = []
    checks = [
        scenario_live_identity,
        scenario_live_a_catalogue,
        scenario_live_d_lambda_association,
        scenario_live_f_negative_control,
        scenario_live_g_permission_report,
        scenario_live_i_multi_region,
        scenario_skipped_b_model_invocation,
        scenario_skipped_c_sagemaker_resource,
        scenario_skipped_e_tag_mutation,
    ]
    for check in checks:
        try:
            results.append(check(config))
        except Exception as exc:  # noqa: BLE001 - record failures honestly
            results.append(
                ScenarioResult(
                    scenario_id=check.__name__,
                    name=check.__name__,
                    setup="live scenario execution",
                    command="python -m src.cli test-live --enable-live-tests",
                    expected="scenario executes",
                    actual=f"{type(exc).__name__}: {error_message(exc)}",
                    status="fail",
                    evidence="",
                    limitations="",
                )
            )
    return results

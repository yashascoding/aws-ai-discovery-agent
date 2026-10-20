"""End-to-end offline scan, schema validation, reporting, governance, CLI."""
import json
from pathlib import Path

import pytest

from src.cli import main
from src.config import ScanConfig
from src.governance import analyze_gaps
from src.offline import run_offline_suite, scenario_h_activity_events
from src.reporting import (
    render_markdown_report,
    validate_inventory,
    write_evidence,
    write_reports,
)
from src.registry import RegistryRecord
from src.scanner import build_scan_metadata, run_scan
from src.testkit import fixture_session


@pytest.fixture
def offline_scan(tmp_path: Path):
    config = ScanConfig(
        profile="synthetic",
        regions=["ap-south-1"],
        activity_days=30,
        report_dir=str(tmp_path / "reports"),
        scan_id="scan-test",
    )

    def factory(_cfg):
        return fixture_session()

    result = run_scan(config, session_factory=factory)
    document = result.registry.to_document(
        build_scan_metadata(result),
        [e.as_dict() for e in result.errors],
        [c.as_dict() for c in result.coverage],
    )
    return config, result, document


# --------------------------------------------------------------------------- #
def test_full_scan_produces_valid_schema_document(offline_scan):
    _config, _result, document = offline_scan
    errors = validate_inventory(document)
    assert errors == [], errors
    assert document["scan"]["records_total"] > 0
    assert document["scan"]["read_only"] is True
    assert document["scan"]["account_id"] == "111122223333"


def test_scan_distinguishes_activity_from_existence(offline_scan):
    _config, _result, document = offline_scan
    by_name = {r["resource_name"]: r for r in document["records"]}
    # Confirmed: direct successful invocation evidence.
    claude = next(
        r for r in document["records"]
        if r.get("foundation_model_id", "") and "claude-haiku" in r.get("foundation_model_id", "")
    )
    assert claude["classification"] == "CONFIRMED_AI_ACTIVITY"
    assert claude["cloudtrail_event_ids"]
    # Configured: exists, no invocation evidence.
    churn = by_name["churn-predictor"]
    assert churn["classification"] == "CONFIGURED_AI_RESOURCE"
    assert churn["usage_status"] == "configured_but_unverified"
    # Unknown: catalogue availability only (titan embed never invoked).
    titan = by_name["Titan Text Embeddings V2"]
    assert titan["classification"] == "UNKNOWN"
    assert titan["resource_kind"] == "catalog"


def test_scan_records_governance_fields_and_gaps(offline_scan):
    config, result, document = offline_scan
    endpoint = next(
        r for r in document["records"] if r["resource_name"] == "fraud-scoring-endpoint"
    )
    assert endpoint["intended_purpose"]
    assert endpoint["system_owner"]
    assert "data_categories" in endpoint["missing_metadata_fields"]
    assert endpoint["human_review_status"] == "pending"
    gaps = analyze_gaps(result.registry.records)
    assert gaps["priority_counts"]["high"] >= 1  # confirmed-activity record needs docs
    assert gaps["field_completeness"]["data_categories"]["missing"] >= 1


def test_error_records_preserve_provenance_and_interpretation(offline_scan):
    config, result, document = offline_scan
    assert document["scan"]["error_count"] == len(document["errors"])
    for err in document["errors"]:
        assert {"service", "operation", "error_type", "message"} <= set(err)


def test_write_reports_emits_all_artifacts(offline_scan, tmp_path):
    config, result, document = offline_scan
    from src.governance import analyze_gaps

    gaps = analyze_gaps(result.registry.records)
    paths = write_reports(document, config, gaps=gaps)
    write_evidence([e.as_dict() for e in result.events], config)
    for name in (
        "inventory.json", "inventory.csv", "summary.json",
        "scan_errors.json", "governance_gaps.json",
    ):
        assert paths[name].exists(), name
    evidence = Path(config.report_dir) / "evidence" / "cloudtrail-events.json"
    assert evidence.exists()
    payload = json.loads(evidence.read_text())
    dumped = json.dumps(payload)
    # Sanitization note may mention prompt bodies; actual prompt-like payloads must not appear.
    assert "PROMPT-CONTENT" not in dumped
    assert "prompt bodies" in payload["sanitization"].lower()
    csv_header = paths["inventory.csv"].read_text().splitlines()[0]
    assert "record_id" in csv_header and "classification" in csv_header
    assert validate_inventory(json.loads(paths["inventory.json"].read_text())) == []


def test_markdown_report_renders_with_key_sections(offline_scan):
    config, result, document = offline_scan
    from src.governance import analyze_gaps

    gaps = analyze_gaps(result.registry.records)
    md = render_markdown_report(document, gaps)
    assert "# AWS AI Discovery — Scan Report" in md
    assert "CONFIRMED_AI_ACTIVITY" in md
    assert "Governance gaps" in md
    assert "ISO/IEC 42001" in md
    assert "not assert compliance or certification" in md or "does not assert" in md


def test_offline_suite_all_scenarios_pass(tmp_path: Path):
    config = ScanConfig(profile="synthetic", regions=["ap-south-1"],
                        report_dir=str(tmp_path / "reports"))
    results = run_offline_suite(config)
    failures = [r for r in results if r.status == "fail"]
    assert len(results) == 8
    assert not failures, [f.as_dict() for f in failures]


def test_cli_validate_and_report_commands(tmp_path: Path):
    report_dir = tmp_path / "reports"
    report_dir.mkdir(parents=True)
    scenario = scenario_h_activity_events(str(tmp_path / "offline"))
    assert scenario.status == "pass"
    inventory = tmp_path / "offline" / "scenario_H_inventory.json"
    report_dir.joinpath("inventory.json").write_text(inventory.read_text())

    assert main(["validate", "--report-dir", str(report_dir)]) == 0
    assert main(["report", "--report-dir", str(report_dir)]) == 0
    assert (report_dir / "report.md").exists()
    assert (report_dir / "schema_validation.json").exists()


def test_cli_validate_fails_on_invalid_document(tmp_path: Path):
    report_dir = tmp_path / "reports"
    report_dir.mkdir(parents=True)
    report_dir.joinpath("inventory.json").write_text(json.dumps({"schema_version": "9.9.9"}))
    assert main(["validate", "--report-dir", str(report_dir)]) == 1


def test_cli_test_live_requires_explicit_opt_in(tmp_path: Path):
    assert main(["test-live", "--report-dir", str(tmp_path)]) == 2

"""Usage, cost, findings, capability, and infrastructure coverage tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.capabilities import build_capability_registry, finalize_capabilities
from src.classification import AI_ASSOCIATED_RESOURCE_TYPES, classify_record
from src.config import ScanConfig
from src.costs import collect_costs
from src.discovery.infrastructure import EC2Adapter
from src.errors import OperationError
from src.findings import generate_findings
from src.registry import RegistryRecord
from src.usage import collect_usage
from tests.testkit import _empty_collection_operations, access_denied, fixture_session


def _config(**kw):
    return ScanConfig(profile="synthetic", regions=["ap-south-1"], **kw)


def _record(**kw):
    defaults = dict(
        record_id="air-" + "b" * 16,
        aws_service="bedrock",
        resource_type="bedrock_guardrail",
        aws_region="ap-south-1",
        resource_id="guardrail-1",
    )
    defaults.update(kw)
    return RegistryRecord(**defaults)


def _caps(*keys):
    return [c for c in build_capability_registry() if c.key in keys]


def _usage_session(values, status="Complete"):
    fmap = _empty_collection_operations()
    fmap["cloudwatch"] = {"operations": {
        "list_metrics": [{"Metrics": [{
            "Namespace": "AWS/SageMaker",
            "MetricName": "Invocations",
            "Dimensions": [{"Name": "EndpointName", "Value": "claims-endpoint"}],
        }]}],
        "get_metric_data": [{"MetricDataResults": [{
            "Id": "m0",
            "StatusCode": status,
            "Values": values,
            "Timestamps": [
                (datetime.now(timezone.utc) - timedelta(hours=i)).isoformat()
                for i in range(len(values))
            ],
        }]}],
    }}
    return fixture_session(fmap)


def test_usage_measurement_matches_resource_dimension_and_sums_invocations():
    cap = _caps("sagemaker")
    record = _record(
        aws_service="sagemaker", resource_type="sagemaker_endpoint",
        resource_id="claims-endpoint", resource_name="claims-endpoint",
        sagemaker_endpoint_name="claims-endpoint",
    )
    errors: list[OperationError] = []
    result = collect_usage(
        _usage_session([5.0, 7.0]), "ap-south-1", [record], cap, _config(), errors,
    )
    assert result.status == "collected"
    assert errors == []
    assert len(result.measurements) == 1
    m = result.measurements[0]
    assert m.resource_record_id == record.record_id
    assert m.scope == "resource"
    assert m.attribution_confidence == "resource_dimension_match"
    assert m.statistic == "Sum"
    assert m.datapoint_count == 2
    assert m.total == 12.0
    assert m.latest_value == 5.0


def test_usage_without_datapoints_is_not_reported_as_zero():
    cap = _caps("sagemaker")
    record = _record(
        aws_service="sagemaker", resource_type="sagemaker_endpoint",
        resource_id="claims-endpoint", resource_name="claims-endpoint",
        sagemaker_endpoint_name="claims-endpoint",
    )
    result = collect_usage(
        _usage_session([], status="Complete"), "ap-south-1", [record], cap, _config(), [],
    )
    m = result.measurements[0]
    assert m.collection_status == "no_datapoints"
    assert m.total is None
    assert "not evidence of zero usage" in (m.limitation or "")


def test_usage_access_denied_is_permission_denied_not_zero():
    fmap = _empty_collection_operations()
    session = fixture_session(fmap, errors={("cloudwatch", "ap-south-1"): access_denied("ListMetrics", "cloudwatch")})
    errors: list[OperationError] = []
    result = collect_usage(session, "ap-south-1", [], _caps("sagemaker"), _config(), errors)
    assert result.status == "permission_denied"
    assert result.measurements == []
    assert errors and errors[0].error_type == "access_denied"


def test_cost_explorer_keeps_service_level_cost_out_of_resources():
    fmap = _empty_collection_operations()
    fmap["ce"] = {"operations": {"get_cost_and_usage": [{
        "ResultsByTime": [{
            "TimePeriod": {"Start": "2026-10-20", "End": "2026-10-21"},
            "Estimated": False,
            "Groups": [
                {"Keys": ["Amazon Bedrock", "ap-south-1"], "Metrics": {
                    "UnblendedCost": {"Amount": "1.25", "Unit": "USD"},
                    "UsageQuantity": {"Amount": "10", "Unit": "Units"},
                }},
                {"Keys": ["Amazon EC2", "ap-south-1"], "Metrics": {
                    "UnblendedCost": {"Amount": "99.00", "Unit": "USD"},
                }},
                {"Keys": ["Amazon Bedrock", "us-east-1"], "Metrics": {
                    "UnblendedCost": {"Amount": "0", "Unit": "USD"},
                }},
            ],
        }],
    }]}}
    result = collect_costs(
        fixture_session(fmap), _config(cost_lookback_days=30), _caps("bedrock"), [], [],
    )
    assert result.status == "collected"
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.service_name == "Amazon Bedrock"
    assert rec.amount == 1.25
    assert rec.capability_keys == ["bedrock"]
    assert rec.category == "managed_ai"
    assert rec.resource_record_id is None
    assert rec.attribution_confidence == "service_level"
    assert rec.data_through == "2026-10-21"


def test_cost_explorer_denied_is_visible_and_not_estimated():
    session = fixture_session(
        _empty_collection_operations(),
        errors={("ce", "us-east-1"): access_denied("GetCostAndUsage", "ce")},
    )
    errors: list[OperationError] = []
    result = collect_costs(
        session, _config(cost_region="us-east-1"), _caps("bedrock"), [], errors,
    )
    assert result.status == "permission_denied"
    assert result.records == []
    assert errors


def test_findings_bind_governance_waste_and_unattributed_cost_to_evidence():
    cap = _caps("bedrock")[0]
    cap.discovery_status = "supported"
    cap.usage_status = "supported"
    record = _record(resource_type="bedrock_provisioned_throughput", resource_id="pt-1")
    from src.usage import UsageMeasurement
    from src.costs import CostRecord

    usage = [UsageMeasurement(
        measurement_id="um-1", source="cloudwatch", service="bedrock",
        capability_keys=["bedrock"], namespace="AWS/Bedrock", metric_name="Invocations",
        statistic="Sum", scope="resource", resource_record_id=record.record_id,
        resource_id=record.resource_id, datapoint_count=3, total=0.0,
        start_time="2026-10-01T00:00:00Z", end_time="2026-10-20T00:00:00Z",
    )]
    costs = [CostRecord(
        cost_record_id="cost-1", source="cost_explorer", period_start="2026-10-20",
        period_end="2026-10-21", granularity="DAILY", service_name="Amazon Bedrock",
        capability_keys=["bedrock"], category="managed_ai", region="ap-south-1",
        amount=5.0, currency="USD",
    )]
    findings = generate_findings(
        records=[record], usage_measurements=usage, cost_records=costs,
        capabilities=[cap], config=_config(),
    )
    types = {f.finding_type for f in findings}
    assert {"missing_governance_ownership", "missing_intended_purpose",
            "idle_paid_runtime_candidate", "unattributed_ai_cost"} <= types
    for f in findings:
        assert f.evidence_refs
        assert f.confidence in {"low", "medium", "high"}


def test_capability_registry_is_complete_and_finalization_is_honest():
    caps = build_capability_registry()
    assert len(caps) == 55
    assert len({c.key for c in caps}) == 55
    assert {c.category for c in caps} == {"managed_ai", "ai_infrastructure", "supporting_ai"}
    bedrock = next(c for c in caps if c.key == "bedrock")
    bedrock.discovery_status = "supported"
    bedrock.usage_status = "supported"
    out = finalize_capabilities(
        [bedrock], records=[_record()], usage_measurements=[], cost_records=[],
        observed_at="2026-10-20T00:00:00Z",
    )[0]
    assert bedrock.resource_count == 1
    assert out["usage_status"] == "partial"
    assert "not evidence of zero usage" in out["status_reason"]


def test_association_prefixes_do_not_treat_plain_infrastructure_as_ai_native():
    assert "ec2_instance" in AI_ASSOCIATED_RESOURCE_TYPES
    associated = _record(aws_service="ec2", resource_type="ec2_instance")
    plain = _record(aws_service="s3", resource_type="s3_resource")
    assert classify_record(associated, []).classification == "CONFIGURED_AI_RESOURCE"
    assert classify_record(plain, []).classification == "UNKNOWN"


def test_ec2_adapter_registers_only_evidence_backed_instances():
    fmap = _empty_collection_operations()
    fmap["ec2"] = {"operations": {
        "describe_instances": [{"Reservations": [{"Instances": [
            {"InstanceId": "i-gpu", "InstanceType": "p4d.24xlarge",
             "Tags": [{"Key": "Name", "Value": "training-box"}],
             "State": {"Name": "running"}, "LaunchTime": "2026-10-01T00:00:00Z"},
            {"InstanceId": "i-named", "InstanceType": "m5.large",
             "Tags": [{"Key": "Name", "Value": "llm-api"}]},
            {"InstanceId": "i-plain", "InstanceType": "m5.large",
             "Tags": [{"Key": "Name", "Value": "web"}]},
        ]}]}],
        "describe_instance_types": [{"InstanceTypes": [{
            "InstanceType": "p4d.24xlarge",
            "GpuInfo": {"Gpus": [{"Count": 8, "Manufacturer": "NVIDIA", "Name": "A100"}]},
            "VCpuInfo": {"DefaultVCpus": 96},
        }]}],
    }}
    result = EC2Adapter(_config()).discover(fixture_session(fmap), "ap-south-1")
    by_id = {r.resource_id: r for r in result.resources}
    assert set(by_id) == {"i-gpu", "i-named"}
    assert by_id["i-gpu"].ai_association["basis"] == "accelerated_compute"
    assert by_id["i-gpu"].ai_association["confidence"] == "medium"
    assert by_id["i-gpu"].metadata["gpu_count"] == 8
    assert by_id["i-named"].ai_association["confidence"] == "low"
    assert by_id["i-named"].ai_association["note"].startswith("Static infrastructure evidence only")


def test_scan_with_usage_and_cost_disabled_still_reports_coverage():
    from src.scanner import run_scan

    config = _config(
        activity_days=30,
        enable_usage_collection=False,
        enable_cost_collection=False,
    )
    result = run_scan(config, session_factory=lambda _cfg: fixture_session())
    assert len(result.capabilities) == 55
    assert result.usage_collection is not None
    assert result.usage_collection.status == "not_configured"
    assert result.usage_measurements == []
    assert result.cost_collection is not None
    assert result.cost_collection.status == "not_configured"
    assert result.cost_records == []
    assert result.findings

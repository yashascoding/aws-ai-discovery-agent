"""Evidence-bound governance, waste, telemetry, and cost findings.

Findings are advisory. They never assert that a resource is unused when the
relevant telemetry was unavailable. Every finding names the evidence used and
the limitation that prevents a stronger conclusion.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .capabilities import ServiceCapability
from .config import ScanConfig, utcnow
from .costs import CostRecord
from .registry import RegistryRecord
from .usage import UsageMeasurement

PAID_RUNTIME_TYPES = {
    "sagemaker_endpoint", "bedrock_provisioned_throughput", "bedrock_inference_profile",
    "ec2_instance", "eks_cluster", "ecs_service",
}
OWNER_FIELDS = ("system_owner", "business_owner", "technical_owner")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    service: str | None = None
    region: str | None = None
    resource_record_id: str | None = None
    resource_id: str | None = None
    capability_keys: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    confidence: str = "medium"
    recommendation: str | None = None
    detected_at: str = field(default_factory=lambda: utcnow().isoformat())
    status: str = "open"

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "service": self.service,
            "region": self.region,
            "resource_record_id": self.resource_record_id,
            "resource_id": self.resource_id,
            "capability_keys": self.capability_keys,
            "evidence_refs": self.evidence_refs,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "detected_at": self.detected_at,
            "status": self.status,
        }


def _fid(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return "fnd-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _finding(*, finding_type: str, severity: str, title: str, description: str, **kw: Any) -> Finding:
    return Finding(
        finding_id=_fid(finding_type, kw.get("resource_record_id"), kw.get("service"), kw.get("region"), title),
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        **kw,
    )


def _by_record(measurements: Iterable[UsageMeasurement]) -> dict[str, list[UsageMeasurement]]:
    out: dict[str, list[UsageMeasurement]] = defaultdict(list)
    for m in measurements:
        if m.resource_record_id:
            out[m.resource_record_id].append(m)
    return out


def _metric(measurements: list[UsageMeasurement], name: str) -> UsageMeasurement | None:
    for m in measurements:
        if (m.metric_name or "").lower() == name.lower():
            return m
    return None


def _has_resource_telemetry(measurements: list[UsageMeasurement]) -> bool:
    return any(m.scope == "resource" and m.collection_status == "collected" and m.datapoint_count > 0 for m in measurements)


def generate_findings(
    *,
    records: list[RegistryRecord],
    usage_measurements: list[UsageMeasurement],
    cost_records: list[CostRecord],
    capabilities: list[ServiceCapability],
    config: ScanConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    by_record = _by_record(usage_measurements)
    caps_by_key = {c.key: c for c in capabilities}

    for record in records:
        if record.resource_kind == "catalog":
            continue
        measurements = by_record.get(record.record_id, [])
        missing_owners = [name for name in OWNER_FIELDS if not getattr(record, name, None)]
        if missing_owners:
            findings.append(_finding(
                finding_type="missing_governance_ownership",
                severity="medium",
                title="No accountable owner recorded",
                description=(
                    f"{record.resource_type} {record.resource_name or record.resource_id} has no system, "
                    "business, or technical owner in tags or registry metadata. "
                    f"Missing: {', '.join(missing_owners)}."
                ),
                service=record.aws_service,
                region=record.aws_region,
                resource_record_id=record.record_id,
                resource_id=record.resource_id,
                evidence_refs=[f"record:{record.record_id}"],
                confidence="high",
                recommendation="Assign an accountable owner and record it with the AI-System-Owner or Owner tag.",
            ))
        if not record.intended_purpose:
            findings.append(_finding(
                finding_type="missing_intended_purpose",
                severity="medium",
                title="No intended purpose recorded",
                description=(
                    f"{record.resource_type} {record.resource_name or record.resource_id} has no purpose "
                    "metadata. Purpose is required to assess whether AI use is appropriate and proportionate."
                ),
                service=record.aws_service,
                region=record.aws_region,
                resource_record_id=record.record_id,
                resource_id=record.resource_id,
                evidence_refs=[f"record:{record.record_id}"],
                confidence="high",
                recommendation="Record the business purpose (for example with a BusinessPurpose tag) and review it.",
            ))

        if config.enable_usage_collection and record.resource_type in PAID_RUNTIME_TYPES:
            if not _has_resource_telemetry(measurements):
                findings.append(_finding(
                    finding_type="missing_usage_telemetry",
                    severity="low",
                    title="No resource-level usage telemetry observed",
                    description=(
                        f"No CloudWatch datapoints were returned for {record.resource_type} "
                        f"{record.resource_name or record.resource_id}. This is not evidence of zero usage: "
                        "telemetry may be disabled, delayed, or require an agent/Container Insights."
                    ),
                    service=record.aws_service,
                    region=record.aws_region,
                    resource_record_id=record.record_id,
                    resource_id=record.resource_id,
                    evidence_refs=[f"record:{record.record_id}"],
                    confidence="low",
                    recommendation="Enable service metrics or the CloudWatch agent, then re-scan to verify utilization.",
                ))
            else:
                _runtime_waste_findings(record, measurements, findings)

    # Service-level costs that cannot be tied to a resource.
    cost_totals: dict[tuple[str, str | None, tuple[str, ...]], float] = defaultdict(float)
    for cost in cost_records:
        if (cost.amount or 0) <= 0 or cost.resource_record_id:
            continue
        managed = [k for k in cost.capability_keys if caps_by_key.get(k) and caps_by_key[k].category == "managed_ai"]
        if not managed:
            continue
        cost_totals[(cost.service_name, cost.region, tuple(sorted(managed)))] += cost.amount or 0
    for (service_name, region, cap_keys), total in sorted(cost_totals.items()):
        findings.append(_finding(
            finding_type="unattributed_ai_cost",
            severity="low" if total < 10 else "medium",
            title="AI service cost is not attributable to a resource",
            description=(
                f"Cost Explorer reports {total:.2f} in the lookback window for {service_name} "
                f"in {region or 'unknown Region'}, but the billing data has no resource-level "
                "identifier. Do not allocate this amount to individual assets without further evidence."
            ),
            service=service_name,
            region=region,
            capability_keys=list(cap_keys),
            evidence_refs=[f"cost:{service_name}:{region}"],
            confidence="high",
            recommendation=(
                "Use CUR with resource IDs, application tagging, or provider-side usage logs to attribute cost."
            ),
        ))

    _cost_change_findings(cost_records, caps_by_key, findings)

    # Capability-level telemetry gaps with discovered assets or managed-AI scope.
    for cap in capabilities:
        if cap.category != "managed_ai":
            continue
        if cap.usage_status in {"unsupported", "not_configured", "permission_denied", "collection_failed", "partial"}:
            if not (cap.resource_count or cap.discovery_status in {"supported", "partial"}):
                continue
            findings.append(_finding(
                finding_type="usage_coverage_gap",
                severity="low",
                title=f"Usage coverage is {cap.usage_status} for {cap.display_name}",
                description=(
                    f"{cap.display_name} discovery status is {cap.discovery_status}, but usage "
                    f"coverage is {cap.usage_status}. {cap.status_reason or ''}".strip()
                ),
                service=cap.adapter or cap.key,
                capability_keys=[cap.key],
                evidence_refs=[f"capability:{cap.key}"],
                confidence="high",
                recommendation="Review the capability limitations and grants; absence of data is not zero usage.",
            ))
        if cap.billing_status in {"permission_denied", "collection_failed"}:
            findings.append(_finding(
                finding_type="billing_coverage_gap",
                severity="medium",
                title=f"Billing coverage is {cap.billing_status} for {cap.display_name}",
                description=f"Reported cost for {cap.display_name} could not be collected. No cost estimate was substituted.",
                service=cap.adapter or cap.key,
                capability_keys=[cap.key],
                evidence_refs=[f"capability:{cap.key}"],
                confidence="high",
                recommendation="Grant Cost Explorer permissions and confirm the account is opted in to Cost Explorer.",
            ))

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.finding_type, f.resource_id or ""))
    _attach_to_records(findings, records)
    return findings


def _runtime_waste_findings(record: RegistryRecord, measurements: list[UsageMeasurement], findings: list[Finding]) -> None:
    invocations = _metric(measurements, "Invocations") or _metric(measurements, "InvocationCount")
    if invocations and invocations.datapoint_count > 0 and (invocations.total or 0) == 0:
        findings.append(_finding(
            finding_type="idle_paid_runtime_candidate",
            severity="medium",
            title="Paid AI runtime has zero invocations in the lookback window",
            description=(
                f"{record.resource_type} {record.resource_name or record.resource_id} is {record.system_status or 'present'} "
                f"and CloudWatch reports zero invocations across {invocations.datapoint_count} datapoints "
                f"from {invocations.start_time} to {invocations.end_time}. Validate before any shutdown."
            ),
            service=record.aws_service,
            region=record.aws_region,
            resource_record_id=record.record_id,
            resource_id=record.resource_id,
            evidence_refs=[f"usage:{invocations.measurement_id}"],
            confidence="medium",
            recommendation="Confirm with the owner that the endpoint is intentionally idle before remediation.",
        ))
    cpu = _metric(measurements, "CPUUtilization")
    if record.resource_type == "ec2_instance" and cpu and cpu.datapoint_count > 0:
        if (cpu.average or 0) < 2.0:
            findings.append(_finding(
                finding_type="low_utilization_accelerated_compute",
                severity="low",
                title="Accelerated compute has very low CPU utilization",
                description=(
                    f"EC2 instance {record.resource_name or record.resource_id} averaged {cpu.average:.2f}% CPU "
                    f"over {cpu.datapoint_count} datapoints. CPU is not GPU utilization; this is a cost-review "
                    "candidate, not proof that the instance is idle."
                ),
                service=record.aws_service,
                region=record.aws_region,
                resource_record_id=record.record_id,
                resource_id=record.resource_id,
                evidence_refs=[f"usage:{cpu.measurement_id}"],
                confidence="low",
                recommendation="Collect GPU metrics before changing capacity; validate workload requirements with the owner.",
            ))


def _cost_change_findings(
    cost_records: list[CostRecord],
    caps_by_key: dict[str, ServiceCapability],
    findings: list[Finding],
) -> None:
    by_service_day: dict[tuple[str, str | None], dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for cost in cost_records:
        if cost.source != "cost_explorer" or not cost.capability_keys:
            continue
        if not any(caps_by_key.get(k) and caps_by_key[k].category == "managed_ai" for k in cost.capability_keys):
            continue
        by_service_day[(cost.service_name, cost.region)][cost.period_start] += cost.amount or 0
    for (service_name, region), days in by_service_day.items():
        ordered = sorted(days)
        if len(ordered) < 10:
            continue
        recent = sum(days[d] for d in ordered[-7:])
        prior = sum(days[d] for d in ordered[-14:-7])
        if prior <= 0.01 or recent < 0.5:
            continue
        ratio = recent / prior
        if ratio < 2.0:
            continue
        findings.append(_finding(
            finding_type="unusual_ai_cost_increase",
            severity="medium" if ratio >= 4 else "low",
            title="Recent AI cost increased materially",
            description=(
                f"{service_name} in {region or 'unknown Region'} cost {recent:.2f} in the latest 7 days "
                f"versus {prior:.2f} in the preceding 7 days ({ratio:.1f}x). This is reported billed cost, "
                "not an estimate."
            ),
            service=service_name,
            region=region,
            capability_keys=[k for k in caps_by_key if caps_by_key[k].category == "managed_ai"],
            evidence_refs=[f"cost-trend:{service_name}:{region}"],
            confidence="medium",
            recommendation="Review recent deployments, traffic, and model selection with the service owner.",
        ))


def _attach_to_records(findings: list[Finding], records: list[RegistryRecord]) -> None:
    by_id = {r.record_id: r for r in records}
    for finding in findings:
        if finding.resource_record_id and finding.resource_record_id in by_id:
            record = by_id[finding.resource_record_id]
            record.findings.append(finding.as_dict())

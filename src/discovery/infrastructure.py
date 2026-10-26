"""Evidence-based discovery for AI-capable infrastructure services.

The tool does not treat every EC2 instance, bucket, or database as AI. A
resource enters the registry only when there is defensible static evidence:
an accelerated instance family, an AI-related name/tag, an AI container image,
or an accelerated EKS node group. This is association evidence, not proof of
model execution.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)

AI_NAME_RE = re.compile(
    r"(^|[-_/.])(ai|ml|llm|genai|gen-ai|rag|embedding|inference|model|models|"
    r"triton|vllm|ollama|huggingface|pytorch|tensorflow|gpu|cuda|sagemaker|bedrock|"
    r"deeplearning|neural)([-_/.]|$)",
    re.IGNORECASE,
)
ACCELERATED_INSTANCE_RE = re.compile(
    r"^(p2|p3|p3dn|p4|p4d|p4de|p5|p5e|p5en|p6|g3|g4dn|g4ad|g5|g5g|g6|g6e|"
    r"inf1|inf2|trn1|trn1n|trn2|trn2e|dl1|f2)\.",
)
AI_IMAGE_RE = re.compile(
    r"(vllm|triton|ollama|huggingface|text-generation-inference|pytorch|tensorflow|"
    r"onnxruntime|sagemaker|bedrock|stable-diffusion|comfyui|llama|mistral|"
    r"deeplearning|inference|model-server)",
    re.IGNORECASE,
)
MAX_RESOURCE_DETAILS = 50


def _iso(value: Any) -> str | None:
    return None if value is None else str(value)


def _tag_evidence(tags: dict[str, str]) -> list[dict[str, str]]:
    out = []
    for key, value in tags.items():
        if AI_NAME_RE.search(key) or AI_NAME_RE.search(str(value or "")):
            out.append({"basis": "tag", "detail": f"{key}={value}"[:160]})
    return out[:10]


def _name_evidence(*values: str | None) -> list[dict[str, str]]:
    out = []
    for value in values:
        if value and AI_NAME_RE.search(value):
            out.append({"basis": "name", "detail": value[:160]})
    return out


def _association(indicators: list[dict[str, str]], basis: str, confidence: str = "low") -> dict[str, Any] | None:
    if not indicators:
        return None
    return {
        "confidence": confidence,
        "basis": basis,
        "indicators": indicators[:10],
        "note": "Static infrastructure evidence only; it does not prove that AI workloads run on this resource.",
    }


class InfrastructureAdapter(BaseAdapter):
    blind_spots: tuple[str, ...] = ()

    def documented_blind_spots(self) -> list[str]:
        return list(self.blind_spots)

    def _error(self, result: AdapterResult, region: str, operation: str, exc: Exception) -> None:
        result.errors.append(OperationError(
            service=self.service,
            operation=operation,
            region=region,
            error_type=classify_exception(exc),
            message=error_message(exc),
            scan_id=self.config.scan_id,
        ))

    def _tags(self, client, arn: str, result: AdapterResult, region: str, operation: str) -> dict[str, str]:
        try:
            response = client.list_tags_for_resource(ResourceARN=arn)
            return {t.get("Key"): t.get("Value") for t in response.get("Tags", []) if t.get("Key")}
        except (ClientError, BotoCoreError) as exc:
            # Tag permission failures are common and non-fatal; keep the error.
            self._error(result, region, operation, exc)
            return {}


@register_adapter
class EC2Adapter(InfrastructureAdapter):
    name = "ec2"
    service = "ec2"
    blind_spots = (
        "Only accelerated instance families or AI-name/tag evidence are registered; ordinary EC2 capacity is not assumed to be AI.",
        "GPU utilization requires the CloudWatch agent; absent GPU metrics are not zero GPU usage.",
        "Instance contents, containers, and application code are never inspected.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("ec2", "DescribeInstances"), ("ec2", "DescribeInstanceTypes"), ("ec2", "DescribeTags")]

    def required_permissions(self) -> list[str]:
        return ["ec2:DescribeInstances", "ec2:DescribeInstanceTypes", "ec2:DescribeTags"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("ec2", region_name=region)
            result.operations_attempted.append("ec2.describe_instances")
            reservations = with_retry(
                lambda: collect_pages(client, "describe_instances", "Reservations"),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context="ec2.describe_instances",
            )
            result.operations_succeeded.append("ec2.describe_instances")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "DescribeInstances", exc)
            return result

        instances = []
        for reservation in reservations:
            for inst in reservation.get("Instances", []) or []:
                instances.append(inst)
        if not instances:
            return result

        types = sorted({i.get("InstanceType") for i in instances if i.get("InstanceType")})
        type_details: dict[str, dict[str, Any]] = {}
        if types:
            result.operations_attempted.append("ec2.describe_instance_types")
            try:
                for start in range(0, len(types), 100):
                    page = client.describe_instance_types(InstanceTypes=types[start:start + 100])
                    for detail in page.get("InstanceTypes", []):
                        type_details[detail.get("InstanceType")] = detail
                result.operations_succeeded.append("ec2.describe_instance_types")
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "DescribeInstanceTypes", exc)

        for inst in instances:
            instance_id = inst.get("InstanceId")
            if not instance_id:
                continue
            itype = inst.get("InstanceType") or ""
            name = next((t.get("Value") for t in inst.get("Tags", []) if t.get("Key") == "Name"), None)
            tags = {t.get("Key"): t.get("Value") for t in inst.get("Tags", []) if t.get("Key")}
            indicators = []
            basis = ""
            if ACCELERATED_INSTANCE_RE.match(itype):
                indicators.append({"basis": "instance_type", "detail": itype})
                basis = "accelerated_compute"
            name_indicators = _name_evidence(name) + _tag_evidence(tags)
            if name_indicators:
                indicators.extend(name_indicators)
                basis = basis or "name_or_tag"
            if not indicators:
                continue
            detail = type_details.get(itype) or {}
            gpu = detail.get("GpuInfo") or {}
            accelerators = detail.get("InferenceAcceleratorInfo") or {}
            result.resources.append(DiscoveredResource(
                service="ec2",
                resource_type="ec2_instance",
                resource_id=instance_id,
                region=region,
                arn=None,
                name=name or instance_id,
                status=(inst.get("State") or {}).get("Name"),
                created_time=_iso(inst.get("LaunchTime")),
                tags=tags,
                metadata={
                    "instance_type": itype,
                    "availability_zone": inst.get("Placement", {}).get("AvailabilityZone"),
                    "architecture": detail.get("ProcessorInfo", {}).get("SupportedArchitectures"),
                    "vcpu_count": (detail.get("VCpuInfo") or {}).get("DefaultVCpus"),
                    "memory_mib": (detail.get("MemoryInfo") or {}).get("SizeInMiB"),
                    "gpu_count": sum(g.get("Count", 0) for g in gpu.get("Gpus", []) or []),
                    "gpu_manufacturer": gpu.get("Gpus", [{}])[0].get("Manufacturer") if gpu.get("Gpus") else None,
                    "gpu_name": gpu.get("Gpus", [{}])[0].get("Name") if gpu.get("Gpus") else None,
                    "inference_accelerators": [
                        {"count": a.get("Count"), "name": a.get("Name")}
                        for a in accelerators.get("Accelerators", []) or []
                    ],
                    "association_basis": basis,
                },
                ai_association=_association(indicators, basis, "medium" if basis == "accelerated_compute" else "low"),
                source_operation="ec2.DescribeInstances",
            ))
        result.notes.append(f"evaluated {len(instances)} EC2 instances; registered only those with AI infrastructure evidence")
        return result


@register_adapter
class ECSAdapter(InfrastructureAdapter):
    name = "ecs"
    service = "ecs"
    blind_spots = (
        "Only ECS clusters/services with AI name/tag, AI container image, or Fargate task evidence are registered.",
        "Container environment secrets, command lines, and payloads are never read.",
        "Task-level CPU/memory utilization is available only where CloudWatch Container Insights publishes it.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("ecs", "ListClusters"), ("ecs", "DescribeClusters"), ("ecs", "ListServices"),
                ("ecs", "DescribeServices"), ("ecs", "DescribeTaskDefinition"), ("ecs", "ListTagsForResource")]

    def required_permissions(self) -> list[str]:
        return ["ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices",
                "ecs:DescribeTaskDefinition", "ecs:ListTagsForResource"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("ecs", region_name=region)
            result.operations_attempted.append("ecs.list_clusters")
            arns = collect_pages(client, "list_clusters", "clusterArns")
            result.operations_succeeded.append("ecs.list_clusters")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "ListClusters", exc)
            return result
        if not arns:
            return result
        clusters = []
        for start in range(0, len(arns), 100):
            try:
                clusters.extend(client.describe_clusters(clusters=arns[start:start + 100]).get("clusters", []))
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "DescribeClusters", exc)
        task_defs: dict[str, dict[str, Any]] = {}
        for cluster in clusters:
            cluster_arn = cluster.get("clusterArn")
            cluster_name = cluster.get("clusterName") or cluster_arn
            if not cluster_arn:
                continue
            tags = self._tags(client, cluster_arn, result, region, "ListTagsForResource")
            try:
                service_arns = collect_pages(client, "list_services", "serviceArns", {"cluster": cluster_arn})
                result.operations_succeeded.append("ecs.list_services")
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "ListServices", exc)
                service_arns = []
            services = []
            for start in range(0, len(service_arns), 10):
                try:
                    services.extend(client.describe_services(cluster=cluster_arn, services=service_arns[start:start + 10]).get("services", []))
                except (ClientError, BotoCoreError) as exc:
                    self._error(result, region, "DescribeServices", exc)
            for svc in services:
                svc_name = svc.get("serviceName")
                svc_arn = svc.get("serviceArn")
                td_arn = svc.get("taskDefinition")
                td = None
                if td_arn and td_arn not in task_defs:
                    try:
                        td = client.describe_task_definition(taskDefinition=td_arn).get("taskDefinition") or {}
                        task_defs[td_arn] = td
                    except (ClientError, BotoCoreError) as exc:
                        self._error(result, region, "DescribeTaskDefinition", exc)
                td = td or task_defs.get(td_arn) or {}
                images = [
                    c.get("image", "") for c in (td.get("containerDefinitions") or []) if c.get("image")
                ]
                image_indicators = [
                    {"basis": "container_image", "detail": img[:200]}
                    for img in images if AI_IMAGE_RE.search(img)
                ]
                indicators = _name_evidence(svc_name) + _tag_evidence(tags) + image_indicators
                launch_type = svc.get("launchType")
                if launch_type == "FARGATE" and indicators:
                    indicators.append({"basis": "fargate_launch_type", "detail": "FARGATE"})
                if not indicators:
                    continue
                result.resources.append(DiscoveredResource(
                    service="ecs",
                    resource_type="ecs_service",
                    resource_id=svc_arn or f"{cluster_name}/{svc_name}",
                    region=region,
                    arn=svc_arn,
                    name=f"{cluster_name}/{svc_name}" if cluster_name else svc_name,
                    status=svc.get("status"),
                    created_time=_iso(svc.get("createdAt")),
                    tags=tags,
                    metadata={
                        "cluster_arn": cluster_arn,
                        "cluster_name": cluster_name,
                        "launch_type": launch_type,
                        "desired_count": svc.get("desiredCount"),
                        "running_count": svc.get("runningCount"),
                        "task_definition": td_arn,
                        "container_images": images[:5],
                    },
                    ai_association=_association(indicators, "container_or_service_evidence", "low"),
                    source_operation="ecs.ListServices+DescribeServices+DescribeTaskDefinition",
                ))
            if not services:
                indicators = _name_evidence(cluster_name) + _tag_evidence(tags)
                if indicators:
                    result.resources.append(DiscoveredResource(
                        service="ecs",
                        resource_type="ecs_cluster",
                        resource_id=cluster_arn,
                        region=region,
                        arn=cluster_arn,
                        name=cluster_name,
                        status=cluster.get("status"),
                        tags=tags,
                        metadata={"cluster_arn": cluster_arn, "registered_task_count": cluster.get("registeredContainerInstancesCount")},
                        ai_association=_association(indicators, "name_or_tag", "low"),
                        source_operation="ecs.DescribeClusters",
                    ))
        return result


@register_adapter
class EKSAdapter(InfrastructureAdapter):
    name = "eks"
    service = "eks"
    blind_spots = (
        "Only clusters/node groups with AI name/tag or accelerated node-group instance types are registered.",
        "Kubernetes pods, namespaces, images, and GPU utilization are not queried; Container Insights is not read.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("eks", "ListClusters"), ("eks", "DescribeCluster"), ("eks", "ListNodegroups"),
                ("eks", "DescribeNodegroup"), ("eks", "ListTagsForResource")]

    def required_permissions(self) -> list[str]:
        return ["eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups",
                "eks:DescribeNodegroup", "eks:ListTagsForResource"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("eks", region_name=region)
            result.operations_attempted.append("eks.list_clusters")
            names = collect_pages(client, "list_clusters", "clusters")
            result.operations_succeeded.append("eks.list_clusters")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "ListClusters", exc)
            return result
        for name in names[:MAX_RESOURCE_DETAILS]:
            try:
                cluster = client.describe_cluster(name=name).get("cluster") or {}
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "DescribeCluster", exc)
                continue
            tags = cluster.get("tags") or {}
            indicators = _name_evidence(name) + _tag_evidence(tags)
            accelerated_groups = []
            try:
                groups = client.list_nodegroups(clusterName=name).get("nodegroups", [])
                for group in groups:
                    try:
                        ng = client.describe_nodegroup(clusterName=name, nodegroupName=group).get("nodegroup") or {}
                    except (ClientError, BotoCoreError) as exc:
                        self._error(result, region, "DescribeNodegroup", exc)
                        continue
                    itypes = ng.get("instanceTypes") or []
                    if any(ACCELERATED_INSTANCE_RE.match(t) for t in itypes):
                        accelerated_groups.append({"name": group, "instance_types": itypes})
                        indicators.append({"basis": "nodegroup_instance_type", "detail": f"{group}:{','.join(itypes)}"})
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "ListNodegroups", exc)
            if not indicators:
                continue
            result.resources.append(DiscoveredResource(
                service="eks",
                resource_type="eks_cluster",
                resource_id=cluster.get("arn") or name,
                region=region,
                arn=cluster.get("arn"),
                name=name,
                status=cluster.get("status"),
                created_time=_iso(cluster.get("createdAt")),
                tags=tags,
                metadata={
                    "kubernetes_version": cluster.get("version"),
                    "platform_version": cluster.get("platformVersion"),
                    "accelerated_nodegroups": accelerated_groups,
                },
                ai_association=_association(indicators, "cluster_or_nodegroup_evidence", "low"),
                source_operation="eks.DescribeCluster+ListNodegroups+DescribeNodegroup",
            ))
        return result


@register_adapter
class S3Adapter(InfrastructureAdapter):
    name = "s3"
    service = "s3"
    blind_spots = (
        "Only buckets with AI-related name or tags are registered; object contents and model artifacts are never read.",
        "Bucket request/storage metrics are not evidence that the data is used by AI.",
        "Tag reads may fail on buckets owned by another account or with restrictive policies.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("s3", "ListBuckets"), ("s3", "GetBucketTagging")]

    def required_permissions(self) -> list[str]:
        return ["s3:ListAllMyBuckets", "s3:GetBucketTagging", "s3:GetBucketLocation"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("s3", region_name=region)
            result.operations_attempted.append("s3.list_buckets")
            buckets = client.list_buckets().get("Buckets", [])
            result.operations_succeeded.append("s3.list_buckets")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "ListBuckets", exc)
            return result
        for bucket in buckets[:200]:
            name = bucket.get("Name")
            if not name:
                continue
            tags: dict[str, str] = {}
            try:
                tags = {t.get("Key"): t.get("Value") for t in client.get_bucket_tagging(Bucket=name).get("TagSet", []) if t.get("Key")}
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {"NoSuchTagSet", "NoSuchTagSetError"}:
                    self._error(result, region, "GetBucketTagging", exc)
            indicators = _name_evidence(name) + _tag_evidence(tags)
            if not indicators:
                continue
            result.resources.append(DiscoveredResource(
                service="s3",
                resource_type="s3_bucket",
                resource_id=name,
                region=region,
                arn=f"arn:aws:s3:::{name}",
                name=name,
                created_time=_iso(bucket.get("CreationDate")),
                tags=tags,
                metadata={"bucket_region_hint": region},
                ai_association=_association(indicators, "name_or_tag", "low"),
                source_operation="s3.ListBuckets+GetBucketTagging",
            ))
        return result


@register_adapter
class OpenSearchAdapter(InfrastructureAdapter):
    name = "opensearch"
    service = "opensearch"
    blind_spots = (
        "Vector search is an index-level capability; only domains with AI name/tag evidence are registered.",
        "Index contents, queries, and vectors are never read.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("opensearch", "ListDomainNames"), ("opensearch", "DescribeDomains"), ("opensearch", "ListTags")]

    def required_permissions(self) -> list[str]:
        return ["es:ListDomainNames", "es:DescribeDomains", "es:ListTags"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("opensearch", region_name=region)
            result.operations_attempted.append("opensearch.list_domain_names")
            names = [d.get("DomainName") for d in client.list_domain_names().get("DomainNames", []) if d.get("DomainName")]
            result.operations_succeeded.append("opensearch.list_domain_names")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "ListDomainNames", exc)
            return result
        details = []
        for start in range(0, len(names), 5):
            try:
                details.extend(client.describe_domains(DomainNames=names[start:start + 5]).get("DomainStatusList", []))
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "DescribeDomains", exc)
        for domain in details:
            name = domain.get("DomainName")
            arn = domain.get("ARN")
            tags = {}
            if arn:
                try:
                    tags = {t.get("Key"): t.get("Value") for t in client.list_tags(ARN=arn).get("TagList", []) if t.get("Key")}
                except (ClientError, BotoCoreError) as exc:
                    self._error(result, region, "ListTags", exc)
            indicators = _name_evidence(name) + _tag_evidence(tags)
            if not indicators:
                continue
            result.resources.append(DiscoveredResource(
                service="opensearch",
                resource_type="opensearch_domain",
                resource_id=arn or name,
                region=region,
                arn=arn,
                name=name,
                status="active" if domain.get("Processing") is False else "processing",
                tags=tags,
                metadata={"engine_version": domain.get("EngineVersion"), "cluster_config": domain.get("ClusterConfig")},
                ai_association=_association(indicators, "name_or_tag", "low"),
                source_operation="opensearch.DescribeDomains+ListTags",
            ))
        return result


@register_adapter
class RedshiftAdapter(InfrastructureAdapter):
    name = "redshift"
    service = "redshift"
    blind_spots = (
        "Redshift ML models are schema-level objects with no account-wide list API used here.",
        "Only clusters with AI name/tag evidence are registered; query text and results are never read.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("redshift", "DescribeClusters"), ("redshift", "DescribeTags")]

    def required_permissions(self) -> list[str]:
        return ["redshift:DescribeClusters", "redshift:DescribeTags"]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client("redshift", region_name=region)
            result.operations_attempted.append("redshift.describe_clusters")
            clusters = collect_pages(client, "describe_clusters", "Clusters")
            result.operations_succeeded.append("redshift.describe_clusters")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "DescribeClusters", exc)
            return result
        for cluster in clusters:
            name = cluster.get("ClusterIdentifier")
            tags = {}
            try:
                tags = {t.get("Key"): t.get("Value") for t in client.describe_tags(ResourceName=cluster.get("ClusterNamespaceArn") or name).get("TaggedResources", []) if t.get("Tag", {}).get("Key")}
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, "DescribeTags", exc)
            indicators = _name_evidence(name) + _tag_evidence(tags)
            if not indicators:
                continue
            result.resources.append(DiscoveredResource(
                service="redshift",
                resource_type="redshift_cluster",
                resource_id=cluster.get("ClusterNamespaceArn") or name,
                region=region,
                arn=cluster.get("ClusterNamespaceArn"),
                name=name,
                status=cluster.get("ClusterStatus"),
                created_time=_iso(cluster.get("ClusterCreateTime")),
                tags=tags,
                metadata={"node_type": cluster.get("NodeType"), "number_of_nodes": cluster.get("NumberOfNodes"), "engine_version": cluster.get("ClusterVersion")},
                ai_association=_association(indicators, "name_or_tag", "low"),
                source_operation="redshift.DescribeClusters+DescribeTags",
            ))
        return result


class _RDSLikeAdapter(InfrastructureAdapter):
    engine_prefixes: tuple[str, ...] = ()

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        try:
            client = session.client(self.service, region_name=region)
            result.operations_attempted.append(f"{self.service}.describe_db_clusters")
            clusters = collect_pages(client, "describe_db_clusters", "DBClusters")
            result.operations_succeeded.append(f"{self.service}.describe_db_clusters")
        except (ClientError, BotoCoreError) as exc:
            self._error(result, region, "DescribeDBClusters", exc)
            return result
        for cluster in clusters:
            engine = (cluster.get("Engine") or "").lower()
            if self.engine_prefixes and not engine.startswith(self.engine_prefixes):
                continue
            name = cluster.get("DBClusterIdentifier")
            arn = cluster.get("DBClusterArn")
            tags = {}
            if arn:
                try:
                    tags = {t.get("Key"): t.get("Value") for t in client.list_tags_for_resource(ResourceName=arn).get("TagList", []) if t.get("Key")}
                except (ClientError, BotoCoreError) as exc:
                    self._error(result, region, "ListTagsForResource", exc)
            indicators = _name_evidence(name) + _tag_evidence(tags)
            if not indicators:
                continue
            result.resources.append(DiscoveredResource(
                service=self.service,
                resource_type=f"{self.service}_cluster",
                resource_id=arn or name,
                region=region,
                arn=arn,
                name=name,
                status=cluster.get("Status"),
                created_time=_iso(cluster.get("ClusterCreateTime")),
                tags=tags,
                metadata={"engine": engine, "engine_version": cluster.get("EngineVersion"), "cluster_members": len(cluster.get("DBClusterMembers", []) or [])},
                ai_association=_association(indicators, "name_or_tag", "low"),
                source_operation=f"{self.service}.DescribeDBClusters+ListTagsForResource",
            ))
        return result


@register_adapter
class AuroraAdapter(_RDSLikeAdapter):
    name = "aurora"
    service = "rds"
    engine_prefixes = ("aurora",)
    blind_spots = (
        "Aurora vector/ML capabilities are engine/feature-level; only clusters with AI name/tag evidence are registered.",
        "Database contents, queries, and vector indexes are never read.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("rds", "DescribeDBClusters"), ("rds", "ListTagsForResource")]

    def required_permissions(self) -> list[str]:
        return ["rds:DescribeDBClusters", "rds:ListTagsForResource"]


@register_adapter
class NeptuneAdapter(_RDSLikeAdapter):
    name = "neptune"
    service = "neptune"
    blind_spots = (
        "Graph contents and queries are never read; only clusters with AI name/tag evidence are registered.",
        "Neptune ML/graph-AI usage is not inferable from cluster metadata alone.",
    )

    def api_operations(self) -> list[tuple[str, str]]:
        return [("neptune", "DescribeDBClusters"), ("neptune", "ListTagsForResource")]

    def required_permissions(self) -> list[str]:
        return ["neptune:DescribeDBClusters", "neptune:ListTagsForResource"]

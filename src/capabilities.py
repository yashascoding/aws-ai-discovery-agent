"""AWS service capability registry for discovery, usage, and billing coverage.

The registry is intentionally explicit: for every requested service it states
what the tool can discover, what usage telemetry exists or is queried, what is
available through AWS Cost Explorer, and what remains unknown. Runtime status
is updated from actual collector outcomes; a service is never reported as
"no usage" merely because telemetry was unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

CAPABILITY_STATUSES = (
    "supported",
    "partial",
    "not_configured",
    "permission_denied",
    "unsupported",
    "collection_failed",
)

CATEGORIES = ("managed_ai", "ai_infrastructure", "supporting_ai")


@dataclass
class ServiceCapability:
    key: str
    display_name: str
    category: str
    adapter: str | None = None
    discovery_status: str = "unsupported"
    usage_status: str = "unsupported"
    billing_status: str = "supported"
    usage_namespaces: list[str] = field(default_factory=list)
    cost_service_names: list[str] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)
    supported_regions: str = "regional unless stated otherwise"
    last_successful_collection: str | None = None
    limitations: list[str] = field(default_factory=list)
    status_reason: str | None = None
    collect_usage: bool = True
    resource_count: int | None = None
    usage_measurement_count: int | None = None
    cost_record_count: int | None = None
    reported_cost: float | None = None
    cost_currency: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category,
            "adapter": self.adapter,
            "discovery_status": self.discovery_status,
            "usage_status": self.usage_status,
            "billing_status": self.billing_status,
            "usage_namespaces": self.usage_namespaces,
            "cost_service_names": self.cost_service_names,
            "required_permissions": self.required_permissions,
            "supported_regions": self.supported_regions,
            "last_successful_collection": self.last_successful_collection,
            "limitations": self.limitations,
            "status_reason": self.status_reason,
            "resource_count": self.resource_count,
            "usage_measurement_count": self.usage_measurement_count,
            "cost_record_count": self.cost_record_count,
            "reported_cost": self.reported_cost,
            "cost_currency": self.cost_currency,
        }


def _cap(key: str, name: str, category: str, **kw: Any) -> ServiceCapability:
    return ServiceCapability(key=key, display_name=name, category=category, **kw)


# Permissions are grouped by collector; each adapter repeats the relevant list
# in its own ``required_permissions`` method.
_BEDROCK_PERMS = [
    "bedrock:ListFoundationModels", "bedrock:ListInferenceProfiles",
    "bedrock:ListProvisionedModelThroughputs", "bedrock:ListCustomModels",
    "bedrock:ListGuardrails", "bedrock:ListTagsForResource",
    "bedrock-agent:ListAgents", "bedrock-agent:ListAgentAliases",
    "bedrock-agent:ListKnowledgeBases", "bedrock-agent:ListPrompts",
    "bedrock-agent:ListFlows",
]
_SAGEMAKER_PERMS = [
    "sagemaker:ListModels", "sagemaker:ListEndpoints", "sagemaker:ListEndpointConfigs",
    "sagemaker:ListTrainingJobs", "sagemaker:ListProcessingJobs",
    "sagemaker:ListPipelines", "sagemaker:ListModelPackages",
    "sagemaker:ListInferenceComponents", "sagemaker:ListExperiments",
    "sagemaker:ListDomains", "sagemaker:ListUserProfiles", "sagemaker:ListApps",
    "sagemaker:ListSpaces", "sagemaker:ListProjects", "sagemaker:ListFlowDefinitions",
    "sagemaker:ListHumanTaskUis", "sagemaker-a2i-runtime:ListHumanLoops",
    "sagemaker:ListTags",
]
_CW_PERMS = ["cloudwatch:ListMetrics", "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics"]
_CE_PERMS = ["ce:GetCostAndUsage", "ce:GetDimensionValues", "ce:GetTags"]

_SERVICES: list[ServiceCapability] = [
    # ------------------------------------------------------------------ #
    # Dedicated AWS AI / ML services
    # ------------------------------------------------------------------ #
    _cap("bedrock", "Amazon Bedrock", "managed_ai", adapter="bedrock",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Bedrock"], cost_service_names=["Amazon Bedrock"],
         required_permissions=_BEDROCK_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=[
             "Foundation-model and system-defined inference-profile listings are catalogue availability, not account usage.",
             "Runtime invocation telemetry depends on CloudWatch metrics and/or operator-enabled CloudTrail data events.",
             "Model invocation logging payloads are never read or stored.",
         ]),
    _cap("sagemaker", "Amazon SageMaker AI", "managed_ai", adapter="sagemaker",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/SageMaker"], cost_service_names=["Amazon SageMaker"],
         required_permissions=_SAGEMAKER_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=[
             "Endpoint-level invocations and utilization are collected only where CloudWatch publishes them.",
             "Training/processing job resource existence is visible; per-job duration may require CloudWatch Logs or custom metrics.",
             "Studio user profiles/apps are inventoried, but notebook content and interactive usage are not inspected.",
         ]),
    _cap("rekognition", "Amazon Rekognition", "managed_ai", adapter="rekognition",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Rekognition"], cost_service_names=["Amazon Rekognition"],
         required_permissions=["rekognition:ListCollections", "rekognition:ListStreamProcessors",
                               "rekognition:DescribeProjects", "rekognition:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Image/video operation counts are service-level CloudWatch metrics; per-call content is never collected."]),
    _cap("textract", "Amazon Textract", "managed_ai", adapter="textract",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Textract"], cost_service_names=["Amazon Textract"],
         required_permissions=["textract:ListAdapters", "textract:ListAdapterVersions",
                               "textract:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Analyzers are detected; document page quantities and per-job usage depend on CloudWatch/billing data."]),
    _cap("comprehend", "Amazon Comprehend", "managed_ai", adapter="comprehend",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Comprehend"], cost_service_names=["Amazon Comprehend"],
         required_permissions=["comprehend:ListDocumentClassifiers", "comprehend:ListEntityRecognizers",
                               "comprehend:ListEndpoints", "comprehend:ListFlywheels",
                               "comprehend:ListDocumentClassificationJobs",
                               "comprehend:ListEntitiesDetectionJobs",
                               "comprehend:ListSentimentDetectionJobs",
                               "comprehend:ListTopicsDetectionJobs",
                               "comprehend:ListKeyPhrasesDetectionJobs",
                               "comprehend:ListPiiEntitiesDetectionJobs"] + _CW_PERMS + _CE_PERMS,
         limitations=["Job listings are bounded by API retention; unit-level document/text throughput is inferred from CloudWatch only."]),
    _cap("lex", "Amazon Lex", "managed_ai", adapter="lex",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Lex"], cost_service_names=["Amazon Lex"],
         required_permissions=["lexv2-models:ListBots", "lexv2-models:ListBotAliases",
                               "lexv2-models:ListBotLocales"] + _CW_PERMS + _CE_PERMS,
         limitations=["Lex V2 bot metadata is regional; conversation content is never read.",
                      "Runtime request metrics are available only where the service publishes CloudWatch metrics."]),
    _cap("polly", "Amazon Polly", "managed_ai", adapter="polly",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Polly"], cost_service_names=["Amazon Polly"],
         required_permissions=["polly:ListLexicons", "polly:ListSpeechSynthesisTasks"] + _CW_PERMS + _CE_PERMS,
         limitations=["No account-level model resource: synthesis is an API operation.",
                      "Characters processed are available through CloudWatch/billing where published."]),
    _cap("transcribe", "Amazon Transcribe", "managed_ai", adapter="transcribe",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Transcribe"], cost_service_names=["Amazon Transcribe"],
         required_permissions=["transcribe:ListTranscriptionJobs", "transcribe:ListMedicalTranscriptionJobs",
                               "transcribe:ListMedicalScribeJobs", "transcribe:ListCallAnalyticsJobs",
                               "transcribe:ListVocabularies", "transcribe:ListMedicalVocabularies",
                               "transcribe:ListLanguageModels"] + _CW_PERMS + _CE_PERMS,
         limitations=["Audio is never accessed; only job metadata and service metrics are collected."]),
    _cap("translate", "Amazon Translate", "managed_ai", adapter="translate",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Translate"], cost_service_names=["Amazon Translate"],
         required_permissions=["translate:ListTerminologies", "translate:ListParallelData",
                               "translate:ListTextTranslationJobs"] + _CW_PERMS + _CE_PERMS,
         limitations=["Character throughput is primarily a billing/CloudWatch measure, not a resource listing."]),
    _cap("personalize", "Amazon Personalize", "managed_ai", adapter="personalize",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Personalize"], cost_service_names=["Amazon Personalize"],
         required_permissions=["personalize:ListDatasets", "personalize:ListDatasetGroups",
                               "personalize:ListSolutions", "personalize:ListCampaigns",
                               "personalize:ListRecommenders", "personalize:ListEventTrackers",
                               "personalize:ListFilters"] + _CW_PERMS + _CE_PERMS,
         limitations=["Recommendation quality and event payloads are not inspected."]),
    _cap("kendra", "Amazon Kendra", "managed_ai", adapter="kendra",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Kendra"], cost_service_names=["Amazon Kendra"],
         required_permissions=["kendra:ListIndices", "kendra:ListDataSources", "kendra:ListFaqs",
                               "kendra:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Document contents and queries are never read; index/query metrics only."]),
    _cap("qbusiness", "Amazon Q Business", "managed_ai", adapter="qbusiness",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/QBusiness"], cost_service_names=["Amazon Q"],
         required_permissions=["qbusiness:ListApplications", "qbusiness:ListIndices",
                               "qbusiness:ListDataSources", "qbusiness:ListRetrievers",
                               "qbusiness:ListPlugins", "qbusiness:ListWebExperiences"] + _CW_PERMS + _CE_PERMS,
         limitations=["Amazon Q Business and Amazon Q Developer costs may share the same Cost Explorer service name.",
                      "Conversation content and prompts are never collected."]),
    _cap("qdeveloper", "Amazon Q Developer", "managed_ai",
         discovery_status="unsupported", usage_status="partial", billing_status="supported",
         cost_service_names=["Amazon Q"],
         required_permissions=_CE_PERMS + ["cloudtrail:LookupEvents"],
         limitations=["No public account-resource listing API for Q Developer subscriptions/usage.",
                      "Cost Explorer may aggregate Q Developer with Q Business; CloudTrail may expose management events but not code suggestions."]),
    _cap("bedrock_agents", "Amazon Bedrock Agents", "managed_ai", adapter="bedrock",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Bedrock"], cost_service_names=["Amazon Bedrock"],
         required_permissions=_BEDROCK_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["Agent alias, action-group and runtime invocation payloads are not read."]),
    _cap("bedrock_knowledge_bases", "Amazon Bedrock Knowledge Bases", "managed_ai", adapter="bedrock",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/Bedrock"], cost_service_names=["Amazon Bedrock"],
         required_permissions=_BEDROCK_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["Data-source contents and retrieved chunks are never read."]),
    _cap("bedrock_guardrails", "Amazon Bedrock Guardrails", "managed_ai", adapter="bedrock",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Bedrock"], cost_service_names=["Amazon Bedrock"],
         required_permissions=_BEDROCK_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["Guardrail configuration is inventoried; per-invocation blocked-content metrics depend on Bedrock monitoring."]),
    _cap("a2i", "Amazon Augmented AI (A2I)", "managed_ai", adapter="sagemaker",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/SageMaker"], cost_service_names=["Amazon SageMaker"],
         required_permissions=_SAGEMAKER_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["Flow definitions and human task UIs are listed; human-loop history is bounded and contains no task content."]),
    _cap("healthscribe", "AWS HealthScribe", "managed_ai", adapter="transcribe",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/Transcribe"], cost_service_names=["Amazon Transcribe"],
         required_permissions=["transcribe:ListMedicalScribeJobs", "transcribe:ListMedicalTranscriptionJobs"] + _CW_PERMS + _CE_PERMS,
         limitations=["HealthScribe has no separate resource-listing API; medical scribe/transcription jobs are inventoried.",
                      "Clinical content is never read or stored."]),
    _cap("healthimaging", "AWS HealthImaging", "managed_ai", adapter="healthimaging",
         discovery_status="supported", usage_status="supported",
         usage_namespaces=["AWS/HealthImaging"], cost_service_names=["AWS HealthImaging"],
         required_permissions=["medical-imaging:ListDatastores", "medical-imaging:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Image sets and DICOM payloads are not accessed."]),
    _cap("frauddetector", "Amazon Fraud Detector", "managed_ai", adapter="frauddetector",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/FraudDetector"], cost_service_names=["Amazon Fraud Detector"],
         required_permissions=["frauddetector:GetDetectors", "frauddetector:GetModels",
                               "frauddetector:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Detector/model configuration is listed; prediction content and outcomes are never read."]),
    _cap("forecast", "Amazon Forecast", "managed_ai", adapter="forecast",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Forecast"], cost_service_names=["Amazon Forecast"],
         required_permissions=["forecast:ListDatasets", "forecast:ListDatasetGroups",
                               "forecast:ListPredictors", "forecast:ListForecasts",
                               "forecast:ListMonitors", "forecast:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Dataset contents and forecast outputs are never read."]),
    _cap("lookoutequipment", "Amazon Lookout for Equipment", "managed_ai", adapter="lookoutequipment",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/LookoutEquipment"], cost_service_names=["Amazon Lookout for Equipment"],
         required_permissions=["lookoutequipment:ListDatasets", "lookoutequipment:ListModels",
                               "lookoutequipment:ListInferenceSchedulers",
                               "lookoutequipment:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Sensor data and inference payloads are never read."]),
    _cap("lookoutvision", "Amazon Lookout for Vision", "managed_ai",
         discovery_status="unsupported", usage_status="unsupported",
         cost_service_names=["Amazon Lookout for Vision"],
         required_permissions=["lookoutvision:ListProjects"] + _CE_PERMS,
         limitations=["The Lookout for Vision service is not present in the current AWS SDK service model; it may be unavailable or closed to new customers.",
                      "Any existing Cost Explorer records are still collected."]),
    _cap("lookoutmetrics", "Amazon Lookout for Metrics", "managed_ai",
         discovery_status="unsupported", usage_status="unsupported",
         cost_service_names=["Amazon Lookout for Metrics"],
         required_permissions=["lookoutmetrics:ListAnomalyDetectors"] + _CE_PERMS,
         limitations=["The Lookout for Metrics service is not present in the current AWS SDK service model; it may be unavailable or closed to new customers.",
                      "Any existing Cost Explorer records are still collected."]),
    _cap("deepracer", "AWS DeepRacer", "managed_ai",
         discovery_status="unsupported", usage_status="unsupported",
         cost_service_names=["AWS DeepRacer"], required_permissions=_CE_PERMS,
         limitations=["No public resource-listing/usage API; primarily a console learning service. Only billing records, if any, are collected."]),
    _cap("deepcomposer", "AWS DeepComposer", "managed_ai",
         discovery_status="unsupported", usage_status="unsupported",
         cost_service_names=["AWS DeepComposer"], required_permissions=_CE_PERMS,
         limitations=["No public resource-listing/usage API in the current SDK. Only billing records, if any, are collected."]),

    # ------------------------------------------------------------------ #
    # Infrastructure that can run AI models
    # ------------------------------------------------------------------ #
    _cap("ec2", "Amazon EC2", "ai_infrastructure", adapter="ec2",
         discovery_status="partial", usage_status="supported",
         usage_namespaces=["AWS/EC2"], cost_service_names=["Amazon Elastic Compute Cloud - Compute", "EC2 - Other"],
         required_permissions=["ec2:DescribeInstances", "ec2:DescribeInstanceTypes",
                               "ec2:DescribeTags"] + _CW_PERMS + _CE_PERMS,
         limitations=["Only instances with accelerated-compute, AI-name/tag, or explicit AI-association evidence enter the AI inventory.",
                      "CPU/GPU utilization depends on CloudWatch agent for GPU metrics.",
                      "Inferentia and Trainium capacity is identified through EC2 instance types; billing is under EC2."]),
    _cap("lambda", "AWS Lambda", "ai_infrastructure", adapter="application",
         discovery_status="partial", usage_status="supported",
         usage_namespaces=["AWS/Lambda"], cost_service_names=["AWS Lambda"],
         required_permissions=["lambda:ListFunctions", "lambda:ListTags"] + _CW_PERMS + _CE_PERMS,
         limitations=["Only functions with defensible AI configuration evidence are registered.",
                      "Invocations/duration/errors are collected for registered functions where CloudWatch metrics exist."]),
    _cap("ecs", "Amazon ECS", "ai_infrastructure", adapter="ecs",
         discovery_status="partial", usage_status="supported",
         usage_namespaces=["AWS/ECS"], cost_service_names=["Amazon Elastic Container Service"],
         required_permissions=["ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices",
                               "ecs:DescribeServices", "ecs:DescribeTaskDefinition",
                               "ecs:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Only services/clusters with AI image, name, or tag evidence are registered.",
                      "Container contents and inference payloads are never read."]),
    _cap("eks", "Amazon EKS", "ai_infrastructure", adapter="eks",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/EKS"], cost_service_names=["Amazon Elastic Kubernetes Service"],
         required_permissions=["eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups",
                               "eks:DescribeNodegroup", "eks:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Control-plane and node-group metadata only; Kubernetes workloads/pods are not queried.",
                      "GPU utilization requires the CloudWatch agent/Container Insights and is not assumed."]),
    _cap("fargate", "AWS Fargate", "ai_infrastructure", adapter="ecs",
         discovery_status="partial", usage_status="supported",
         usage_namespaces=["AWS/ECS"], cost_service_names=["AWS Fargate"],
         required_permissions=["ecs:ListServices", "ecs:DescribeServices", "ecs:DescribeTaskDefinition"] + _CW_PERMS + _CE_PERMS,
         limitations=["Fargate is detected through ECS service launch type; task-level workload contents are not read."]),
    _cap("inferentia", "AWS Inferentia", "ai_infrastructure", adapter="ec2",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/EC2"], cost_service_names=["Amazon Elastic Compute Cloud - Compute"],
         required_permissions=["ec2:DescribeInstances", "ec2:DescribeInstanceTypes"] + _CW_PERMS + _CE_PERMS,
         limitations=["Identified as EC2 instance families with Inferentia accelerators; no separate billing service name."]),
    _cap("trainium", "AWS Trainium", "ai_infrastructure", adapter="ec2",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/EC2"], cost_service_names=["Amazon Elastic Compute Cloud - Compute"],
         required_permissions=["ec2:DescribeInstances", "ec2:DescribeInstanceTypes"] + _CW_PERMS + _CE_PERMS,
         limitations=["Identified as EC2 instance families with Trainium accelerators; no separate billing service name."]),
    _cap("jumpstart", "Amazon SageMaker JumpStart", "ai_infrastructure", adapter="sagemaker",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/SageMaker"], cost_service_names=["Amazon SageMaker"],
         required_permissions=_SAGEMAKER_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["JumpStart is a catalogue/launch experience rather than a separately listable account resource.",
                      "Models deployed from JumpStart appear as normal SageMaker models/endpoints."]),
    _cap("studio", "Amazon SageMaker Studio", "ai_infrastructure", adapter="sagemaker",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/SageMaker"], cost_service_names=["Amazon SageMaker"],
         required_permissions=_SAGEMAKER_PERMS + _CW_PERMS + _CE_PERMS,
         limitations=["Domains, user profiles, apps and spaces are listed; notebook contents and interactive commands are not inspected."]),
    _cap("s3", "Amazon S3", "ai_infrastructure", adapter="s3",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/S3"], cost_service_names=["Amazon Simple Storage Service"],
         required_permissions=["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketTagging"] + _CW_PERMS + _CE_PERMS,
         limitations=["Only buckets with AI-name/tag evidence are registered; object contents and model artifacts are never read.",
                      "Bucket-level request/storage metrics are not proof that data is used for AI."]),
    _cap("opensearch", "Amazon OpenSearch Service", "ai_infrastructure", adapter="opensearch",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/ES"], cost_service_names=["Amazon OpenSearch Service"],
         required_permissions=["es:ListDomainNames", "es:DescribeDomains", "es:ListTags"] + _CW_PERMS + _CE_PERMS,
         limitations=["Vector search is an index-level capability; domains are registered only with AI-name/tag evidence.",
                      "Index contents and queries are never read."]),
    _cap("redshift", "Amazon Redshift", "ai_infrastructure", adapter="redshift",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/Redshift"], cost_service_names=["Amazon Redshift"],
         required_permissions=["redshift:DescribeClusters", "redshift:DescribeTags"] + _CW_PERMS + _CE_PERMS,
         limitations=["Redshift ML models are schema-level objects with no account-wide list API in this tool.",
                      "Only clusters with AI-name/tag evidence are registered."]),
    _cap("aurora", "Amazon Aurora", "ai_infrastructure", adapter="aurora",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/RDS"], cost_service_names=["Amazon Relational Database Service"],
         required_permissions=["rds:DescribeDBClusters", "rds:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Aurora vector/ML capabilities are engine/feature-level; only clusters with AI-name/tag evidence are registered."]),
    _cap("neptune", "Amazon Neptune", "ai_infrastructure", adapter="neptune",
         discovery_status="partial", usage_status="partial",
         usage_namespaces=["AWS/Neptune"], cost_service_names=["Amazon Neptune"],
         required_permissions=["neptune:DescribeDBClusters", "neptune:ListTagsForResource"] + _CW_PERMS + _CE_PERMS,
         limitations=["Graph contents and queries are never read; only clusters with AI-name/tag evidence are registered."]),

    # ------------------------------------------------------------------ #
    # Services used alongside AI
    # ------------------------------------------------------------------ #
    _cap("cloudwatch", "Amazon CloudWatch", "supporting_ai",
         discovery_status="unsupported", usage_status="not_configured",
         usage_namespaces=["AWS/CloudWatch"], cost_service_names=["Amazon CloudWatch"],
         required_permissions=_CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Used as the telemetry source for other services; its own metrics are not treated as AI usage."]),
    _cap("cloudtrail", "AWS CloudTrail", "supporting_ai",
         discovery_status="supported", usage_status="supported",
         cost_service_names=["AWS CloudTrail"], required_permissions=["cloudtrail:LookupEvents"] + _CE_PERMS,
         collect_usage=False,
         limitations=["Event History is limited to 90 days; data-plane events must be operator-enabled."]),
    _cap("config", "AWS Config", "supporting_ai",
         discovery_status="unsupported", usage_status="not_configured",
         cost_service_names=["AWS Config"], required_permissions=["config:DescribeConfigurationRecorders"] + _CE_PERMS,
         collect_usage=False,
         limitations=["Config is an optional supporting evidence source; resource history is not required for the AI inventory."]),
    _cap("costexplorer", "AWS Cost Explorer", "supporting_ai",
         discovery_status="not_configured", usage_status="not_configured",
         cost_service_names=["AWS Cost Explorer"], required_permissions=_CE_PERMS,
         collect_usage=False,
         limitations=["Used as the billing source; API calls may incur a small Cost Explorer request charge."]),
    _cap("costandusagereports", "AWS Cost and Usage Reports", "supporting_ai",
         discovery_status="not_configured", usage_status="not_configured",
         cost_service_names=[], required_permissions=["s3:GetObject", "s3:ListBucket"] + _CE_PERMS,
         collect_usage=False,
         limitations=["Optional CUR CSV/GZIP export can be enabled with CUR_BUCKET/CUR_PREFIX; no report is created automatically."]),
    _cap("iam", "AWS Identity and Access Management", "supporting_ai",
         discovery_status="unsupported", usage_status="unsupported",
         cost_service_names=["AWS Identity and Access Management"], required_permissions=[],
         collect_usage=False,
         limitations=["IAM identities are not AI assets; access to AI services is represented through CloudTrail callers, not IAM inventory."]),
    _cap("apigateway", "Amazon API Gateway", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/ApiGateway"], cost_service_names=["Amazon API Gateway"],
         required_permissions=["apigateway:GET"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["API Gateway is only supporting infrastructure; no AI-specific resource semantics.",
                      "Costs are reported at service level and are not attributed to AI without a reliable identifier."]),
    _cap("sqs", "Amazon SQS", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/SQS"], cost_service_names=["Amazon Simple Queue Service"],
         required_permissions=["sqs:ListQueues", "sqs:GetQueueAttributes"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Queue usage is not AI-specific unless correlated to an AI application; only costs/service metrics are available."]),
    _cap("sns", "Amazon SNS", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/SNS"], cost_service_names=["Amazon Simple Notification Service"],
         required_permissions=["sns:ListTopics"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Notification usage is not AI-specific unless correlated to an AI application."]),
    _cap("stepfunctions", "AWS Step Functions", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/States"], cost_service_names=["AWS Step Functions"],
         required_permissions=["states:ListStateMachines"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["State machines may orchestrate AI but are not AI resources; no content is read."]),
    _cap("eventbridge", "Amazon EventBridge", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/Events"], cost_service_names=["Amazon EventBridge"],
         required_permissions=["events:ListRules"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Events are not AI-specific; costs remain service-level and unattributed."]),
    _cap("glue", "AWS Glue", "supporting_ai", adapter="glue",
         discovery_status="supported", usage_status="partial",
         usage_namespaces=["AWS/Glue"], cost_service_names=["AWS Glue"],
         required_permissions=["glue:ListMLTransforms", "glue:GetMLTransform"] + _CW_PERMS + _CE_PERMS,
         limitations=["Only ML transforms are treated as AI resources; ordinary ETL jobs are excluded unless AI-tagged."]),
    _cap("emr", "Amazon EMR", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/ElasticMapReduce"], cost_service_names=["Amazon EMR"],
         required_permissions=["elasticmapreduce:ListClusters"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["EMR clusters are not AI-specific; AI workloads (e.g. Spark ML) cannot be separated without application telemetry."]),
    _cap("athena", "Amazon Athena", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/Athena"], cost_service_names=["Amazon Athena"],
         required_permissions=["athena:ListWorkGroups"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Queries are not AI-specific; query text and results are never read."]),
    _cap("quicksuite", "Amazon Quick Suite", "supporting_ai",
         discovery_status="unsupported", usage_status="partial",
         usage_namespaces=["AWS/QuickSight"], cost_service_names=["Amazon QuickSight"],
         required_permissions=["quicksight:ListDataSets"] + _CW_PERMS + _CE_PERMS, collect_usage=False,
         limitations=["Quick Suite/QuickSight AI features are not separable from general BI usage without resource-level correlation."]),
]


def build_capability_registry() -> list[ServiceCapability]:
    return [ServiceCapability(**cap.__dict__) for cap in _SERVICES]


def capabilities_by_adapter(capabilities: Iterable[ServiceCapability]) -> dict[str, list[ServiceCapability]]:
    out: dict[str, list[ServiceCapability]] = {}
    for cap in capabilities:
        if cap.adapter:
            out.setdefault(cap.adapter, []).append(cap)
    return out


def capability_keys_for_service_name(service_name: str, capabilities: Iterable[ServiceCapability]) -> list[str]:
    needle = service_name.strip().lower()
    return [
        cap.key for cap in capabilities
        if any(needle == n.lower() for n in cap.cost_service_names)
    ]


def mark_adapter_outcome(
    capabilities: list[ServiceCapability], adapter: str, *,
    attempted: bool, succeeded: bool, reason: str | None = None,
    error_type: str | None = None,
) -> None:
    for cap in capabilities:
        if cap.adapter != adapter:
            continue
        if not attempted:
            cap.discovery_status = "not_configured"
            cap.status_reason = "Adapter was not selected for this scan."
        elif succeeded:
            if cap.discovery_status not in {"partial", "unsupported"}:
                cap.discovery_status = "supported"
            cap.status_reason = reason
        else:
            if error_type in {"access_denied", "permission_denied"}:
                cap.discovery_status = "permission_denied"
            elif error_type == "not_found" or error_type == "unsupported":
                cap.discovery_status = "unsupported"
            else:
                cap.discovery_status = "collection_failed"
            cap.status_reason = reason or "Discovery operation failed; see scan errors."


def finalize_capabilities(
    capabilities: list[ServiceCapability],
    *,
    records: list[Any],
    usage_measurements: list[Any],
    cost_records: list[Any],
    observed_at: str,
) -> list[dict[str, Any]]:
    """Attach counts and honest usage/cost status to every capability."""
    from collections import Counter

    resource_counts = Counter()
    for rec in records:
        service = getattr(rec, "aws_service", "") or ""
        for cap in capabilities:
            adapter = cap.adapter or ""
            if service == adapter or (adapter == "application" and service == "lambda"):
                resource_counts[cap.key] += 1
            elif adapter == "sagemaker" and service.startswith("sagemaker"):
                resource_counts[cap.key] += 1
            elif adapter == "bedrock" and service.startswith("bedrock"):
                resource_counts[cap.key] += 1

    usage_counts = Counter()
    for m in usage_measurements:
        for key in getattr(m, "capability_keys", []) or []:
            usage_counts[key] += 1
    cost_counts = Counter()
    cost_amounts: dict[str, float] = {}
    currencies: dict[str, str] = {}
    for c in cost_records:
        for key in getattr(c, "capability_keys", []) or []:
            cost_counts[key] += 1
            if getattr(c, "amount", None) is not None:
                cost_amounts[key] = cost_amounts.get(key, 0.0) + float(c.amount)
            currencies[key] = getattr(c, "currency", "USD") or "USD"

    for cap in capabilities:
        cap.resource_count = resource_counts.get(cap.key, 0)
        cap.usage_measurement_count = usage_counts.get(cap.key, 0)
        cap.cost_record_count = cost_counts.get(cap.key, 0)
        cap.reported_cost = round(cost_amounts.get(cap.key, 0.0), 6) if cap.cost_record_count else None
        cap.cost_currency = currencies.get(cap.key)
        if cap.collect_usage and cap.usage_namespaces and cap.usage_status not in {"unsupported", "not_configured"}:
            if cap.usage_measurement_count:
                cap.usage_status = "supported"
                cap.last_successful_collection = observed_at
            elif cap.usage_status == "supported":
                cap.usage_status = "partial"
                cap.status_reason = (
                    "Discovery and telemetry query succeeded, but no CloudWatch datapoints "
                    "were returned in the lookback window. This is not evidence of zero usage."
                )
        if cap.cost_record_count:
            cap.billing_status = "supported"
            cap.last_successful_collection = observed_at
    return [cap.as_dict() for cap in capabilities]

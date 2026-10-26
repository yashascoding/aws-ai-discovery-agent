"""Discovery adapters for AWS managed AI services beyond Bedrock/SageMaker.

Each adapter is independent and error-isolated. List operations are read-only,
paginated, and bounded. Only resource metadata is stored; no document, audio,
image, prompt, completion, or prediction payload is ever read.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)


def _iso(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class ListOperation:
    client: str
    operation: str
    result_key: str
    resource_type: str
    id_key: str
    name_key: str | None = None
    arn_key: str | None = None
    status_key: str | None = None
    created_key: str | None = None
    modified_key: str | None = None
    description_key: str | None = None
    kwargs: dict[str, Any] = field(default_factory=dict)
    metadata_builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    max_pages: int = 50


class ConfigurableListAdapter(BaseAdapter):
    """Reusable adapter for services whose resources are exposed by list APIs."""

    operations: tuple[ListOperation, ...] = ()
    resource_prefix = "managed_ai"
    blind_spots: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    def api_operations(self) -> list[tuple[str, str]]:
        return [(op.client, op.operation) for op in self.operations]

    def required_permissions(self) -> list[str]:
        return list(self.permissions)

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

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        for spec in self.operations:
            op_label = f"{spec.client}.{spec.operation}"
            result.operations_attempted.append(op_label)
            try:
                client = session.client(spec.client, region_name=region)
                items = with_retry(
                    lambda c=client, s=spec: collect_pages(
                        c, s.operation, s.result_key, dict(s.kwargs), max_pages=s.max_pages
                    ),
                    max_retries=self.config.max_retries,
                    base_delay=self.config.retry_base_delay,
                    logger=logger,
                    context=op_label,
                )
                result.operations_succeeded.append(op_label)
            except (ClientError, BotoCoreError) as exc:
                self._error(result, region, spec.operation, exc)
                continue
            for item in items:
                if isinstance(item, str):
                    item = {spec.id_key: item}
                if not isinstance(item, dict):
                    continue
                metadata = {"managed_service": self.name}
                if spec.metadata_builder:
                    try:
                        metadata.update(spec.metadata_builder(item) or {})
                    except Exception:  # noqa: BLE001 - metadata must not break discovery
                        pass
                result.resources.append(DiscoveredResource(
                    service=self.name,
                    resource_type=spec.resource_type,
                    resource_id=str(item.get(spec.id_key) or f"unknown-{spec.resource_type}"),
                    region=region,
                    arn=item.get(spec.arn_key) if spec.arn_key else None,
                    name=item.get(spec.name_key) if spec.name_key else None,
                    description=item.get(spec.description_key) if spec.description_key else None,
                    status=item.get(spec.status_key) if spec.status_key else None,
                    created_time=_iso(item.get(spec.created_key)) if spec.created_key else None,
                    modified_time=_iso(item.get(spec.modified_key)) if spec.modified_key else None,
                    metadata=metadata,
                    source_operation=f"{spec.client}.{spec.operation}",
                ))
        return result


@register_adapter
class RekognitionAdapter(ConfigurableListAdapter):
    name = "rekognition"
    service = "rekognition"
    operations = (
        ListOperation("rekognition", "list_collections", "CollectionIds", "rekognition_collection", "CollectionId"),
        ListOperation("rekognition", "list_stream_processors", "StreamProcessors", "rekognition_stream_processor", "Name", name_key="Name", status_key="Status", created_key="CreationTimestamp"),
        ListOperation("rekognition", "describe_projects", "ProjectDescriptions", "rekognition_project", "ProjectArn", name_key="ProjectName", arn_key="ProjectArn", status_key="Status", created_key="CreationTimestamp"),
    )
    permissions = ("rekognition:ListCollections", "rekognition:ListStreamProcessors", "rekognition:DescribeProjects")
    blind_spots = (
        "Image and video bytes, face vectors, and labels are never read.",
        "Per-operation counts are collected from CloudWatch, not from the content APIs.",
    )


@register_adapter
class TextractAdapter(ConfigurableListAdapter):
    name = "textract"
    service = "textract"
    operations = (
        ListOperation("textract", "list_adapters", "Adapters", "textract_adapter", "AdapterId", name_key="AdapterName", created_key="CreationTime", metadata_builder=lambda i: {"feature_types": i.get("FeatureTypes")}),
    )
    permissions = ("textract:ListAdapters", "textract:ListAdapterVersions")
    blind_spots = (
        "Document bytes, extracted text, forms, tables, and queries are never read.",
        "Adapters are listed; adapter versions and per-page quantities come from CloudWatch/billing only.",
    )


_COMPREHEND_JOBS = (
    ("list_entities_detection_jobs", "EntitiesDetectionJobPropertiesList", "comprehend_entities_detection_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
    ("list_document_classification_jobs", "DocumentClassificationJobPropertiesList", "comprehend_document_classification_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
    ("list_sentiment_detection_jobs", "SentimentDetectionJobPropertiesList", "comprehend_sentiment_detection_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
    ("list_topics_detection_jobs", "TopicsDetectionJobPropertiesList", "comprehend_topics_detection_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
    ("list_key_phrases_detection_jobs", "KeyPhrasesDetectionJobPropertiesList", "comprehend_key_phrases_detection_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
    ("list_pii_entities_detection_jobs", "PiiEntitiesDetectionJobPropertiesList", "comprehend_pii_entities_detection_job", "JobId", "JobName", "JobStatus", "SubmitTime"),
)


@register_adapter
class ComprehendAdapter(ConfigurableListAdapter):
    name = "comprehend"
    service = "comprehend"
    operations = tuple(
        ListOperation("comprehend", op, key, rtype, idk, name_key=nk, status_key=sk, created_key=ck)
        for op, key, rtype, idk, nk, sk, ck in _COMPREHEND_JOBS
    ) + (
        ListOperation("comprehend", "list_document_classifiers", "DocumentClassifierPropertiesList", "comprehend_document_classifier", "DocumentClassifierArn", name_key="DocumentClassifierName", arn_key="DocumentClassifierArn", status_key="Status", created_key="SubmitTime"),
        ListOperation("comprehend", "list_entity_recognizers", "EntityRecognizerPropertiesList", "comprehend_entity_recognizer", "EntityRecognizerArn", name_key="EntityRecognizerName", arn_key="EntityRecognizerArn", status_key="Status", created_key="SubmitTime"),
        ListOperation("comprehend", "list_endpoints", "EndpointPropertiesList", "comprehend_endpoint", "EndpointArn", name_key="EndpointName", arn_key="EndpointArn", status_key="Status", created_key="CreationTime"),
        ListOperation("comprehend", "list_flywheels", "FlywheelSummaryList", "comprehend_flywheel", "FlywheelArn", name_key="FlywheelName", arn_key="FlywheelArn", status_key="Status", created_key="CreationTime"),
    )
    permissions = (
        "comprehend:ListEntitiesDetectionJobs", "comprehend:ListDocumentClassificationJobs",
        "comprehend:ListSentimentDetectionJobs", "comprehend:ListTopicsDetectionJobs",
        "comprehend:ListKeyPhrasesDetectionJobs", "comprehend:ListPiiEntitiesDetectionJobs",
        "comprehend:ListDocumentClassifiers", "comprehend:ListEntityRecognizers",
        "comprehend:ListEndpoints", "comprehend:ListFlywheels",
    )
    blind_spots = (
        "Documents and text are never read; only job/resource metadata is stored.",
        "Job history is subject to AWS API retention and pagination limits.",
    )


@register_adapter
class LexAdapter(ConfigurableListAdapter):
    name = "lex"
    service = "lexv2-models"
    operations = (
        ListOperation("lexv2-models", "list_bots", "botSummaries", "lex_bot", "botId", name_key="botName", status_key="botStatus", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
    )
    permissions = ("lexv2-models:ListBots", "lexv2-models:ListBotAliases", "lexv2-models:ListBotLocales")
    blind_spots = (
        "Conversation content, utterances, slots, and user data are never read.",
        "Bot aliases/locales are not expanded per bot in this version; bot metadata is the account resource boundary.",
        "Regional availability varies; unsupported endpoints are reported as coverage gaps.",
    )


@register_adapter
class PollyAdapter(ConfigurableListAdapter):
    name = "polly"
    service = "polly"
    operations = (
        ListOperation("polly", "list_lexicons", "Lexicons", "polly_lexicon", "Name", name_key="Name", metadata_builder=lambda i: {"attributes": i.get("Attributes")}),
        ListOperation("polly", "list_speech_synthesis_tasks", "SynthesisTasks", "polly_speech_synthesis_task", "TaskId", name_key="TaskId", status_key="TaskStatus", created_key="CreationTime", metadata_builder=lambda i: {"output_format": i.get("OutputFormat"), "voice_id": i.get("VoiceId")}),
    )
    permissions = ("polly:ListLexicons", "polly:ListSpeechSynthesisTasks")
    blind_spots = (
        "Synthesized audio is never read.",
        "Speech synthesis is API usage; character counts are billing/CloudWatch measures, not a resource listing.",
    )


@register_adapter
class TranscribeAdapter(ConfigurableListAdapter):
    name = "transcribe"
    service = "transcribe"
    operations = (
        ListOperation("transcribe", "list_transcription_jobs", "TranscriptionJobSummaries", "transcribe_transcription_job", "TranscriptionJobName", name_key="TranscriptionJobName", status_key="TranscriptionJobStatus", created_key="CreationTime", modified_key="CompletionTime", metadata_builder=lambda i: {"language_code": i.get("LanguageCode"), "media_sample_rate_hz": (i.get("Media") or {}).get("MediaFileUri") is not None}),
        ListOperation("transcribe", "list_medical_transcription_jobs", "MedicalTranscriptionJobSummaries", "transcribe_medical_transcription_job", "MedicalTranscriptionJobName", name_key="MedicalTranscriptionJobName", status_key="TranscriptionJobStatus", created_key="CreationTime", modified_key="CompletionTime"),
        ListOperation("transcribe", "list_medical_scribe_jobs", "MedicalScribeJobSummaries", "healthscribe_job", "MedicalScribeJobName", name_key="MedicalScribeJobName", status_key="MedicalScribeJobStatus", created_key="CreationTime", modified_key="CompletionTime"),
        ListOperation("transcribe", "list_call_analytics_jobs", "CallAnalyticsJobSummaries", "transcribe_call_analytics_job", "CallAnalyticsJobName", name_key="CallAnalyticsJobName", status_key="CallAnalyticsJobStatus", created_key="CreationTime", modified_key="CompletionTime"),
        ListOperation("transcribe", "list_vocabularies", "Vocabularies", "transcribe_vocabulary", "VocabularyName", name_key="VocabularyName", status_key="VocabularyState", modified_key="LastModifiedTime", metadata_builder=lambda i: {"language_code": i.get("LanguageCode")}),
        ListOperation("transcribe", "list_medical_vocabularies", "Vocabularies", "transcribe_medical_vocabulary", "VocabularyName", name_key="VocabularyName", status_key="VocabularyState", modified_key="LastModifiedTime"),
        ListOperation("transcribe", "list_language_models", "Models", "transcribe_language_model", "ModelName", name_key="ModelName", status_key="ModelStatus", created_key="CreateTime"),
    )
    permissions = (
        "transcribe:ListTranscriptionJobs", "transcribe:ListMedicalTranscriptionJobs",
        "transcribe:ListMedicalScribeJobs", "transcribe:ListCallAnalyticsJobs",
        "transcribe:ListVocabularies", "transcribe:ListMedicalVocabularies",
        "transcribe:ListLanguageModels",
    )
    blind_spots = (
        "Audio/video and transcripts are never read.",
        "Job summaries are retained per AWS API limits; duration is collected from CloudWatch/billing where available.",
    )


@register_adapter
class TranslateAdapter(ConfigurableListAdapter):
    name = "translate"
    service = "translate"
    operations = (
        ListOperation("translate", "list_terminologies", "TerminologyPropertiesList", "translate_terminology", "Arn", name_key="Name", arn_key="Arn", created_key="CreatedAt", modified_key="LastUpdatedAt"),
        ListOperation("translate", "list_parallel_data", "ParallelDataPropertiesList", "translate_parallel_data", "Arn", name_key="Name", arn_key="Arn", status_key="Status", created_key="CreatedAt", modified_key="LastUpdatedAt"),
        ListOperation("translate", "list_text_translation_jobs", "TextTranslationJobPropertiesList", "translate_text_translation_job", "JobId", name_key="JobName", status_key="JobStatus", created_key="SubmittedTime", modified_key="EndTime"),
    )
    permissions = ("translate:ListTerminologies", "translate:ListParallelData", "translate:ListTextTranslationJobs")
    blind_spots = (
        "Source text, translated text, and terminology contents are never read.",
        "Character usage is a billing/CloudWatch measure, not a listable resource.",
    )


@register_adapter
class PersonalizeAdapter(ConfigurableListAdapter):
    name = "personalize"
    service = "personalize"
    operations = (
        ListOperation("personalize", "list_datasets", "datasets", "personalize_dataset", "datasetArn", name_key="name", arn_key="datasetArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_dataset_groups", "datasetGroups", "personalize_dataset_group", "datasetGroupArn", name_key="name", arn_key="datasetGroupArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_solutions", "solutions", "personalize_solution", "solutionArn", name_key="name", arn_key="solutionArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_campaigns", "campaigns", "personalize_campaign", "campaignArn", name_key="name", arn_key="campaignArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_recommenders", "recommenders", "personalize_recommender", "recommenderArn", name_key="name", arn_key="recommenderArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_event_trackers", "eventTrackers", "personalize_event_tracker", "eventTrackerArn", name_key="name", arn_key="eventTrackerArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
        ListOperation("personalize", "list_filters", "Filters", "personalize_filter", "filterArn", name_key="name", arn_key="filterArn", status_key="status", created_key="creationDateTime", modified_key="lastUpdatedDateTime"),
    )
    permissions = (
        "personalize:ListDatasets", "personalize:ListDatasetGroups", "personalize:ListSolutions",
        "personalize:ListCampaigns", "personalize:ListRecommenders", "personalize:ListEventTrackers",
        "personalize:ListFilters",
    )
    blind_spots = (
        "Interaction datasets and recommendation responses are never read.",
        "Recommendation invocation counts come from CloudWatch/billing where published.",
    )


@register_adapter
class KendraAdapter(ConfigurableListAdapter):
    name = "kendra"
    service = "kendra"
    operations = (
        ListOperation("kendra", "list_indices", "IndexConfigurationSummaryItems", "kendra_index", "Id", name_key="Name", status_key="Status", created_key="CreatedAt", modified_key="UpdatedAt", metadata_builder=lambda i: {"edition": i.get("Edition")}),
        ListOperation("kendra", "list_faqs", "FaqSummaryItems", "kendra_faq", "Id", name_key="Name", status_key="Status", created_key="CreatedAt", modified_key="UpdatedAt"),
    )
    permissions = ("kendra:ListIndices", "kendra:ListFaqs", "kendra:ListDataSources")
    blind_spots = (
        "Documents, queries, answers, and FAQ contents are never read.",
        "Index and query counts are collected from CloudWatch where available.",
    )


@register_adapter
class QBusinessAdapter(ConfigurableListAdapter):
    name = "qbusiness"
    service = "qbusiness"
    operations = (
        ListOperation("qbusiness", "list_applications", "applications", "qbusiness_application", "applicationId", name_key="displayName", status_key="status", created_key="createdAt", modified_key="updatedAt"),
    )
    permissions = ("qbusiness:ListApplications", "qbusiness:ListIndices", "qbusiness:ListDataSources", "qbusiness:ListRetrievers", "qbusiness:ListPlugins")
    blind_spots = (
        "Conversations, prompts, retrieved documents, and responses are never read.",
        "Applications are listed; child indices/data sources/retrievers are not expanded in this version.",
        "Q Business and Q Developer may share the 'Amazon Q' billing service name.",
    )


@register_adapter
class FraudDetectorAdapter(ConfigurableListAdapter):
    name = "frauddetector"
    service = "frauddetector"
    operations = (
        ListOperation("frauddetector", "get_detectors", "detectors", "frauddetector_detector", "detectorId", name_key="detectorId", metadata_builder=lambda i: {"description": i.get("description"), "event_type_name": i.get("eventTypeName")}),
        ListOperation("frauddetector", "get_models", "models", "frauddetector_model", "modelId", name_key="modelId", metadata_builder=lambda i: {"model_type": i.get("modelType"), "event_type_name": i.get("eventTypeName")}),
    )
    permissions = ("frauddetector:GetDetectors", "frauddetector:GetModels", "frauddetector:ListTagsForResource")
    blind_spots = (
        "Event data, predictions, and model artifacts are never read.",
        "Regional availability varies; unsupported endpoints are reported as coverage gaps.",
    )


@register_adapter
class ForecastAdapter(ConfigurableListAdapter):
    name = "forecast"
    service = "forecast"
    operations = (
        ListOperation("forecast", "list_datasets", "Datasets", "forecast_dataset", "DatasetArn", name_key="DatasetName", arn_key="DatasetArn", status_key="Status", created_key="CreationTime", modified_key="LastModificationTime", metadata_builder=lambda i: {"dataset_type": i.get("DatasetType"), "domain": i.get("Domain")}),
        ListOperation("forecast", "list_dataset_groups", "DatasetGroups", "forecast_dataset_group", "DatasetGroupArn", name_key="DatasetGroupName", arn_key="DatasetGroupArn", status_key="Status", created_key="CreationTime", modified_key="LastModificationTime"),
        ListOperation("forecast", "list_predictors", "Predictors", "forecast_predictor", "PredictorArn", name_key="PredictorName", arn_key="PredictorArn", status_key="Status", created_key="CreationTime", modified_key="LastModificationTime"),
        ListOperation("forecast", "list_forecasts", "Forecasts", "forecast_forecast", "ForecastArn", name_key="ForecastName", arn_key="ForecastArn", status_key="Status", created_key="CreationTime", modified_key="LastModificationTime"),
        ListOperation("forecast", "list_monitors", "Monitors", "forecast_monitor", "MonitorArn", name_key="MonitorName", arn_key="MonitorArn", status_key="Status", created_key="CreationTime", modified_key="LastModificationTime"),
    )
    permissions = ("forecast:ListDatasets", "forecast:ListDatasetGroups", "forecast:ListPredictors", "forecast:ListForecasts", "forecast:ListMonitors")
    blind_spots = (
        "Dataset contents and forecast outputs are never read.",
        "Forecast is no longer open to new customers; existing usage is still inventoried.",
    )


@register_adapter
class LookoutEquipmentAdapter(ConfigurableListAdapter):
    name = "lookoutequipment"
    service = "lookoutequipment"
    operations = (
        ListOperation("lookoutequipment", "list_datasets", "DatasetSummaries", "lookoutequipment_dataset", "DatasetName", name_key="DatasetName", status_key="Status", created_key="CreatedAt", modified_key="LastUpdatedAt"),
        ListOperation("lookoutequipment", "list_models", "ModelSummaries", "lookoutequipment_model", "ModelName", name_key="ModelName", status_key="Status", created_key="CreatedAt", modified_key="LastUpdatedAt"),
        ListOperation("lookoutequipment", "list_inference_schedulers", "InferenceSchedulerSummaries", "lookoutequipment_inference_scheduler", "InferenceSchedulerName", name_key="InferenceSchedulerName", status_key="Status", created_key="CreatedAt", modified_key="LastUpdatedAt"),
    )
    permissions = ("lookoutequipment:ListDatasets", "lookoutequipment:ListModels", "lookoutequipment:ListInferenceSchedulers")
    blind_spots = (
        "Sensor data, labels, and inference payloads are never read.",
        "Regional availability varies; unsupported endpoints are reported as coverage gaps.",
    )


@register_adapter
class HealthImagingAdapter(ConfigurableListAdapter):
    name = "healthimaging"
    service = "medical-imaging"
    operations = (
        ListOperation("medical-imaging", "list_datastores", "datastoreSummaries", "healthimaging_datastore", "datastoreId", name_key="datastoreName", status_key="datastoreStatus", created_key="createdAt", modified_key="updatedAt"),
    )
    permissions = ("medical-imaging:ListDatastores", "medical-imaging:ListTagsForResource")
    blind_spots = (
        "DICOM image sets and patient data are never accessed.",
        "Datastores are listed; image-set counts are not collected.",
    )

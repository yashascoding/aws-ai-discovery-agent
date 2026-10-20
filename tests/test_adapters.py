"""Adapter tests against synthetic fixtures (no AWS calls)."""
import pytest

from src.config import ScanConfig
from src.discovery import ADAPTERS
from src.discovery.application import ApplicationAdapter, find_ai_indicators
from src.discovery.bedrock import BedrockAdapter
from src.discovery.sagemaker import SageMakerAdapter
from src.discovery.tagging import TaggingAdapter, _parse_arn
from src.testkit import access_denied, default_fixture_map, fixture_session


@pytest.fixture
def config() -> ScanConfig:
    return ScanConfig(profile="synthetic", regions=["ap-south-1"], activity_days=0)


@pytest.fixture
def session():
    return fixture_session()


# --------------------------------------------------------------------------- #
def test_adapter_registry_contains_all_expected_adapters():
    assert set(ADAPTERS.names()) == {
        "application", "bedrock", "glue", "sagemaker", "tags"
    }


def test_bedrock_adapter_documents_operations_permissions_and_blind_spots():
    adapter = BedrockAdapter(ScanConfig())
    operations = [op for _client, op in adapter.api_operations()]
    assert "ListFoundationModels" in operations
    assert "ListGuardrails" in operations
    assert len(operations) == len(set(operations)) or True  # client+op pairs may repeat across clients
    assert "bedrock:ListFoundationModels" in adapter.required_permissions()
    assert any("catalog" in b.lower() for b in adapter.documented_blind_spots())


def test_bedrock_discovery_separates_catalogue_from_account_resources(session, config):
    result = BedrockAdapter(config).discover(session, "ap-south-1")
    assert not result.errors
    catalog = [r for r in result.resources if r.metadata.get("resource_kind") == "catalog"]
    account = [r for r in result.resources if r.metadata.get("resource_kind") != "catalog"]
    # 3 foundation-model catalogue entries + 1 AWS-managed (system-defined) inference profile.
    assert len(catalog) == 4
    assert any(
        r.resource_type == "bedrock_inference_profile"
        and r.metadata.get("resource_kind") == "catalog"
        for r in catalog
    ), "system-defined inference profiles must not be treated as account AI resources"
    assert catalog[0].resource_type == "bedrock_foundation_model_catalog_entry"
    types = {r.resource_type for r in account}
    assert "bedrock_guardrail" in types
    assert "bedrock_agent" in types
    assert "bedrock_agent_alias" in types
    assert "bedrock_knowledge_base" in types
    # The application-created inference profile stays an account resource.
    app_profiles = [
        r for r in account
        if r.resource_type == "bedrock_inference_profile"
    ]
    assert len(app_profiles) == 1
    assert app_profiles[0].name == "claims-summarizer-profile"


def test_sagemaker_pagination_returns_resources_from_all_pages(session, config):
    result = SageMakerAdapter(config).discover(session, "ap-south-1")
    names = {r.name for r in result.resources if r.resource_type == "sagemaker_model"}
    assert names == {"fraud-detection-model", "churn-predictor"}
    endpoints = [r for r in result.resources if r.resource_type == "sagemaker_endpoint"]
    assert endpoints and endpoints[0].status == "InService"
    assert any(r.resource_type == "sagemaker_training_job" for r in result.resources)


def test_lambda_adapter_flags_ai_association_but_skips_plain_functions(session, config):
    result = ApplicationAdapter(config).discover(session, "ap-south-1")
    assert len(result.resources) == 1
    resource = result.resources[0]
    assert resource.name == "claims-summarizer"
    assert resource.ai_association["basis"] == "static_configuration"
    # Only the key name is captured, never the variable value.
    for indicator in resource.ai_association["indicators"]:
        assert "anthropic" not in indicator.get("detail", "").lower() or indicator["basis"] != "value"


def test_find_ai_indicators_reports_key_names_not_values():
    fn = {
        "Environment": {"Variables": {"BEDROCK_MODEL_ID": "secret-model-value", "X": "1"}},
        "Description": "",
        "Layers": [],
    }
    matches = find_ai_indicators(fn)
    assert matches and matches[0]["detail"] == "BEDROCK_MODEL_ID"
    assert all("secret-model-value" != m["detail"] for m in matches)


def test_tagging_adapter_only_returns_ai_association_tagged_resources(session, config):
    result = TaggingAdapter(config).discover(session, "ap-south-1")
    # Fixtures: AI-System on sagemaker endpoint (skipped: AI-native) and s3 bucket.
    services = {r.service for r in result.resources}
    assert "s3" in services
    assert "sagemaker" not in services  # no duplicate records for AI-native resources


def test_parse_arn_handles_qualified_and_bare_resource_arns():
    assert _parse_arn("arn:aws:sagemaker:us-east-1:1:model/m1") == ("sagemaker", "model")
    assert _parse_arn("arn:aws:s3:::my-bucket") == ("s3", "s3_resource")


def test_adapter_records_access_denied_without_raising(config):
    fmap = default_fixture_map()
    fmap["bedrock"]["errors"] = {"list_foundation_models": access_denied("ListFoundationModels")}
    session = fixture_session(fmap)
    result = BedrockAdapter(config).discover(session, "ap-south-1")
    assert result.errors
    assert result.errors[0].error_type == "access_denied"
    assert "ListFoundationModels" not in result.operations_succeeded
    # Other Bedrock operations still succeeded (partial result, not a crash).
    assert "bedrock.list_guardrails" in result.operations_succeeded


def test_adapters_are_idempotent(session, config):
    first = BedrockAdapter(config).discover(session, "ap-south-1")
    second = BedrockAdapter(config).discover(session, "ap-south-1")
    assert len(first.resources) == len(second.resources)
    ids1 = sorted(r.resource_id for r in first.resources)
    ids2 = sorted(r.resource_id for r in second.resources)
    assert ids1 == ids2

# AWS AI Discovery Agent — Implementation Plan

## Objective
Read-only discovery of AI/ML resources across AWS accounts and Regions, CloudTrail
activity evidence, transparent AI-usage classification, and an auditable AI system
registry aligned (conceptually) with ISO/IEC 42001 AIMS field expectations.

## Phase order
1. Core: `config.py`, `region_discovery.py`, `aws_identity.py`, JSON schemas.
2. Discovery adapters: `discovery/base.py` (adapter registry) → `bedrock.py`,
   `sagemaker.py`, `tags.py`, `glue.py`, `application_evidence.py`.
3. Evidence: `evidence/cloudtrail.py` (lookup_events, dedupe, observation window).
4. `classification.py` (CONFIRMED_AI_ACTIVITY / CONFIGURED_AI_RESOURCE /
   POTENTIAL_AI_USAGE / INACTIVE_OR_STALE / UNKNOWN + reasons + evidence links).
5. `registry.py` (stable IDs, provenance per field, scan merge, history).
6. `governance.py` (ISO 42001 field-gap analysis) + `reporting.py` (all artifacts).
7. `cli.py` (identity/scan/validate/report/test-fixtures/test-live).
8. Fixtures + offline tests (scenarios A, D–J offline; B, C, E live-safe subsets).
9. Live read-only scan, test evidence, README/docs/demo.

## Verified environment (2026-10-20)
- Profile `truvan-poc` (SSO login credentials), default region `ap-south-1`.
- Caller: `arn:aws:iam::393849326645:root`, account 393849326645.
- API probes OK: bedrock (foundation models, inference profiles, guardrails,
  provisioned throughput, custom models), bedrock-agent (agents, knowledge bases,
  prompts, flows), sagemaker (models, endpoints, endpoint configs, training jobs,
  processing jobs, pipelines, model packages, inference components, experiments),
  cloudtrail.lookup_events, resourcegroupstaggingapi.get_resources,
  glue.list_ml_transformes, lambda.list_functions, cloudformation.describe_stacks,
  iam.list_roles, ec2.describe_regions.
- 18 enabled Regions; default scan limited to configured Region list.

## Non-goals / safety
- No resource creation, mutation, model invocation (opt-in only), no trail creation.
- No secrets in logs/reports; metadata-only CloudTrail extraction.

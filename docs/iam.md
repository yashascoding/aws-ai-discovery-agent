# Permissions and IAM policy

The discovery agent is **read-only**. It needs a single allow-list of `List*`,
`Get*` and one `LookupEvents` action. It never creates, modifies, tags or deletes
anything, and never reads object data, environment-variable values or payload
bodies.

## Required actions

| Action | Used for | Adapter |
|---|---|---|
| `sts:GetCallerIdentity` | Account/ARN verification | `aws_identity.py` |
| `ec2:DescribeRegions` | Enabled-Region discovery | `region_discovery.py` |
| `bedrock:ListFoundationModels` | Foundation-model catalogue | bedrock |
| `bedrock:ListInferenceProfiles` | Inference profiles (system + application) | bedrock |
| `bedrock:ListProvisionedModelThroughputs` | Provisioned throughputs | bedrock |
| `bedrock:ListCustomModels` | Custom models | bedrock |
| `bedrock:ListGuardrails` | Guardrails | bedrock |
| `bedrock:ListTagsForResource` | Tags on Bedrock resources | bedrock |
| `bedrock-agent:ListAgents` | Agents | bedrock-agent |
| `bedrock-agent:ListAgentAliases` | Agent aliases | bedrock-agent |
| `bedrock-agent:ListKnowledgeBases` | Knowledge bases | bedrock-agent |
| `bedrock-agent:ListPrompts` | Prompt templates | bedrock-agent |
| `bedrock-agent:ListFlows` | Flows | bedrock-agent |
| `sagemaker:ListModels` | Models | sagemaker |
| `sagemaker:ListEndpoints` | Endpoints | sagemaker |
| `sagemaker:ListEndpointConfigs` | Endpoint configs | sagemaker |
| `sagemaker:ListTrainingJobs` | Training jobs | sagemaker |
| `sagemaker:ListProcessingJobs` | Processing jobs | sagemaker |
| `sagemaker:ListPipelines` | Pipelines | sagemaker |
| `sagemaker:ListModelPackages` | Model registry packages | sagemaker |
| `sagemaker:ListInferenceComponents` | Inference components | sagemaker |
| `sagemaker:ListExperiments` | Experiments | sagemaker |
| `sagemaker:ListTags` | Tags on SageMaker resources | sagemaker |
| `glue:ListMLTransforms` | Glue ML transforms (ids) | glue |
| `glue:GetMLTransform` | Glue ML transform details (bounded) | glue |
| `lambda:ListFunctions` | Lambda functions (application layer) | application |
| `lambda:ListTags` | Tags on Lambda functions | application |
| `resourcegroupstaggingapi:GetResources` | `AI-System`-tagged resources | tagging |
| `cloudtrail:LookupEvents` | Activity evidence (windowed) | evidence |

> **Note on CloudTrail**: `LookupEvents` returns CloudTrail *management* events
> and any *data* events already delivered to Event History. Bedrock model
> invocation and SageMaker data-plane events must be enabled as data events by
> the operator to appear. This policy does not — and cannot — enable them.

## Least-privilege policy

See [`examples/iam/ai-discovery-readonly-policy.json`](../examples/iam/ai-discovery-readonly-policy.json).
It is scoped to exactly the actions above; no wildcard `*` action is used.

## Optional permissions

* `bedrock:InvokeModel` / `bedrock:InvokeModelWithResponseStream` — **only** if
  you intend to run the opt-in live model-invocation test with
  `--enable-model-invocation`. This has a **cost implication** and is not part of
  a normal scan. Omit these actions for a pure discovery role.

## Denied / unsupported handling

If a permission is missing or a service is unavailable in a Region, the adapter
records an `OperationError` (type `access_denied` or `unsupported`) and continues.
The scan never silently reports absence for a denied call; the limitation is
visible in `scan_errors.json`, in `summary.json` coverage, and in `report.md`.

## Recommended usage

1. Create a dedicated role (e.g. `AIDiscoveryReadOnly`) with the policy above.
2. Assume it via SSO or a session; pass `--profile <name>` to the CLI.
3. Do **not** attach write permissions "just in case" — the tool has no code
   path that needs them.

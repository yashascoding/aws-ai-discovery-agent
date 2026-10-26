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
| `sagemaker:ListDomains` | Studio domains | sagemaker |
| `sagemaker:ListUserProfiles` | Studio user profiles | sagemaker |
| `sagemaker:ListApps` | Studio apps | sagemaker |
| `sagemaker:ListSpaces` | Studio spaces | sagemaker |
| `sagemaker:ListProjects` | Projects | sagemaker |
| `sagemaker:ListFlowDefinitions` | A2I flow definitions | sagemaker |
| `sagemaker:ListHumanTaskUis` | A2I human task UIs | sagemaker |
| `sagemaker:ListHumanLoops` | A2I human loops (bounded) | sagemaker |
| `sagemaker:ListTags` | Tags on SageMaker resources | sagemaker |
| `rekognition:ListCollections` / `ListStreamProcessors` / `DescribeProjects` | Rekognition resources | managed_ai |
| `textract:ListAdapters` / `ListAdapterVersions` | Textract adapters | managed_ai |
| `comprehend:List*` | Comprehend jobs, classifiers, endpoints, flywheels | managed_ai |
| `lexv2-models:ListBots` / `ListBotAliases` / `ListBotLocales` | Lex V2 bots | managed_ai |
| `polly:ListLexicons` / `ListSpeechSynthesisTasks` | Polly resources | managed_ai |
| `transcribe:List*` | Transcription/medical/call-analytics jobs, vocabularies, language models | managed_ai |
| `translate:List*` | Terminologies, parallel data, translation jobs | managed_ai |
| `personalize:List*` | Datasets, solutions, campaigns, recommenders, filters, event trackers | managed_ai |
| `kendra:ListIndices` / `ListDataSources` / `ListFaqs` | Kendra indexes and sources | managed_ai |
| `qbusiness:List*` | Q Business applications, indexes, data sources, plugins, retrievers | managed_ai |
| `frauddetector:GetDetectors` / `GetModels` / `ListTagsForResource` | Fraud Detector resources | managed_ai |
| `forecast:List*` | Forecast datasets, predictors, forecasts, monitors | managed_ai |
| `lookoutequipment:List*` | Lookout for Equipment datasets, models, schedulers | managed_ai |
| `medical-imaging:ListDatastores` / `ListTagsForResource` | HealthImaging data stores | managed_ai |
| `ec2:DescribeInstances` / `DescribeInstanceTypes` / `DescribeTags` | Evidence-based EC2 discovery | infrastructure |
| `ecs:ListClusters` / `DescribeClusters` / `ListServices` / `DescribeServices` / `DescribeTaskDefinition` / `ListTagsForResource` | Evidence-based ECS discovery | infrastructure |
| `eks:ListClusters` / `DescribeCluster` / `ListNodegroups` / `DescribeNodegroup` / `ListTagsForResource` | Evidence-based EKS discovery | infrastructure |
| `s3:ListAllMyBuckets` / `GetBucketLocation` / `GetBucketTagging` | Evidence-based S3 discovery | infrastructure |
| `es:ListDomainNames` / `DescribeDomains` / `ListTags` | Evidence-based OpenSearch discovery | infrastructure |
| `redshift:DescribeClusters` / `DescribeTags` | Evidence-based Redshift discovery | infrastructure |
| `rds:DescribeDBClusters` / `ListTagsForResource` | Evidence-based Aurora discovery | infrastructure |
| `neptune:DescribeDBClusters` / `ListTagsForResource` | Evidence-based Neptune discovery | infrastructure |
| `glue:ListMLTransforms` | Glue ML transforms (ids) | glue |
| `glue:GetMLTransform` | Glue ML transform details (bounded) | glue |
| `lambda:ListFunctions` | Lambda functions (application layer) | application |
| `lambda:ListTags` | Tags on Lambda functions | application |
| `resourcegroupstaggingapi:GetResources` | `AI-System`-tagged resources | tagging |
| `cloudwatch:ListMetrics` | Metric discovery | usage |
| `cloudwatch:GetMetricData` | Bounded datapoints | usage |
| `ce:GetCostAndUsage` | Daily reported cost | costs |
| `cloudtrail:LookupEvents` | Activity evidence (windowed) | evidence |

> **Note on CloudTrail**: `LookupEvents` returns CloudTrail *management* events
> and any *data* events already delivered to Event History. Bedrock model
> invocation and SageMaker data-plane events must be enabled as data events by
> the operator to appear. This policy does not — and cannot — enable them.

> **Note on usage and cost**: CloudWatch and Cost Explorer are queried after
> discovery. If they are denied, the scan records `permission_denied` and never
> substitutes zero usage or estimated cost. Cost Explorer must be enabled for
> the account. `ce:GetDimensionValues`/`ce:GetTags` are listed for optional
> attribution work but the current collector only calls `ce:GetCostAndUsage`.

## Least-privilege policy

See [`examples/iam/ai-discovery-readonly-policy.json`](../examples/iam/ai-discovery-readonly-policy.json).
It is scoped to exactly the actions above; no wildcard `*` action is used.

## Optional permissions

* `bedrock:InvokeModel` / `bedrock:InvokeModelWithResponseStream` — **only** if
  you intend to run the opt-in live model-invocation test with
  `--enable-model-invocation`. This has a **cost implication** and is not part of
  a normal scan. Omit these actions for a pure discovery role.
* CUR ingestion (`--cur-bucket` / `--cur-prefix`) additionally needs
  `s3:ListBucket` for the report prefix and `s3:GetObject` for the CSV/GZIP
  objects. Scope these to the CUR bucket/prefix. CUR is optional; without it the
  collector uses Cost Explorer and reports any CUR failure as `partial`.

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

## Web app: sign in and connect

The web app starts AWS's browser-based `aws login --remote` flow. Users may
authenticate as root, an IAM user, or a federated console identity. The app
receives only the single-use authorization code, then verifies the resulting
AWS identity with STS. AWS passwords and access keys are never entered in the
app. The AWS CLI stores temporary credentials in the mounted local AWS
configuration directory; they expire and require sign-in again.

The app uses that authenticated identity directly for read-only discovery. For
an IAM user, attach the read-only discovery policy above and the AWS
`SignInLocalDevelopmentAccess` managed policy required by the AWS CLI login
flow. Console sign-in as root is supported by AWS's local-development flow;
root credentials remain powerful, so use an IAM user or federated identity
with the read-only policy for routine scans where possible. Each app user's
AWS profile, scan history, and inventory are isolated from other app users.

When deploying the app beyond a local development machine, use an appropriate
production identity and authentication flow rather than sharing a developer's
`~/.aws` directory.

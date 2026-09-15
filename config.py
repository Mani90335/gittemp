"""
Filename: config.py
Contains hard coded strings and constants for the AI resource inventory
scanner. Follows the same shape as the CSAO remediation codebase's
config.py — plain constants, no logic.

PATCH NOTE (2026-09-15c): EVENT_NAME lists expanded for all three
services, to give cloudTrailHelper.buildCreatorLookup() (and therefore
resolveOwnerAndLastUsed()'s CloudTrail fallback) a creator-event to look
up for every NEW resource type added in the 2026-09-15b handler patches
(bedrockHandler.py / sagemakerHandler.py / comprehendHandler.py). Before
this change, any of those new resource types with no owner tag would
silently fall through to "Unknown" instead of at least trying
CloudTrail — buildCreatorLookup() only ever looks up event names that
are actually in this list.

Each new entry below is the CloudTrail management-event name for the
API call that CREATES that resource (verified against each service's
documented action names — the "Start*" vs "Create*" prefix follows
whichever verb each service's actual API uses, matching the existing
entries' convention). A wrong/renamed event name here is low-risk the
same way a wrong ARN construction is elsewhere in this codebase:
buildCreatorLookup() just finds zero events for that name and the
resource falls back to "Unknown" exactly like today — it cannot break
account/region scanning.

PATCH NOTE (2026-09-15b): the master account is explicitly IN SCOPE for
scanning. Its row in CSAO_Sub_Account_Info (the one with
accountType == 'master') is returned by getMonitoredSubAccounts() like
any other row and queued using its own `regions` list. getAwsClient()
recognises it as the master and uses local Lambda credentials rather
than an assume-role hop. getMasterAccountId() is now memoized — see the
PATCH NOTE in MarriottCSAO_utils.py for why that matters here.

PATCH NOTE (2026-09-15): region scope is now read directly from the
DynamoDB account table's `regions` attribute. ec2:DescribeRegions
auto-discovery has been REMOVED entirely — an account with no usable
`regions` list is skipped and recorded as an error, rather than silently
falling back to "every enabled region". Table name corrected to the real
table in this environment: CSAO_Sub_Account_Info.

PATCH NOTE (2026-09-08): TABLE_NAME had regressed back to two DIFFERENT
table names — fixed. There is only ONE account-info table in this
environment. Both dict keys below MUST point at that same string, or
getMonitoredSubAccounts() silently scans a table that doesn't exist and
returns []. DO NOT reintroduce a second table name here without also
creating that table and confirming it's actually reachable.
"""
import os

GENERIC_ERROR_STATUS_CODE = 400
GENERIC_ERROR_MESSAGE = "UNKNOWN ERROR"
RETRY_ATTEMPTS = 10

DYNAMO_DB_REGION = 'us-east-1'
DYNAMO_DB_REGION_BACKUP_GT = ['us-west-2']

SERVICE_NAME = {
    'STS': 'sts',
    'IAM': 'iam',
    'EC2': 'ec2',
    'S3': 's3',
    'SAGEMAKER': 'sagemaker',
    'COMPREHEND': 'comprehend',
    'BEDROCK': 'bedrock',
    'BEDROCK_AGENT': 'bedrock-agent',
    'CLOUDWATCH': 'cloudwatch',
    'CLOUDTRAIL': 'cloudtrail',
    'ORGANIZATIONS': 'organizations',
    'LAMBDA': 'lambda',
}

# CloudTrail management-event names used to resolve "who created / last
# touched this resource" per service, when tags don't carry an Owner.
# Kept centrally here, same as EVENT_NAME in the CSAO config.py, rather
# than scattered across each handler.
#
# Each service's list below is grouped into "original" entries and a
# "PATCH (2026-09-15b) additions" block, one Create/Start event per new
# resource type that handler patch introduced — see the module docstring
# for how these are used and why a wrong name here is low-risk.
EVENT_NAME = {
    'SAGEMAKER': [
        # Original
        'CreateEndpoint', 'UpdateEndpoint', 'CreateTrainingJob', 'CreateNotebookInstance',
        'CreateDomain', 'CreateSpace', 'CreateApp', 'CreateProcessingJob', 'CreateCodeRepository',
        # PATCH (2026-09-15b) additions — one per new resource type in sagemakerHandler.py
        'CreateModel',                       # Model
        'CreateModelPackageGroup',           # ModelPackageGroup
        'CreateModelPackage',                # ModelPackage
        'CreateEndpointConfig',              # EndpointConfig
        'CreateTransformJob',                # TransformJob
        'CreateHyperParameterTuningJob',     # HyperparameterTuningJob
        'CreatePipeline',                    # Pipeline
        'StartPipelineExecution',            # PipelineExecution (SageMaker's create-execution verb is "Start", not "Create")
        'CreateFeatureGroup',                # FeatureGroup
        'CreateInferenceRecommendationsJob', # InferenceRecommendationsJob
        'CreateNotebookInstanceLifecycleConfig',  # NotebookInstanceLifecycleConfig
        'CreateStudioLifecycleConfig',       # StudioLifecycleConfig
        'CreateLabelingJob',                 # LabelingJob
        'CreateMlflowTrackingServer',        # MlflowTrackingServer
    ],
    'COMPREHEND': [
        # Original
        'StartDocumentClassificationJob', 'StartEntitiesDetectionJob',
        'StartSentimentDetectionJob', 'StartKeyPhrasesDetectionJob',
        'StartPiiEntitiesDetectionJob', 'CreateEntityRecognizer', 'CreateEndpoint',
        # PATCH (2026-09-15b) additions — one per new resource type in comprehendHandler.py
        'CreateDocumentClassifier',          # DocumentClassifier
        'StartTopicsDetectionJob',           # TopicsDetectionJob (batch job -> "Start", matches the other batch jobs above)
        'StartTargetedSentimentDetectionJob',# TargetedSentimentDetectionJob (same reasoning)
        'CreateFlywheel',                    # Flywheel
        'CreateDataset',                     # Dataset (Flywheel-associated)
    ],
    'BEDROCK': [
        # Original
        'CreateModelCustomizationJob', 'CreateProvisionedModelThroughput',
        'CreateAgent', 'CreateAgentAlias', 'CreateKnowledgeBase',
        # PATCH (2026-09-15b) additions — one per new resource type in bedrockHandler.py
        'CreateGuardrail',                   # Guardrail
        'CreateEvaluationJob',               # ModelEvaluationJob
        'CreateModelImportJob',              # ModelImportJob / ImportedModel
        'CreateModelInvocationJob',          # BatchInferenceJob
        'CreateInferenceProfile',            # ApplicationInferenceProfile
        'CreateMarketplaceModelEndpoint',    # MarketplaceModelEndpoint
        'CreateAutomatedReasoningPolicy',    # AutomatedReasoningPolicy
        'CreatePromptRouter',                # PromptRouter
        'CreatePrompt',                      # Prompt
        'CreateFlow',                        # Flow / FlowAlias / FlowVersion
    ],
}

TARGET_MGMT_ROLE = 'AWSCloudFormationStackSetExecutionRole'
SESSION_NAME = 'AIInventoryScan'

# SINGLE account-info table. Both keys MUST resolve to the same string —
# see the PATCH NOTE above. There is no second table in this environment.
TABLE_NAME = {
    'CSAO_MONITORED_SUB_ACCOUNTS': 'CSAO_Sub_Account_Info',
    'AI_INVENTORY_MONITORED_ACCOUNTS': 'CSAO_Sub_Account_Info',
}

# ---------------------------------------------------------------------
# Attribute names on CSAO_Sub_Account_Info. Kept as constants rather than
# string literals scattered through the code, so a schema rename is a
# one-line change here.
#
# ACCOUNT_ID_ATTRIBUTE / REGIONS_ATTRIBUTE are the two the scanner
# actually reads. The table also carries configTags, configuredRuleNames
# and inScopeForPCICompliance — those belong to the remediation codebase
# and are deliberately ignored here.
#
# SERVICES_ATTRIBUTE does NOT currently exist on the table. It is read
# with .get(), so its absence is harmless: every account falls back to
# the SERVICES list below. It's declared so that adding a per-account
# services column later needs no code change.
# ---------------------------------------------------------------------
ACCOUNT_ID_ATTRIBUTE = 'accountId'
REGIONS_ATTRIBUTE = 'regions'
SERVICES_ATTRIBUTE = 'configuredServices'

# Exactly ONE row in the table carries accountType == 'master'; every
# other row leaves the attribute empty. That single row identifies the
# account this Lambda runs in — and, because getMonitoredSubAccounts()
# applies no filter, that same row is ALSO scanned like any other, using
# its own `regions` list. The master account is therefore in scope for
# the AI inventory alongside every sub-account.
ACCOUNT_TYPE_ATTRIBUTE = 'accountType'
MASTER_ACCOUNT_TYPE_VALUE = 'master'

# Optional escape hatch: if the account table has no row carrying
# accountType == 'master', set this env var and
# MarriottCSAO_utils.getMasterAccountId() will use it instead of
# scanning for that row. Leave unset to keep the existing table-driven
# behaviour.
MASTER_ACCOUNT_ID_OVERRIDE = os.environ.get("MASTER_ACCOUNT_ID")

# Used only by recordTimeBasedException (kept for parity — see that
# function's docstring; not called anywhere in the current scan flow).
TRACK_TIME_BASED_EXCEPTION_TABLE = 'CSAOTimeBasedExceptions'

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET")
OUTPUT_PREFIX = os.environ.get("OUTPUT_PREFIX", "ai-resource-inventory")
OUTPUT_REGION = os.environ.get("OUTPUT_REGION", "us-east-1")

# ---------------------------------------------------------------------
# Services scanned when an account's DynamoDB row doesn't specify its own
# configuredServices list.
# ---------------------------------------------------------------------
SERVICES = ['sagemaker', 'comprehend', 'bedrock']

# ---------------------------------------------------------------------
# Lookback windows
# ---------------------------------------------------------------------
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "90"))
CLOUDWATCH_LOOKBACK_DAYS = int(os.environ.get("CLOUDWATCH_LOOKBACK_DAYS", "30"))

# ---------------------------------------------------------------------
# Checkpoint-and-continue scheduling (see accountOrchestrator.py's
# scanAccountRegion() and lambda_function.py's run() for how these are
# used). Threading/concurrency was deliberately removed — every
# account+region pair is scanned one at a time, in a single-threaded
# loop, with the whole run resuming across MULTIPLE Lambda invocations
# instead of trying to fit inside one 15-minute execution.
# ---------------------------------------------------------------------

# Estimated worst-case time to fully scan ONE (account, region) pair
# across all its configured services. This is intentionally an
# OVER-estimate (a safety margin, not a true average) — the loop uses it
# to decide "do I have enough time left to safely start one more unit of
# work", so underestimating it risks starting a unit we can't finish
# before Lambda hard-kills the invocation mid-scan.
#
# NOTE (2026-09-15b): the SageMaker and Bedrock handler patches added
# roughly a dozen extra list_* calls each (plus one describe_processing_job
# call per Processing Job, for Clarify detection). If a region legitimately
# has a lot of resources, a single scanAccountRegion() call now does
# meaningfully more work than before this patch. Worth re-measuring actual
# per-region scan time in a real account and bumping this default if it's
# now running close to it, rather than assuming the old 180s estimate still
# holds.
AVG_SECONDS_PER_REGION = int(os.environ.get("AVG_SECONDS_PER_REGION", "180"))

# Time reserved at the end of every invocation for writing the final
# checkpoint to S3 and firing the self-re-invoke call — both need to
# complete BEFORE Lambda's hard timeout, not race against it.
SAFETY_BUFFER_SECONDS = int(os.environ.get("SAFETY_BUFFER_SECONDS", "30"))

# Only used when there's no real Lambda `context` object to ask for
# remaining time (i.e. local testing via `python lambda_function.py`).
# Mirrors the real 15-minute Lambda ceiling, minus a minute of margin.
LOCAL_TIME_BUDGET_SECONDS = int(os.environ.get("LOCAL_TIME_BUDGET_SECONDS", "840"))

# Safety valve on the self-re-invocation chain. If a run hasn't finished
# after this many chained invocations, something is wrong (e.g. the
# pending-work list isn't shrinking) — better to stop and surface an
# error than let a broken loop re-invoke itself indefinitely and rack up
# cost/log noise.
MAX_CONTINUATIONS = int(os.environ.get("MAX_CONTINUATIONS", "100"))

# S3 key prefix under which the persisted work-queue/run-state JSON
# lives while a run is in progress (see runStateHelper.py). Deleted once
# a run finishes successfully.
RUN_STATE_PREFIX = os.environ.get("RUN_STATE_PREFIX", "_run_state")

# ---------------------------------------------------------------------
# Client-level network timeouts + retry cap. NOT present in the
# remediation codebase's MarriottCSAO_utils.py — S3Versioning only ever
# touches one account/region per invocation, so a slow/SCP-blocked call
# was never a real cost there. AI Inventory fans out across many
# accounts x regions x services per run, where boto3's generous default
# timeouts (and its automatic retries) mean a single SCP-blocked call can
# silently burn 30-60+ seconds instead of failing fast. These make every
# blocked call fail in single-digit seconds instead.
CLIENT_CONNECT_TIMEOUT = int(os.environ.get("CLIENT_CONNECT_TIMEOUT", "3"))
CLIENT_READ_TIMEOUT = int(os.environ.get("CLIENT_READ_TIMEOUT", "5"))

# MAX_API_RETRIES — applied at the boto3 CLIENT level (via
# botocore.config.Config, see MarriottCSAO_utils.BOTO_CONFIG), not at
# any individual call site. Because getAwsClient()/getAwsResourceClient()
# are the ONLY place any AWS client gets built anywhere in this codebase,
# setting this one constant automatically covers every AWS call every
# handler/helper makes — no per-call-site changes needed.
MAX_API_RETRIES = int(os.environ.get("MAX_API_RETRIES", "1"))

"""
Required DynamoDB table (single table — see PATCH NOTE at top of file):
  CSAO_Sub_Account_Info
    - EVERY row is scanned, including the master row. Each row needs:
        accountId  (String)  — REQUIRED
        regions    (List of String, e.g. ["us-east-1","us-west-2"]) — REQUIRED.
                   This is now the ONLY source of region scope. An account
                   whose row has no regions list (or an empty one) is
                   SKIPPED and recorded in the run summary's call_errors —
                   there is no ec2:DescribeRegions fallback any more.
        configuredServices (List of String, optional) — not currently a
                   column on this table; when absent, config.SERVICES is used.
      -> used by getMonitoredSubAccounts() (NO scanEnabled filter — every
         row in the table is treated as in-scope)
        accountType (String, optional) — set to 'master' on exactly one
                   row; left empty on all the others. Used by
                   getMasterAccountId() to identify the account this
                   Lambda runs in, so getAwsClient() knows to use local
                   credentials for it instead of assuming a role.
                   This does NOT exclude the master row from scanning —
                   it is queued for scanning like every other row, using
                   its own `regions` list.
                   MASTER_ACCOUNT_ID env var (see above) bypasses this
                   lookup if ever needed.

    Other columns on this table (configTags, configuredRuleNames,
    inScopeForPCICompliance) belong to the remediation codebase and are
    ignored by this scanner.

Required IAM permissions for SCAN_ROLE (TARGET_MGMT_ROLE) in every sub-account:
  sagemaker:List*, comprehend:List*, bedrock:List*, bedrock-agent:List*,
  bedrock:GetModelInvocationLoggingConfiguration, cloudwatch:ListMetrics,
  cloudwatch:GetMetricStatistics, cloudtrail:LookupEvents, sts:GetCallerIdentity
  (ec2:DescribeRegions is NO LONGER required — region scope comes from
   the `regions` attribute in DynamoDB)

  PATCH (2026-09-15b): sagemaker:DescribeProcessingJob is ALSO required now
  — _scanProcessingJobs() in sagemakerHandler.py calls DescribeProcessingJob
  once per Processing Job to detect SageMaker Clarify (Model Bias /
  Explainability) runs. sagemaker:List* does not cover Describe* calls,
  so this is a genuinely new permission, not already implied by the line
  above.

Required IAM permissions for the MASTER account's Lambda execution role:
  sts:AssumeRole on arn:aws:iam::*:role/<TARGET_MGMT_ROLE>
  dynamodb:GetItem, dynamodb:Scan on CSAO_Sub_Account_Info (in
    DYNAMO_DB_REGION AND every region in DYNAMO_DB_REGION_BACKUP_GT)
  s3:PutObject, s3:GetObject, s3:DeleteObject on OUTPUT_BUCKET (GetObject/DeleteObject
    are needed for the run-state checkpoint file under RUN_STATE_PREFIX)
  lambda:InvokeFunction on this Lambda's OWN function ARN — required for the
    self-re-invoke continuation call in lambda_function.py's run()
"""

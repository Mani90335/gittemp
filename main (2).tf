data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Single source of truth for the function name — used both by the
# Lambda resource itself and by the policy's self-invoke ARN below, so
# the two can never drift out of sync even though (see the depends_on
# note further down) the policy deliberately does NOT reference the
# Lambda resource directly.
locals {
  function_name = "AIResourceInventoryScanner"
}

# ---------------------------------------------------------------------
# Package the code. Whole thing (lambda_function.py + the src/ folder)
# gets uploaded into source_codes/AIResourceInventory, same as
# RemediationCodePrisma does for the existing Lambda.
# ---------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "source_codes/AIResourceInventory"
  output_path = "lambda_function.zip"
}

# ---------------------------------------------------------------------
# S3 bucket — where the scanner writes its results (per-service JSON,
# summary.json) and the run-state checkpoint file it uses to resume a
# scan across multiple Lambda invocations.
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "ai_inventory_output" {
  bucket = "ai-resource-inventory-output"
}

# Production hardening for the output bucket — it's going to hold
# resource ARNs, owner emails, and tags across every scanned account,
# so it shouldn't be publicly reachable or stored unencrypted.
resource "aws_s3_bucket_public_access_block" "ai_inventory_output" {
  bucket                  = aws_s3_bucket.ai_inventory_output.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ai_inventory_output" {
  bucket = aws_s3_bucket.ai_inventory_output.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---------------------------------------------------------------------
# IAM role + policies
# ---------------------------------------------------------------------
resource "aws_iam_role" "lambda_role" {
  name = "AIResourceInventory-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "ai_inventory_policy" {
  name = "AIResourceInventory-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Lets the Lambda assume into every sub-account it scans.
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole"
      },
      {
        # Reads the account/region list from the shared
        # CSAO_Sub_Account_Info table. This table already exists — it's
        # shared with the remediation codebase — so it isn't created
        # here, only read from. Two regions are listed since the
        # scanner retries in us-west-2 if us-east-1 fails.
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan",
        ]
        Resource = [
          "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/CSAO_Sub_Account_Info",
          "arn:aws:dynamodb:us-west-2:${data.aws_caller_identity.current.account_id}:table/CSAO_Sub_Account_Info",
        ]
      },
      {
        # Read/write the output bucket, plus delete — delete is needed
        # because the run-state checkpoint file gets removed once a
        # scan finishes successfully.
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
        ]
        Resource = "${aws_s3_bucket.ai_inventory_output.arn}/*"
      },
      {
        # The Lambda invokes itself asynchronously to continue a scan
        # that ran out of time (15-minute Lambda limit).
        #
        # Built from a data source + local.function_name, NOT a direct
        # reference to aws_lambda_function.ai_inventory_scanner.arn —
        # deliberately, so this policy has no dependency on the Lambda
        # resource. That's what lets the Lambda resource below declare
        # depends_on = [this policy] (so the policy is guaranteed to
        # exist before the function is created) without Terraform
        # reporting a dependency cycle (policy -> lambda -> policy).
        # Still always correct regardless of deployment region, since
        # data.aws_region.current.name is live, not hardcoded.
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${local.function_name}"
      },
      {
        # The master account itself is one of the accounts scanned
        # (not just the sub-accounts) — the code recognizes it's
        # already in that account and skips the assume-role step,
        # calling SageMaker/Comprehend/Bedrock/CloudTrail/CloudWatch
        # DIRECTLY using this Lambda's own role. Without this
        # statement, scanning the master account's own AI resources
        # fails with AccessDenied even though every sub-account scan
        # (which goes through AssumeRole into a role that DOES have
        # these permissions) works fine.
        #
        # Listed explicitly, not as service:List* wildcards — every
        # action below is exactly what the code calls, one boto3
        # operation at a time. This exact same list (everything in
        # this one statement) also needs to be granted on
        # AWSCloudFormationStackSetExecutionRole in every SUB-account
        # — that's a separate stack/StackSet, not this file, since
        # this file only controls the master account.
        Effect = "Allow"
        Action = [
          # SageMaker
          "sagemaker:ListEndpoints",
          "sagemaker:ListTags",
          "sagemaker:ListNotebookInstances",
          "sagemaker:ListTrainingJobs",
          "sagemaker:ListDomains",
          "sagemaker:ListSpaces",
          "sagemaker:ListApps",
          "sagemaker:ListProcessingJobs",
          "sagemaker:ListCodeRepositories",
          "sagemaker:ListModels",
          "sagemaker:ListModelPackageGroups",
          "sagemaker:ListModelPackages",
          "sagemaker:ListEndpointConfigs",
          "sagemaker:ListTransformJobs",
          "sagemaker:ListHyperParameterTuningJobs",
          "sagemaker:ListPipelines",
          "sagemaker:ListPipelineExecutions",
          "sagemaker:ListFeatureGroups",
          "sagemaker:ListInferenceRecommendationsJobs",
          "sagemaker:ListNotebookInstanceLifecycleConfigs",
          "sagemaker:ListStudioLifecycleConfigs",
          "sagemaker:ListLabelingJobs",
          "sagemaker:ListMlflowTrackingServers",
          # Comprehend
          "comprehend:ListDocumentClassificationJobs",
          "comprehend:ListEntitiesDetectionJobs",
          "comprehend:ListSentimentDetectionJobs",
          "comprehend:ListKeyPhrasesDetectionJobs",
          "comprehend:ListPiiEntitiesDetectionJobs",
          "comprehend:ListTopicsDetectionJobs",
          "comprehend:ListTargetedSentimentDetectionJobs",
          "comprehend:ListEntityRecognizers",
          "comprehend:ListDocumentClassifiers",
          "comprehend:ListEndpoints",
          "comprehend:ListTagsForResource",
          "comprehend:ListFlywheels",
          "comprehend:ListDatasets",
          # Bedrock
          "bedrock:ListCustomModels",
          "bedrock:ListProvisionedModelThroughputs",
          "bedrock:ListTagsForResource",
          "bedrock:GetModelInvocationLoggingConfiguration",
          "bedrock:ListGuardrails",
          "bedrock:ListEvaluationJobs",
          "bedrock:ListModelCustomizationJobs",
          "bedrock:ListModelImportJobs",
          "bedrock:ListImportedModels",
          "bedrock:ListModelInvocationJobs",
          "bedrock:ListInferenceProfiles",
          "bedrock:ListMarketplaceModelEndpoints",
          "bedrock:ListAutomatedReasoningPolicies",
          "bedrock:ListPromptRouters",
          # Bedrock Agent
          "bedrock-agent:ListAgents",
          "bedrock-agent:ListAgentAliases",
          "bedrock-agent:ListKnowledgeBases",
          "bedrock-agent:ListTagsForResource",
          "bedrock-agent:ListPrompts",
          "bedrock-agent:ListFlows",
          "bedrock-agent:ListFlowAliases",
          "bedrock-agent:ListFlowVersions",
          # CloudTrail (owner/creator resolution)
          "cloudtrail:LookupEvents",
          # CloudWatch (usage/last-invoked data)
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricStatistics",
          # Identity check performed after assuming into an account
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
    ]
  })
}

# ---------------------------------------------------------------------
# Tunable scan settings, kept together here so they're easy to find
# and change in one place instead of hunting through the environment
# block below. Every one of these already has a matching fallback
# constant in config.py — if you ever remove one of these environment
# variables entirely, the Lambda still runs fine using that fallback.
# ---------------------------------------------------------------------
locals {
  avg_seconds_per_region   = 180
  safety_buffer_seconds    = 30
  max_continuations        = 100
  lookback_days            = 90
  cloudwatch_lookback_days = 30
}

# ---------------------------------------------------------------------
# The Lambda function itself.
# ---------------------------------------------------------------------
resource "aws_lambda_function" "ai_inventory_scanner" {
  function_name    = local.function_name
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 900
  memory_size      = 512

  # Forces the policy (and the basic-execution attachment) to exist
  # before the function is created, rather than relying on Terraform's
  # implicit ordering (which only guarantees the ROLE exists first,
  # not that the role's PERMISSIONS are attached first). This is what
  # you asked for — "create IAM policy before lambda". Safe from a
  # cycle only because the policy above references the Lambda's ARN
  # via a constructed string (region data source + local.function_name),
  # not via aws_lambda_function.ai_inventory_scanner.arn directly — see
  # the comment on that statement.
  depends_on = [
    aws_iam_role_policy.ai_inventory_policy,
    aws_iam_role_policy_attachment.lambda_basic_logs,
  ]

  environment {
    variables = {
      OUTPUT_BUCKET            = aws_s3_bucket.ai_inventory_output.bucket
      AVG_SECONDS_PER_REGION   = tostring(local.avg_seconds_per_region)
      SAFETY_BUFFER_SECONDS    = tostring(local.safety_buffer_seconds)
      MAX_CONTINUATIONS        = tostring(local.max_continuations)
      LOOKBACK_DAYS            = tostring(local.lookback_days)
      CLOUDWATCH_LOOKBACK_DAYS = tostring(local.cloudwatch_lookback_days)
    }
  }
}

# ---------------------------------------------------------------------
# Daily trigger — runs the scan every day at 10:00 AM IST.
#
# EventBridge cron always runs in UTC (no timezone setting exists for
# it), so 10:00 AM IST is written here as 4:30 AM UTC (IST = UTC+5:30).
# ---------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "ai_inventory_schedule" {
  name                = "AIResourceInventory-daily-trigger"
  schedule_expression = "cron(30 4 * * ? *)" # 10:00 AM IST
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule           = aws_cloudwatch_event_rule.ai_inventory_schedule.name
  arn            = aws_lambda_function.ai_inventory_scanner.arn
  target_id      = "AIResourceInventoryLambda"
  event_bus_name = "default"
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvokeAIResourceInventory"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_inventory_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ai_inventory_schedule.arn
}

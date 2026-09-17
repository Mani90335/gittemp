# AIResourceInventoryScanner.tf
# Deployed in the MASTER account. Same resource pattern as
# DSPMec2AutoTagging.tf: archive_file -> iam_role -> managed policy
# attachment -> lambda_function -> eventbridge rule -> eventbridge
# target -> lambda_permission -> custom inline iam_role_policy --
# PLUS a real S3 bucket (output + run-state checkpoint), a dedicated
# CloudWatch Log Group with a retention period, and IST scheduling.
#
# Difference from DSPMec2AutoTagging.tf: that Lambda reacts to a
# CloudTrail EVENT PATTERN (RunInstances). This one runs on a
# SCHEDULE (cron), since it's a periodic org-wide scan, not an
# event-driven remediation -- so aws_cloudwatch_event_rule uses
# schedule_expression instead of event_pattern.
#
# PRE-EXISTING DEPENDENCY, NOT CREATED HERE: the CSAO_Sub_Account_Info
# DynamoDB table. It is shared with the existing CSAO remediation
# stack and is assumed to already exist in this account, in both
# us-east-1 and us-west-2. If it does not exist yet, this Lambda will
# deploy successfully but every run will fail at getMasterAccountId()
# / getMonitoredSubAccounts() -- that table is genuinely out of scope
# for this file and must be confirmed separately before go-live.

data "aws_caller_identity" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "source_codes/AIResourceInventoryScanner"
  output_path = "ai_resource_inventory_lambda.zip"
}

# ---------------------------------------------------------------------
# S3 bucket -- BOTH the final inventory output AND the run-state
# checkpoint file live here (see s3OutputHelper.py / runStateHelper.py
# -- one bucket, two key prefixes). Bucket name includes the account
# id so it's globally unique without needing a random suffix.
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "ai_inventory_output" {
  bucket = "ai-resource-inventory-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "ai_inventory_output" {
  bucket = aws_s3_bucket.ai_inventory_output.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ai_inventory_output" {
  bucket = aws_s3_bucket.ai_inventory_output.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ai_inventory_output" {
  bucket                  = aws_s3_bucket.ai_inventory_output.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Safety net: if a run ever dies in a way that leaves an orphaned
# checkpoint behind (crash, manual kill, etc.), this guarantees it
# doesn't sit there forever. Final inventory output under
# ai-resource-inventory/ is NOT touched by this rule -- no expiry.
resource "aws_s3_bucket_lifecycle_configuration" "ai_inventory_output" {
  bucket = aws_s3_bucket.ai_inventory_output.id
  rule {
    id     = "expire-orphaned-run-state"
    status = "Enabled"
    filter {
      prefix = "_run_state/"
    }
    expiration {
      days = 14
    }
  }
}

# ---------------------------------------------------------------------
# IAM role + logging
# ---------------------------------------------------------------------
resource "aws_iam_role" "lambda_role" {
  name = "AIResourceInventoryScanner-role"
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

# Created explicitly, with a retention period, and named to EXACTLY
# match what Lambda auto-creates ("/aws/lambda/<function_name>") --
# without this, Lambda creates its own log group with NO expiration,
# which quietly accumulates cost forever.
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/AIResourceInventoryScanner"
  retention_in_days = 30
}

resource "aws_lambda_function" "AIResourceInventoryScanner" {
  function_name = "AIResourceInventoryScanner"
  filename      = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  role = aws_iam_role.lambda_role.arn

  # 900s = Lambda's hard maximum. The scanner's own checkpoint-and-
  # continue logic (AVG_SECONDS_PER_REGION / SAFETY_BUFFER_SECONDS)
  # relies on getting the full 15 minutes every invocation.
  timeout     = 900
  memory_size = 512

  environment {
    variables = {
      OUTPUT_BUCKET            = aws_s3_bucket.ai_inventory_output.bucket
      OUTPUT_PREFIX            = "ai-resource-inventory"
      OUTPUT_REGION            = "us-east-1"
      RUN_STATE_PREFIX         = "_run_state"
      LOOKBACK_DAYS            = "90"
      CLOUDWATCH_LOOKBACK_DAYS = "30"
      AVG_SECONDS_PER_REGION   = "180"
      SAFETY_BUFFER_SECONDS    = "30"
      MAX_CONTINUATIONS        = "100"
      CLIENT_CONNECT_TIMEOUT   = "3"
      CLIENT_READ_TIMEOUT      = "5"
      MAX_API_RETRIES          = "1"
    }
  }

  depends_on = [
    aws_iam_role_policy.ai_inventory_policy,
    aws_iam_role_policy_attachment.lambda_basic_logs,
    aws_cloudwatch_log_group.lambda_logs
  ]

}

# ---------------------------------------------------------------------
# Schedule -- 10:00 AM IST daily. EventBridge cron is UTC-only;
# IST is UTC+5:30, so 10:00 IST = 04:30 UTC.
# ---------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "AIResourceInventoryScanner_schedule" {
  name           = "AIResourceInventoryScanner-schedule"
  description    = "Triggers the AI Resource Inventory Scanner daily at 10:00 AM IST (04:30 UTC)"
  event_bus_name = "default"

  # This fires the FIRST invocation of a run only. Every subsequent
  # invocation of that same run is self-invoked by the Lambda itself
  # (continuation=true), not by this schedule firing again.
  schedule_expression = "cron(30 4 * * ? *)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule           = aws_cloudwatch_event_rule.AIResourceInventoryScanner_schedule.name
  arn            = aws_lambda_function.AIResourceInventoryScanner.arn
  target_id      = "AIResourceInventoryScannerLambda"
  event_bus_name = "default"
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvokeAIInventory"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.AIResourceInventoryScanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.AIResourceInventoryScanner_schedule.arn
}

resource "aws_iam_role_policy" "ai_inventory_policy" {
  name = "AIResourceInventoryScanner-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # DynamoDB -- CSAO_Sub_Account_Info, the single source of
        # which accounts/regions to scan. Needed in BOTH the primary
        # and backup DynamoDB regions (see DYNAMO_DB_REGION /
        # DYNAMO_DB_REGION_BACKUP_GT in config.py). Pre-existing
        # table -- see the module-level comment at the top of this file.
        Sid    = "DynamoDbAccountTable"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan"
        ]
        Resource = [
          "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/CSAO_Sub_Account_Info",
          "arn:aws:dynamodb:us-west-2:${data.aws_caller_identity.current.account_id}:table/CSAO_Sub_Account_Info"
        ]
      },
      {
        # S3 -- final inventory output AND the run-state checkpoint
        # file, in the bucket THIS file creates above.
        Sid    = "OutputBucketReadWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.ai_inventory_output.arn}/*"
      },
      {
        # Cross-account scanning -- assume the scan role deployed in
        # every monitored sub-account.
        Sid      = "AssumeScanRoleInSubAccounts"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole"
      },
      {
        # Self-invoke for the checkpoint-and-continue pattern. Uses a
        # CONSTRUCTED arn, not aws_lambda_function.AIResourceInventoryScanner.arn,
        # to avoid a Terraform dependency cycle (this policy already
        # has depends_on -> lambda, so the lambda cannot also depend
        # on this policy's output).
        Sid      = "SelfInvokeForContinuation"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:AIResourceInventoryScanner"
      },
      {
        # Direct scan permissions -- used ONLY when scanning the
        # MASTER account itself, where getAwsClient() uses local
        # Lambda credentials instead of an assume-role hop. Every
        # sub-account needs this same set granted on its OWN
        # AWSCloudFormationStackSetExecutionRole, deployed separately
        # (see AIInventoryScanRole.tf / StackSet, not this file).
        Sid    = "DirectScanPermissionsForMasterAccount"
        Effect = "Allow"
        Action = [
          "sagemaker:List*",
          "sagemaker:ListTags",
          "comprehend:List*",
          "comprehend:ListTagsForResource",
          "bedrock:List*",
          "bedrock:ListTagsForResource",
          "bedrock:GetModelInvocationLoggingConfiguration",
          "bedrock-agent:List*",
          "bedrock-agent:ListTagsForResource",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricStatistics",
          "cloudtrail:LookupEvents",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------
# Outputs -- for confirming a successful deploy and for wiring up the
# sub-account scan-role StackSet separately.
# ---------------------------------------------------------------------
output "output_bucket_name" {
  value = aws_s3_bucket.ai_inventory_output.bucket
}

output "lambda_function_arn" {
  value = aws_lambda_function.AIResourceInventoryScanner.arn
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda_role.arn
}

output "schedule_rule_arn" {
  value = aws_cloudwatch_event_rule.AIResourceInventoryScanner_schedule.arn
}


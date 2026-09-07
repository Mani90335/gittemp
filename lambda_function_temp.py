"""
accountOrchestrator.py

Runs the full scan for ONE sub-account. Unlike the remediation codebase
(where one Lambda invocation always concerns exactly one account, taken
from the triggering event), this scanner must cover EVERY monitored
account in one run — so lambda_function.py calls scanAccount() once per
item returned by MarriottCSAO_utils.getMonitoredSubAccounts().

PATCH NOTE (2026-09-03): region scope no longer REQUIRES a
'configuredRegions' attribute in DynamoDB. 'configuredRegions' is now an
OPTIONAL override; when absent, regions are auto-discovered per account
via ec2:DescribeRegions.

PATCH NOTE (2026-09-05): _discoverAccountRegions() renamed to
discoverAccountRegions() (no leading underscore). lambda_function.py now
resolves every account's regions UPFRONT, before any scanning starts (so
it can print the full account+region picture immediately), and caches
the result directly onto each accountInfo dict's 'configuredRegions'
key. scanAccount() below still calls discoverAccountRegions() itself as
a fallback for any caller that DIDN'T pre-resolve regions (e.g. calling
scanAccount() directly/standalone) — so this file works correctly either
way, it just won't re-discover regions a second time when
lambda_function.py has already done it.
"""
from src.utils import logUtils, MarriottCSAO_utils
from src.helpers import cloudTrailHelper, cloudWatchHelper
from src.handlers.sagemakerHandler import SageMakerHandler
from src.handlers.comprehendHandler import ComprehendHandler
from src.handlers.bedrockHandler import BedrockHandler
from src.config import config

MODULE_NAME = __file__

# Add a new service by (1) writing a new leaf handler class in
# src/handlers/, same as adding a new rule handler in the remediation
# codebase, and (2) registering it here.
HANDLER_CLASSES = {
    "sagemaker": SageMakerHandler,
    "comprehend": ComprehendHandler,
    "bedrock": BedrockHandler,
}


def scanAccount(accountInfo):
    """
    accountInfo: one item from MarriottCSAO_utils.getMonitoredSubAccounts()
      — expected shape: {accountId, configuredRegions?, configuredServices?}
      (configuredRegions / configuredServices are both OPTIONAL overrides;
      see discoverAccountRegions() and config.SERVICES for the defaults
      used when they're absent. lambda_function.py now typically
      pre-populates configuredRegions before this is ever called — see
      PATCH NOTE above — but the fallback here still works standalone.)

    Returns:
      {
        "account_id": ...,
        "rows": {"sagemaker": [...], "comprehend": [...], "bedrock": [...]},
        "bedrock_model_usage": [...],
        "bedrock_logging_status": [...],
        "errors": [...],
      }
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + scanAccount.__name__)

    accountId = str(accountInfo.get("accountId"))
    result = {
        "account_id": accountId,
        "rows": {name: [] for name in HANDLER_CLASSES},
        "bedrock_model_usage": [],
        "bedrock_logging_status": [],
        "errors": [],
    }

    try:
        services = accountInfo.get("configuredServices") or config.SERVICES

        # configuredRegions is an OPTIONAL manual override (from DynamoDB)
        # OR may already be pre-populated by lambda_function.py's upfront
        # discovery pass. Only fall back to a fresh ec2:DescribeRegions
        # call here if nobody has resolved it yet.
        regions = accountInfo.get("configuredRegions")
        if not regions:
            logUtils.logDebug(
                MODULE_NAME,
                f"[{accountId}] No configuredRegions set — auto-discovering enabled regions"
            )
            regions = discoverAccountRegions(accountId)

        if not regions:
            logUtils.logInfo(
                MODULE_NAME,
                f"[{accountId}] Could not determine any region to scan (no override, "
                "and ec2:DescribeRegions returned nothing/failed) — skipping account"
            )
            result["errors"].append({
                "account": accountId, "region": None, "source": "accountOrchestrator",
                "error_type": "NoRegionsResolved",
                "error": f"No configuredRegions override and region auto-discovery found "
                         f"nothing for {accountId} — check ec2:DescribeRegions permission "
                         f"on {config.TARGET_MGMT_ROLE} in that account.",
            })
            return result

        logUtils.logDebug(MODULE_NAME, f"[{accountId}] scanning regions={regions} services={services}")

        for region in regions:
            for service in services:
                # print(f"Scanning account={accountId} region={region} service={service}")
                handlerCls = HANDLER_CLASSES.get(service)
                if handlerCls is None:
                    logUtils.logInfo(MODULE_NAME, f"Unknown service '{service}' in configuredServices — skipping")
                    continue

                try:
                    ctClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDTRAIL'], accountId, region)
                    creatorLookup = cloudTrailHelper.buildCreatorLookup(
                        ctClient, region, handlerCls.eventNames, config.LOOKBACK_DAYS
                    ) if ctClient else {}

                    handler = handlerCls(service, accountId, region, creatorLookup)
                    result["rows"][service].extend(handler.scan())
                    result["errors"].extend(handler.errors)

                    if service == "bedrock":
                        result["bedrock_logging_status"].append(handler.getLoggingStatus())
                        _mergeBedrockUsage(accountId, region, result)

                    if service == "sagemaker":
                        _mergeSageMakerUsage(accountId, region, result)

                    if service == "comprehend":
                        _mergeComprehendUsage(accountId, region, result)

                except Exception as e:
                    logUtils.logError(MODULE_NAME, e)
                    result["errors"].append({
                        "account": accountId, "region": region, "source": f"{service}:handler",
                        "error_type": type(e).__name__, "error": str(e),
                    })

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        result["errors"].append({
            "account": accountId, "region": None, "source": "accountOrchestrator",
            "error_type": type(e).__name__, "error": str(e),
        })

    return result


def discoverAccountRegions(accountId):
    """
    Inside " + discoverAccountRegions.__name__ — returns every region
    enabled for this account, via ec2:DescribeRegions (AllRegions=False
    returns only OPTED-IN/enabled regions). Uses the same getAwsClient
    flow as every other AWS call here, so it transparently assumes into
    the sub-account if needed. Always returns a list (never raises) — a
    failure here is just "no regions discovered", handled by the caller.

    Renamed from _discoverAccountRegions (no leading underscore) —
    lambda_function.py now calls this directly, upfront for every
    account, to print the full account+region picture before any
    scanning starts. See PATCH NOTE at the top of this file.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + discoverAccountRegions.__name__)
    try:
        ec2Client = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['EC2'], accountId, 'us-east-1')
        if not ec2Client:
            return []
        response = ec2Client.describe_regions(AllRegions=False)
        return sorted(r['RegionName'] for r in response['Regions'])
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        return []


# ---------------------------------------------------------------------
# CloudWatch usage merges
# ---------------------------------------------------------------------

def _mergeBedrockUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeBedrockUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/Bedrock", "Invocations", "ModelId", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for modelId, u in usage.items():
            result["bedrock_model_usage"].append({
                "model_id": modelId, "region": region, "account": accountId, **u
            })
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


def _mergeSageMakerUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeSageMakerUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/SageMaker", "Invocations", "EndpointName", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for row in result["rows"]["sagemaker"]:
            if row["Type"] == "Endpoint" and row["Region"] == region and row["Resource"] in usage:
                row["Details"].update(usage[row["Resource"]])
                row["Last Used"] = usage[row["Resource"]]["last_invocation_time"]
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


def _mergeComprehendUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeComprehendUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/Comprehend", "ConsumedInferenceUnits", "EndpointArn", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for row in result["rows"]["comprehend"]:
            if row["Type"] != "Endpoint" or row["Region"] != region:
                continue
            arn = row["Details"].get("endpoint_arn")
            if arn and arn in usage:
                row["Details"].update(usage[arn])
                row["Last Used"] = usage[arn]["last_invocation_time"]
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
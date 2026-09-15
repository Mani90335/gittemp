"""
accountOrchestrator.py

PATCH NOTE (2026-09-07): threading removed. Scanning is now driven by
lambda_function.py's checkpoint-and-continue loop, one (account, region)
pair at a time — see scanAccountRegion() below, which is the actual
"unit of work" that loop processes. scanAccount() (scan every region of
ONE account in a single call, looping scanAccountRegion() internally) is
kept as a convenience wrapper for local/standalone testing — it is NOT
called by the production checkpointed flow in lambda_function.py, which
calls scanAccountRegion() directly so it can check the time budget
between every single region instead of every whole account.

PATCH NOTE (2026-09-15): discoverAccountRegions() / ec2:DescribeRegions
auto-discovery is GONE. Region scope now comes exclusively from the
`regions` attribute on each account's row in CSAO_Sub_Account_Info, read
once at run start by runStateHelper.buildInitialRunState(). An account
with no regions list is skipped and recorded as an error rather than
falling back to "scan every enabled region".
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


def emptyScanResult():
    """A fresh, empty result shape — used by scanAccountRegion() and
    reused by lambda_function.py when merging many of these together."""
    return {
        "rows": {name: [] for name in HANDLER_CLASSES},
        "bedrock_model_usage": [],
        "bedrock_logging_status": [],
        "errors": [],
    }


def scanAccountRegion(accountId, region, services):
    """
    Scans ONE (account, region) pair across `services`. This is the
    single unit of work the checkpointed loop in lambda_function.py
    processes between every time-budget check — see AVG_SECONDS_PER_REGION
    in config.py, which is calibrated against roughly how long ONE call
    to this function takes (all its services combined).

    Returns the same shape as emptyScanResult() — no account_id/region
    wrapper, since the caller (which already knows which account+region
    it just asked for) attaches that context when merging into the
    run-wide state.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + scanAccountRegion.__name__)
    accountId = str(accountId)
    result = emptyScanResult()

    for service in services:
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

    return result


def scanAccount(accountInfo):
    """
    Convenience wrapper for local/standalone testing — scans EVERY region
    of ONE account in a single call, by looping scanAccountRegion(). NOT
    used by the production checkpointed flow (see module docstring).

    accountInfo: {accountId, regions, configuredServices?}

    PATCH (2026-09-15): `regions` is now REQUIRED here too — there is no
    ec2:DescribeRegions fallback. Uses the same _normalizeRegions()
    helper as the production path so local testing and production agree
    on how the attribute is interpreted.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + scanAccount.__name__)

    from src.helpers.runStateHelper import _normalizeRegions

    accountId = str(accountInfo.get(config.ACCOUNT_ID_ATTRIBUTE))
    combined = {"account_id": accountId, **emptyScanResult()}

    try:
        services = accountInfo.get(config.SERVICES_ATTRIBUTE) or config.SERVICES
        regions = _normalizeRegions(accountInfo.get(config.REGIONS_ATTRIBUTE))

        if not regions:
            combined["errors"].append({
                "account": accountId, "region": None, "source": "accountOrchestrator",
                "error_type": "NoRegionsConfigured",
                "error": f"No usable '{config.REGIONS_ATTRIBUTE}' list for {accountId} — "
                         f"region auto-discovery has been removed, so there is nothing to scan.",
            })
            return combined

        for region in regions:
            unit = scanAccountRegion(accountId, region, services)
            for service, rows in unit["rows"].items():
                combined["rows"][service].extend(rows)
            combined["bedrock_model_usage"].extend(unit["bedrock_model_usage"])
            combined["bedrock_logging_status"].extend(unit["bedrock_logging_status"])
            combined["errors"].extend(unit["errors"])

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        combined["errors"].append({
            "account": accountId, "region": None, "source": "accountOrchestrator",
            "error_type": type(e).__name__, "error": str(e),
        })

    return combined


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

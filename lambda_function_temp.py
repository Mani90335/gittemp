"""
lambda_function.py

Entry point. Deployed in the MASTER account (same deployment model as the
CSAO remediation Lambdas). For every sub-account listed in the
AIInventoryMonitoredAccounts DynamoDB table: scans its configured regions
for its configured services, and merges everything into one run. Output
is written ONCE, from the master account's own credentials, to the
master account's S3 bucket.

Also runnable directly for local testing: `python lambda_function.py`.
"""
import os
import json
import traceback
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils import logUtils, MarriottCSAO_utils, customErrors
from src.helpers import s3OutputHelper
from src.accountOrchestrator import scanAccount, HANDLER_CLASSES
from src.config import config

MODULE_NAME = __file__


def run(event=None, context=None):
    logUtils.logInfo(MODULE_NAME, "Inside " + run.__name__)
    try:
        if not config.OUTPUT_BUCKET:
            raise customErrors.GenericError(
                config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                "OUTPUT_BUCKET environment variable must be set"
            )

        masterAccountId = MarriottCSAO_utils.getMasterAccountId()
        logUtils.logInfo(MODULE_NAME, f"Master account: {masterAccountId}")

        monitoredAccounts = MarriottCSAO_utils.getMonitoredSubAccounts()

        # --- TEMP TESTING OVERRIDE (2026-09-03) ---------------------------
        # MARRIOTTCSAOSubAccountInfo currently has exactly ONE item, and
        # it's the master account row (accountType == 'master') — there
        # are no separate sub-account rows in the table yet, so
        # getMonitoredSubAccounts() has nothing to return and
        # monitoredAccounts comes back empty.
        #
        # For this test run only: if nothing came back, scan the master
        # account itself instead, restricted to us-east-1 via
        # configuredRegions — the same OPTIONAL per-account override
        # accountOrchestrator.scanAccount() already reads from a real
        # DynamoDB row (see its docstring/PATCH NOTE). accountOrchestrator.py,
        # config.py, and every other file are UNCHANGED — this override is
        # entirely local to this function.
        #
        # Gated behind TEST_SCAN_MASTER_ACCOUNT so it's a no-op by default
        # in any environment where that variable isn't set.
        #
        # TO REMOVE LATER: delete this whole block (between the ---- markers)
        # and unset TEST_SCAN_MASTER_ACCOUNT from the Lambda's environment.
        # Once real sub-account rows exist in MARRIOTTCSAOSubAccountInfo,
        # this block also stops firing on its own (it only applies when
        # monitoredAccounts is empty), so it's safe to leave in place for a
        # while if you'd rather not touch the code again right away.
        if os.environ.get("TEST_SCAN_MASTER_ACCOUNT", "") and not monitoredAccounts:
            logUtils.logInfo(
                MODULE_NAME,
                f"TEST_SCAN_MASTER_ACCOUNT set and no sub-accounts found in "
                f"MARRIOTTCSAOSubAccountInfo — scanning master account "
                f"{masterAccountId} only, region us-east-1"
            )
            monitoredAccounts = [{
                "accountId": masterAccountId,
                "configuredRegions": ["us-east-1"],
            }]
        # --------------------------------------------------------------------

        logUtils.logInfo(MODULE_NAME, f"Scanning {len(monitoredAccounts)} sub-account(s)")

        combined = {name: [] for name in HANDLER_CLASSES}
        bedrockModelUsage = []
        bedrockLoggingStatus = []
        allErrors = []
        accountsScanned = []

        # Each account's scan is independent, slow, I/O-bound work (many
        # AWS API calls per region), so accounts are scanned concurrently
        # rather than one at a time — otherwise an org-wide, all-region
        # scan risks exceeding the Lambda timeout.
        with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_ACCOUNTS) as pool:
            futures = {
                pool.submit(scanAccount, accountInfo): str(accountInfo.get("accountId"))
                for accountInfo in monitoredAccounts
            }
            for future in as_completed(futures):
                accountId = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    logUtils.logError(MODULE_NAME, e)
                    allErrors.append({
                        "account": accountId, "region": None, "source": "scanAccount",
                        "error_type": type(e).__name__, "error": str(e),
                    })
                    continue

                accountsScanned.append(accountId)
                for service, rows in result["rows"].items():
                    combined[service].extend(rows)
                bedrockModelUsage.extend(result["bedrock_model_usage"])
                bedrockLoggingStatus.extend(result["bedrock_logging_status"])
                allErrors.extend(result["errors"])

        dateStr = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        baseKey = f"{config.OUTPUT_PREFIX}/master-account={masterAccountId}/date={dateStr}"

        for service, rows in combined.items():
            s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/{service}_resources.json", rows)
        s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/bedrock_model_usage.json", bedrockModelUsage)

        summary = {
            "master_account_id": masterAccountId,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "accounts_in_scope": [str(a.get("accountId")) for a in monitoredAccounts],
            "accounts_scanned_successfully": accountsScanned,
            "counts": {service: len(rows) for service, rows in combined.items()},
            "bedrock_models_with_recorded_invocations": len(bedrockModelUsage),
            "cloudwatch_lookback_days": config.CLOUDWATCH_LOOKBACK_DAYS,
            "bedrock_invocation_logging_status": bedrockLoggingStatus,
            "call_errors": allErrors,
            "output_location": f"s3://{config.OUTPUT_BUCKET}/{baseKey}/",
        }
        s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/summary.json", summary)

        logUtils.logInfo(MODULE_NAME, json.dumps(summary, indent=2, default=str))
        return summary

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)
        raise


def lambda_handler(event, context):
    try:
        return run(event, context)
    except Exception:
        # Surface the full traceback in Lambda logs, not just str(e), so
        # setup-level failures (e.g. missing OUTPUT_BUCKET, or the
        # MARRIOTTCSAOSubAccountInfo table being unreachable) are easy to
        # diagnose.
        traceback.print_exc()
        raise


if __name__ == "__main__":
    run()

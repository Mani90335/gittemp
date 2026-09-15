"""
lambda_function.py

Entry point. Deployed in the MASTER account.

PATCH NOTE (2026-09-07): rebuilt around a checkpoint-and-continue pattern
instead of threaded concurrency, to avoid the issues concurrency was
causing. Every (account, region) pair is scanned ONE AT A TIME. Before
starting each one, the invocation checks how much execution time it has
left; once there isn't enough time left to safely finish one more unit
(config.AVG_SECONDS_PER_REGION + config.SAFETY_BUFFER_SECONDS), it stops,
saves exactly where it left off to S3, and fires a brand-new Lambda
invocation (async self-invoke) to pick up from there — which gets its
own fresh 15-minute clock. This repeats until the work queue is empty.

IMPORTANT — why this isn't literal recursion: calling run() again from
inside the SAME invocation would NOT reset Lambda's execution clock; it
would just be more work inside the same 15-minute window, hitting the
exact same wall. The only way to get a fresh time budget is a genuinely
NEW invocation — hence the async self-invoke via lambda:Invoke rather
than a plain Python function call.

Trigger model:
  - FIRST invocation of a run: fired by an EventBridge Scheduled Rule
    (e.g. daily/weekly cron) — a normal scheduler trigger, event has no
    'continuation' key.
  - EVERY SUBSEQUENT invocation of that same run: fired by THIS Lambda
    invoking itself asynchronously, with {"continuation": True} in the
    payload — see _selfReinvoke() below. lambda_handler()/run() branch
    on that flag to decide "start a fresh work list" vs. "resume the one
    already checkpointed in S3".

Also runnable directly for local testing: `python lambda_function.py` —
see the `if __name__ == "__main__"` block, which drives the same
continuation loop in plain Python (no real Lambda self-invoke available
locally, so run() detects the absence of a real `context` and returns
control to this local driving loop instead).
"""
import os
import json
import time
import traceback
from datetime import datetime, timezone

from src.utils import logUtils, MarriottCSAO_utils, customErrors
from src.helpers import s3OutputHelper, runStateHelper
from src import accountOrchestrator
from src.config import config

MODULE_NAME = __file__


def run(event=None, context=None):
    logUtils.logInfo(MODULE_NAME, "Inside " + run.__name__)
    invocationStartMonotonic = time.monotonic()

    try:
        if not config.OUTPUT_BUCKET:
            raise customErrors.GenericError(
                config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                "OUTPUT_BUCKET environment variable must be set"
            )

        masterAccountId = MarriottCSAO_utils.getMasterAccountId()
        logUtils.logInfo(MODULE_NAME, f"Master account: {masterAccountId}")

        isContinuation = bool(event and event.get("continuation"))

        if isContinuation:
            state = runStateHelper.loadRunState(masterAccountId)
            if state is None:
                raise customErrors.GenericError(
                    config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                    "Received a continuation event but no run state was found in S3 — nothing to resume."
                )
        else:
            existing = runStateHelper.loadRunState(masterAccountId)
            if existing is not None and existing.get("status") == "in_progress":
                msg = (f"A run (run_id={existing.get('run_id')}) is already in progress — "
                       f"{len(existing.get('pending_work', []))} item(s) still pending. Skipping this "
                       f"trigger rather than starting a second, overlapping run.")
                logUtils.logInfo(MODULE_NAME, msg)
                print(msg)
                return {"status": "skipped_already_running", "run_id": existing.get("run_id")}

            state = runStateHelper.buildInitialRunState(masterAccountId)
            # Persisted immediately — if something crashes right after
            # this, the (potentially expensive-to-rebuild) work list
            # isn't lost; the next trigger just resumes it, same as any
            # other checkpoint.
            runStateHelper.saveRunState(masterAccountId, state)

        state["invocation_count"] = state.get("invocation_count", 0) + 1
        logUtils.logInfo(
            MODULE_NAME,
            f"Invocation #{state['invocation_count']} for run {state['run_id']} — "
            f"{len(state['pending_work'])} item(s) pending"
        )

        if state["invocation_count"] > config.MAX_CONTINUATIONS:
            state["status"] = "failed"
            runStateHelper.saveRunState(masterAccountId, state)
            raise customErrors.GenericError(
                config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                f"Exceeded MAX_CONTINUATIONS ({config.MAX_CONTINUATIONS}) without finishing — "
                f"aborting to avoid a runaway self-invoke loop. Run state left in S3 at "
                f"{runStateHelper.stateKey()} for inspection."
            )

        itemsProcessedThisInvocation = 0

        while state["pending_work"]:
            remainingSeconds = _getRemainingSeconds(context, invocationStartMonotonic)

            if remainingSeconds - config.SAFETY_BUFFER_SECONDS < config.AVG_SECONDS_PER_REGION:
                logUtils.logInfo(
                    MODULE_NAME,
                    f"{remainingSeconds:.0f}s left (need >= {config.AVG_SECONDS_PER_REGION + config.SAFETY_BUFFER_SECONDS}s "
                    f"to safely start one more unit) — stopping this invocation with "
                    f"{len(state['pending_work'])} item(s) still pending"
                )
                break

            # Removed BEFORE scanning, not after — guarantees forward
            # progress even if this specific unit errors out badly or
            # somehow hangs past its budget. A genuinely transient
            # failure just shows up in call_errors; a future scheduled
            # run re-discovers this account/region fresh and tries again.
            workItem = state["pending_work"].pop(0)
            accountId_ = workItem["accountId"]
            region_ = workItem["region"]
            services = state["account_services"].get(accountId_, config.SERVICES)

            logUtils.logInfo(
                MODULE_NAME,
                f"Scanning account={accountId_} region={region_} "
                f"({len(state['pending_work'])} remaining after this one)"
            )

            try:
                unit = accountOrchestrator.scanAccountRegion(accountId_, region_, services)
            except Exception as e:
                logUtils.logError(MODULE_NAME, e)
                unit = accountOrchestrator.emptyScanResult()
                unit["errors"].append({
                    "account": accountId_, "region": region_, "source": "scanAccountRegion",
                    "error_type": type(e).__name__, "error": str(e),
                })

            for service, rows in unit["rows"].items():
                state["combined"].setdefault(service, []).extend(rows)
            state["bedrock_model_usage"].extend(unit["bedrock_model_usage"])
            state["bedrock_logging_status"].extend(unit["bedrock_logging_status"])
            state["errors"].extend(unit["errors"])
            if accountId_ not in state["accounts_scanned"]:
                state["accounts_scanned"].append(accountId_)

            itemsProcessedThisInvocation += 1
            # Checkpoint after EVERY unit, not just at the end of the
            # invocation — if the Lambda gets killed unexpectedly (OOM,
            # a real crash, not just our own time-budget check), we lose
            # at most the one unit in flight, never the whole invocation's
            # progress.
            runStateHelper.saveRunState(masterAccountId, state)

        if state["pending_work"]:
            reinvoked = _selfReinvoke(context, masterAccountId, {"continuation": True, "run_id": state["run_id"]})
            msg = (f"Processed {itemsProcessedThisInvocation} item(s) this invocation; "
                   f"{len(state['pending_work'])} remaining. self_reinvoked={reinvoked}")
            if not reinvoked:
                msg += (" — no real Lambda context available (e.g. local run); "
                        "caller must invoke again with continuation=True to proceed.")
            logUtils.logInfo(MODULE_NAME, msg)
            print(msg)
            return {
                "status": "continued",
                "run_id": state["run_id"],
                "remaining": len(state["pending_work"]),
                "self_reinvoked": reinvoked,
            }

        # pending_work is empty — this run is done.
        summary = _finalizeRun(masterAccountId, state)
        print(f"Run complete: {json.dumps(summary, default=str)}")
        logUtils.logInfo(MODULE_NAME, json.dumps(summary, indent=2, default=str))
        return {"status": "complete", **summary}

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)
        raise


def _getRemainingSeconds(context, invocationStartMonotonic):
    """
    Real Lambda: ask the runtime directly via context.get_remaining_time_in_millis()
    — this is the authoritative source, since it accounts for Lambda's
    actual configured timeout, not a guess.

    No real context (local testing): fall back to wall-clock elapsed
    time against config.LOCAL_TIME_BUDGET_SECONDS, so the same time-budget
    logic in run()'s loop is exercised locally too, not skipped.
    """
    if context is not None and hasattr(context, "get_remaining_time_in_millis"):
        return context.get_remaining_time_in_millis() / 1000.0
    elapsed = time.monotonic() - invocationStartMonotonic
    return max(config.LOCAL_TIME_BUDGET_SECONDS - elapsed, 0)


def _selfReinvoke(context, masterAccountId, payload):
    """
    Fires a NEW, asynchronous invocation of this same Lambda function —
    see the module docstring for why this must be a real new invocation
    rather than a plain Python function call. Returns True if the
    self-invoke call succeeded, False otherwise (including "there's no
    real Lambda context to get a function name from", i.e. a local run).
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + _selfReinvoke.__name__)
    if context is None or not hasattr(context, "function_name"):
        return False
    try:
        lambdaClient = MarriottCSAO_utils.getAwsClient(
            config.SERVICE_NAME['LAMBDA'], masterAccountId,
            os.environ.get('AWS_REGION', config.OUTPUT_REGION)
        )
        if not lambdaClient:
            return False
        lambdaClient.invoke(
            FunctionName=context.function_name,
            InvocationType='Event',
            Payload=json.dumps(payload).encode('utf-8'),
        )
        return True
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        return False


def _finalizeRun(masterAccountId, state):
    """Writes final per-service output + summary.json, then clears the
    checkpoint so the next scheduled trigger starts a fresh run."""
    logUtils.logInfo(MODULE_NAME, "Inside " + _finalizeRun.__name__)

    dateStr = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    baseKey = f"{config.OUTPUT_PREFIX}/master-account={masterAccountId}/date={dateStr}"

    for service, rows in state["combined"].items():
        s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/{service}_resources.json", rows)
    s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/bedrock_model_usage.json", state["bedrock_model_usage"])

    summary = {
        "run_id": state["run_id"],
        "master_account_id": masterAccountId,
        "started_at": state["started_at"],
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "invocations_used": state["invocation_count"],
        "accounts_in_scope": state["accounts_in_scope"],
        "accounts_scanned_successfully": state["accounts_scanned"],
        "total_work_items": state["total_work_items"],
        "master_account_scanned": state.get("master_account_scanned", False),
        "counts": {service: len(rows) for service, rows in state["combined"].items()},
        "bedrock_models_with_recorded_invocations": len(state["bedrock_model_usage"]),
        "cloudwatch_lookback_days": config.CLOUDWATCH_LOOKBACK_DAYS,
        "bedrock_invocation_logging_status": state["bedrock_logging_status"],
        "call_errors": state["errors"],
        "output_location": f"s3://{config.OUTPUT_BUCKET}/{baseKey}/",
    }
    s3OutputHelper.writeJsonToS3(masterAccountId, f"{baseKey}/summary.json", summary)
    runStateHelper.deleteRunState(masterAccountId)

    return summary


def lambda_handler(event, context):
    try:
        return run(event, context)
    except Exception:
        # Surface the full traceback in Lambda logs, not just str(e), so
        # setup-level failures are easy to diagnose.
        traceback.print_exc()
        raise


if __name__ == "__main__":
    # Local driving loop — since there's no real Lambda to self-invoke,
    # this plays that role locally: keep calling run() with
    # continuation=True until it reports the run is complete. Each call
    # is still a genuinely separate Python-level call (not nested
    # recursion), so there's no stack-depth concern even for a long chain.
    result = run()
    while result.get("status") == "continued":
        print(f"--- Local continuation: {result.get('remaining')} item(s) still pending ---")
        result = run({"continuation": True, "run_id": result.get("run_id")})
    print("Local run finished with status:", result.get("status"))

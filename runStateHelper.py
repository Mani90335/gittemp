"""
runStateHelper.py

Owns the persisted "run state" — the single JSON object in S3 that makes
the checkpoint-and-continue pattern in lambda_function.py possible. It
holds:
  - pending_work: the remaining (accountId, region) pairs still to scan
  - account_services: which services each account should be scanned for
    (looked up once, at run start, so scanAccountRegion() doesn't need to
    re-fetch it on every single work item)
  - combined / bedrock_model_usage / bedrock_logging_status / errors:
    results accumulated SO FAR, across however many invocations this run
    has taken

Only one run is tracked at a time (a single fixed S3 key) — this
codebase does not support two scans running concurrently. See
loadOrInitRunState() for what happens if a scheduler trigger fires while
a run is already in progress.
"""
from datetime import datetime, timezone
from src.utils import logUtils, MarriottCSAO_utils
from src.helpers import s3OutputHelper
from src.config import config

MODULE_NAME = __file__


def stateKey():
    return f"{config.RUN_STATE_PREFIX}/current_run.json"


def buildInitialRunState(masterAccountId):
    """
    Inside " + buildInitialRunState.__name__ — reads
    CSAO_Sub_Account_Info and flattens it into a pending_work queue of
    {accountId, region} pairs. This is the ONE-TIME setup step for a
    fresh run — every invocation after this one just pops from
    pending_work.

    PATCH (2026-09-15): region scope now comes ONLY from each row's
    `regions` attribute (config.REGIONS_ATTRIBUTE). There is no
    ec2:DescribeRegions fallback any more — if a row has no usable
    regions list, that account is skipped and the skip is recorded in
    the run's errors list so it shows up in summary.json's call_errors
    rather than vanishing silently.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + buildInitialRunState.__name__)

    # Imported here, not at module level, to avoid a circular import
    # (accountOrchestrator doesn't import this module, but keeping the
    # dependency direction one-way — helpers importing orchestration code
    # only where actually needed — is easier to reason about as this
    # codebase grows).
    from src.accountOrchestrator import HANDLER_CLASSES

    monitoredAccounts = MarriottCSAO_utils.getMonitoredSubAccounts()
    logUtils.logInfo(MODULE_NAME, f"Found {len(monitoredAccounts)} row(s) in "
                                  f"{config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS']}")

    pendingWork = []
    accountServices = {}
    accountsInScope = []
    setupErrors = []
    masterInScope = False

    for accountInfo in monitoredAccounts:
        accountId = accountInfo.get(config.ACCOUNT_ID_ATTRIBUTE)

        # A row with no accountId at all can't be scanned or even named
        # in an error — skip it loudly rather than queueing work for
        # account "None".
        if not accountId:
            logUtils.logInfo(MODULE_NAME, "Found a row with no accountId attribute — skipping it")
            setupErrors.append({
                "account": None, "region": None, "source": "runStateHelper:buildInitialRunState",
                "error_type": "MissingAccountId",
                "error": f"A row in {config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS']} has no "
                         f"'{config.ACCOUNT_ID_ATTRIBUTE}' attribute — skipped.",
            })
            continue

        accountId = str(accountId)
        accountsInScope.append(accountId)

        services = accountInfo.get(config.SERVICES_ATTRIBUTE) or config.SERVICES
        accountServices[accountId] = services

        regions = _normalizeRegions(accountInfo.get(config.REGIONS_ATTRIBUTE))

        # No auto-discovery fallback by design — if the table doesn't say
        # which regions to scan for this account, the correct answer is
        # "don't guess", and to surface it as an error the team can act on.
        if not regions:
            msg = (f"No usable '{config.REGIONS_ATTRIBUTE}' list on this account's row in "
                   f"{config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS']} — account skipped. "
                   f"Add a regions list (e.g. [\"us-east-1\", \"us-west-2\"]) to scan it.")
            logUtils.logInfo(MODULE_NAME, f"[{accountId}] {msg}")
            setupErrors.append({
                "account": accountId, "region": None, "source": "runStateHelper:buildInitialRunState",
                "error_type": "NoRegionsConfigured", "error": msg,
            })
            continue

        # The master row is scanned exactly like a sub-account row — the
        # only difference is downstream, where getAwsClient() uses local
        # Lambda credentials for it instead of assuming a role. Logged
        # distinctly so it's obvious from the logs that the master
        # account really was included.
        isMaster = (accountId == str(masterAccountId))
        if isMaster:
            masterInScope = True

        logUtils.logInfo(
            MODULE_NAME,
            f"[{accountId}]{' (MASTER)' if isMaster else ''} {len(regions)} region(s) "
            f"from DynamoDB: {', '.join(regions)}"
        )
        for region in regions:
            pendingWork.append({"accountId": accountId, "region": region})

    # Not an error — the master account is only scanned if its own row
    # carries a regions list. Surfaced loudly because "the master account
    # silently wasn't inventoried" is exactly the kind of gap this
    # scanner exists to prevent.
    if not masterInScope:
        msg = (f"Master account {masterAccountId} is NOT in the scan queue — its row in "
               f"{config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS']} is missing or has no "
               f"'{config.REGIONS_ATTRIBUTE}' list. Add a regions list to that row to "
               f"inventory the master account's own AI resources.")
        logUtils.logInfo(MODULE_NAME, msg)
        setupErrors.append({
            "account": str(masterAccountId), "region": None,
            "source": "runStateHelper:buildInitialRunState",
            "error_type": "MasterAccountNotScanned", "error": msg,
        })

    logUtils.logInfo(
        MODULE_NAME,
        f"Built work queue: {len(pendingWork)} (account, region) item(s) across "
        f"{len(accountsInScope)} account(s) (master included: {masterInScope}); "
        f"{len(setupErrors)} row(s) skipped"
    )

    nowIso = datetime.now(timezone.utc).isoformat()
    return {
        "run_id": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ"),
        "status": "in_progress",
        "master_account_id": masterAccountId,
        "started_at": nowIso,
        "last_checkpoint_at": nowIso,
        "invocation_count": 0,
        "accounts_in_scope": accountsInScope,
        "master_account_scanned": masterInScope,
        "account_services": accountServices,
        "pending_work": pendingWork,
        "total_work_items": len(pendingWork),
        "accounts_scanned": [],
        "combined": {name: [] for name in HANDLER_CLASSES},
        "bedrock_model_usage": [],
        "bedrock_logging_status": [],
        # Pre-seeded with any setup-time skips so they survive into
        # summary.json's call_errors alongside per-scan errors.
        "errors": setupErrors,
    }


def _normalizeRegions(rawRegions):
    """
    Turns whatever the `regions` attribute holds into a clean, ordered,
    de-duplicated list of region-code strings.

    boto3's DynamoDB RESOURCE api (which getMonitoredSubAccounts uses)
    already unwraps a List-of-String attribute into a plain Python list
    of str, so the common case is a straight pass-through. The extra
    handling below covers the shapes that still show up in practice:
      - a raw low-level item, where each entry is still {"S": "us-east-1"}
      - a DynamoDB String Set, which boto3 hands back as a `set` (no
        ordering — sorted here so the work queue is deterministic)
      - a single region stored as a plain string instead of a list
      - stray whitespace or empty entries from manual console edits
    Anything unrecognised yields [] rather than raising — the caller
    treats an empty list as "skip this account with an error".
    """
    if not rawRegions:
        return []

    if isinstance(rawRegions, str):
        rawRegions = [rawRegions]
    elif isinstance(rawRegions, set):
        rawRegions = sorted(rawRegions)
    elif not isinstance(rawRegions, (list, tuple)):
        logUtils.logInfo(MODULE_NAME, f"Unexpected regions attribute type: {type(rawRegions).__name__}")
        return []

    cleaned = []
    for entry in rawRegions:
        if isinstance(entry, dict):          # low-level {"S": "us-east-1"} shape
            entry = entry.get("S")
        if not isinstance(entry, str):
            continue
        entry = entry.strip()
        if entry and entry not in cleaned:   # de-dupe, preserve order
            cleaned.append(entry)

    return cleaned


def loadRunState(masterAccountId):
    """Returns the persisted run state, or None if no run is in
    progress (no file present)."""
    logUtils.logInfo(MODULE_NAME, "Inside " + loadRunState.__name__)
    return s3OutputHelper.readJsonFromS3(masterAccountId, stateKey())


def saveRunState(masterAccountId, state):
    logUtils.logInfo(MODULE_NAME, "Inside " + saveRunState.__name__)
    state["last_checkpoint_at"] = datetime.now(timezone.utc).isoformat()
    s3OutputHelper.writeJsonToS3(masterAccountId, stateKey(), state)


def deleteRunState(masterAccountId):
    """Called once a run finishes successfully, so the next scheduled
    trigger starts clean."""
    logUtils.logInfo(MODULE_NAME, "Inside " + deleteRunState.__name__)
    s3OutputHelper.deleteS3Object(masterAccountId, stateKey())

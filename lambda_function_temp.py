"""
cloudTrailHelper.py

Resolves "who owns this resource" and "when was it last touched", with a
priority order:
  1. A resource tag (Owner/CreatedBy/Team/...) — most trustworthy when present
  2. CloudTrail management events — best-effort fallback for the (common)
     case where the resource has no ownership tag at all
  3. "Unknown" — if neither source has an answer

On why CloudWatch is NOT used as an owner source: CloudWatch metrics
(Invocations, ConsumedInferenceUnits, etc.) carry no caller identity at
all — a metric datapoint says a resource WAS CALLED and roughly how much,
never BY WHOM. CloudWatch is used elsewhere in this codebase (see
cloudWatchHelper.py) purely for usage/last-invoked data, which is a
separate, complementary signal from ownership.

PATCH NOTE (2026-09-03): buildCreatorLookup() was returning an empty
lookup for every resource across every account, which meant every row
came out with Owner == "Unknown" regardless of tags/permissions. Root
cause: it only ever read the ResourceName out of each CloudTrail event's
top-level Resources[] summary field — and CloudTrail only populates that
summary field for a limited, legacy set of services (EC2, S3, IAM, RDS,
...). SageMaker, Bedrock, and Comprehend management events generally
leave Resources[] EMPTY, even though the created resource's name/ARN is
very much present in the event — it's just recorded inside
requestParameters/responseElements of the raw event body instead, which
this function never looked at.

_extractResourceIdentifiers() below is the fix: it parses each event's
raw 'CloudTrailEvent' JSON and pulls out every string value whose key
ends in Name/Arn/ARN from requestParameters and responseElements, plus
(for anything ARN-shaped) that ARN's trailing "/"-segment, so a lookup by
bare resource name still matches an ARN CloudTrail recorded, and vice
versa. Resources[] is still checked first/in addition — this is additive,
not a replacement — since it's a legitimate hit on the services that do
populate it.

Per-event eventsSeen/resourcesPopulated counts are now logged at DEBUG so
you can tell, from CloudWatch Logs, which of the three likely causes
applies in a given environment:
  - eventsSeen == 0 for every event name -> either nothing was created in
    the LOOKBACK_DAYS window, CloudTrail's default 90-day Event History
    retention has already aged the Create* event out, or
    cloudtrail:LookupEvents itself is being denied (check for a
    logDebug/logError line right above showing an AccessDenied-style
    message).
  - eventsSeen > 0 but the lookup still comes back empty -> this was the
    Resources[]-not-populated bug fixed here.
"""
import json
from datetime import datetime, timedelta, timezone
from src.utils import logUtils

MODULE_NAME = __file__


def buildCreatorLookup(client, region, eventNames, lookbackDays):
    """
    Inside " + buildCreatorLookup.__name__ — builds a best-effort map of
    resource name -> (creator username, event time) from CloudTrail
    management events. Later events overwrite earlier ones, so the map
    ends up reflecting the MOST RECENT management action seen per name.

    `client` is a CloudTrail client already built via
    MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDTRAIL'],
    accountId, region) — same getAwsClient flow used everywhere else in
    this codebase, rather than a cached session.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + buildCreatorLookup.__name__)
    lookup = {}
    try:
        endTime = datetime.now(timezone.utc)
        startTime = endTime - timedelta(days=lookbackDays)

        for eventName in eventNames:
            eventsSeen = 0
            resourcesFieldPopulated = 0
            try:
                paginator = client.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": eventName}],
                    StartTime=startTime, EndTime=endTime,
                ):
                    for e in page["Events"]:
                        eventsSeen += 1
                        user = e.get("Username", "Unknown")
                        ts = e["EventTime"]

                        # Primary path: CloudTrail's own Resources[]
                        # summary, when the service actually populates it.
                        candidateNames = [r.get("ResourceName") for r in e.get("Resources", []) if r.get("ResourceName")]
                        if candidateNames:
                            resourcesFieldPopulated += 1

                        # Fallback path: pull identifiers straight out of
                        # the raw event body instead — this is what
                        # actually finds resources for SageMaker/Bedrock/
                        # Comprehend, whose events leave Resources[] empty.
                        candidateNames.extend(_extractResourceIdentifiers(e))

                        for name in set(candidateNames):
                            prev = lookup.get(name)
                            if prev is None or ts > prev[1]:
                                lookup[name] = (user, ts)

                logUtils.logDebug(
                    MODULE_NAME,
                    f"[cloudtrail:{eventName}:{region}] eventsSeen={eventsSeen} "
                    f"resourcesFieldPopulated={resourcesFieldPopulated} "
                    f"lookupSizeSoFar={len(lookup)}"
                )
            except Exception as e:
                logUtils.logDebug(MODULE_NAME, f"[cloudtrail:{eventName}:{region}] {e}")

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)

    return lookup


def _extractResourceIdentifiers(event):
    """
    Best-effort extraction of resource name/ARN candidates from a
    CloudTrail event's raw JSON (the 'CloudTrailEvent' field). See the
    PATCH NOTE above for why this is necessary — LookupEvents' own
    Resources[] summary is empty for most SageMaker/Bedrock/Comprehend
    management events even though the identifier IS present in the event
    body itself.

    Walks requestParameters and responseElements looking for any string
    value under a key ending in Name/Arn/ARN, and returns both the raw
    value and — for anything ARN-shaped — its trailing "/" segment too,
    so a lookup keyed by a bare resource name (e.g. "my-endpoint") still
    matches an ARN CloudTrail recorded (e.g.
    "arn:aws:sagemaker:...:endpoint/my-endpoint"), and vice versa.
    """
    identifiers = []
    try:
        raw = event.get("CloudTrailEvent")
        if not raw:
            return identifiers
        body = json.loads(raw)

        for section in ("responseElements", "requestParameters"):
            data = body.get(section) or {}
            _collectIdentifiers(data, identifiers)

    except Exception:
        # Malformed/unexpected event shape — skip silently. This is a
        # best-effort fallback, not something that should ever abort
        # the scan over one odd event.
        pass

    return identifiers


def _collectIdentifiers(node, out, depth=0):
    """Recursive helper for _extractResourceIdentifiers(). Depth-capped
    since CloudTrail event bodies can nest fairly deeply and this only
    needs to find name/ARN-shaped leaves, not walk the whole structure."""
    if depth > 4 or not isinstance(node, dict):
        return
    for key, value in node.items():
        if isinstance(value, str) and (key.endswith("Name") or key.endswith("Arn") or key.endswith("ARN")):
            out.append(value)
            if ":" in value or "/" in value:
                out.append(value.replace(":", "/").rsplit("/", 1)[-1])
        elif isinstance(value, dict):
            _collectIdentifiers(value, out, depth + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collectIdentifiers(item, out, depth + 1)


def resolveOwnerAndLastUsed(resourceName, tags, creatorLookup, fallbackTime):
    """
    Inside " + resolveOwnerAndLastUsed.__name__ — prefers a tag-based
    owner over the CloudTrail-derived creator (a human-assigned Owner tag
    is more trustworthy than "whoever last called an API"), and prefers
    the most recent of the resource's own timestamp vs. the CloudTrail
    event time for "Last Used".
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + resolveOwnerAndLastUsed.__name__)
    try:
        owner = None
        for key in ("Owner", "owner", "CreatedBy", "createdBy", "team", "Team"):
            if key in tags:
                owner = tags[key]
                break

        lastUsed = fallbackTime.isoformat() if fallbackTime else "Unknown"

        if resourceName in creatorLookup:
            ctUser, ctTime = creatorLookup[resourceName]
            if owner is None:
                # No tag at all — this is the fallback the team asked
                # for: CloudTrail becomes the owner source of last resort.
                owner = ctUser
                logUtils.logDebug(MODULE_NAME, f"No owner tag for {resourceName}; using CloudTrail creator {ctUser}")
            if fallbackTime is None or ctTime > fallbackTime:
                lastUsed = ctTime.isoformat()

        if owner is None:
            owner = "Unknown"

        return owner, lastUsed

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        return "Unknown", "Unknown"
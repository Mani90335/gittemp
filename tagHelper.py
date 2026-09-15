"""
tagHelper.py

Read-only tag lookups, one function per service, in the same shape as
the remediation codebase's taghelpers3.py getTags(): a single try/except,
a logDebug fallback message on failure, always returns a value (never
raises) so a missing/failed tag call never breaks a scan.

Only getTags-equivalents are kept. addTagsForReset() and addTags() from
the remediation codebase are NOT ported here — this scanner only ever
reads tags, it never writes/removes them, so those two functions have
no use in this codebase.

PATCH NOTE (2026-09-15): added getBedrockAgentTags(). This is NOT
interchangeable with getBedrockTags() below, even though both are
"Bedrock" — they hit two different control planes with two different
response shapes:

  - getBedrockTags()      -> the `bedrock` client (CustomModel,
                              ProvisionedThroughput). Call takes
                              resourceARN (capital ARN), returns
                              {'tags': [{'key':.., 'value':..}, ...]}
                              — a LIST of key/value dicts.
  - getBedrockAgentTags() -> the `bedrock-agent` client (Agent,
                              AgentAlias, KnowledgeBase). Call takes
                              resourceArn (lowercase arn), returns
                              {'tags': {'k': 'v', ...}} — already a
                              flat DICT, not a list to unpack.

Mixing these up doesn't crash (the try/except below swallows a
KeyError/TypeError same as any other failure) but it silently returns
{} — i.e. "no tags found" — for a resource that may well have tags.
Every leaf handler MUST call the one matching the client it's using.
"""
from src.utils import logUtils

MODULE_NAME = __file__


def getSageMakerTags(client, resourceArn):
    """resourceArn: the SageMaker resource's ARN (endpoint, domain, etc.)."""
    try:
        tagResponse = client.list_tags(ResourceArn=resourceArn)
        return {t['Key']: t['Value'] for t in tagResponse.get('Tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}


def getComprehendTags(client, resourceArn):
    try:
        tagResponse = client.list_tags_for_resource(ResourceArn=resourceArn)
        return {t['Key']: t['Value'] for t in tagResponse.get('Tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}


def getBedrockTags(client, resourceArn):
    """For the `bedrock` client ONLY (CustomModel, ProvisionedThroughput).
    Param is resourceARN (capital ARN); response['tags'] is a LIST of
    {'key':.., 'value':..} dicts — see the module docstring."""
    try:
        tagResponse = client.list_tags_for_resource(resourceARN=resourceArn)
        return {t['key']: t['value'] for t in tagResponse.get('tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}


def getBedrockAgentTags(bedrockAgentClient, resourceArn):
    """For the `bedrock-agent` client ONLY (Agent, AgentAlias,
    KnowledgeBase). Param is resourceArn (lowercase arn); response['tags']
    is ALREADY a flat dict ({'k': 'v', ...}), not a list — do not try to
    iterate it as (key, value) pairs like getBedrockTags() does. See the
    module docstring for why this needs to be a separate function rather
    than a branch inside getBedrockTags()."""
    try:
        tagResponse = bedrockAgentClient.list_tags_for_resource(resourceArn=resourceArn)
        return dict(tagResponse.get('tags', {}))
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}

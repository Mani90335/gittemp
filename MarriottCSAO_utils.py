"""
MarriottCSAO_utils.py

Shared AWS/DynamoDB helpers for the AI Inventory scanner.

PATCH NOTE (2026-09-08) — two previously-fixed regressions restored here:

  1. getMonitoredSubAccounts() had a FilterExpression=Attr('scanEnabled')
     .eq(True) filter. This was deliberately removed earlier (every row
     in the table is now treated as in-scope; there is no per-row opt-out
     flag by design) — the filter had come back and was silently
     excluding rows that don't carry a Boolean scanEnabled=true attribute.
     Removed again; see config.py's docstring for the current expected
     row shape.

  2. getMasterAccountId() and getMonitoredSubAccounts() both returned a
     variable that was only ever assigned INSIDE their try blocks. If the
     primary region AND every backup region both raised, the function
     fell through to `return masterAccountId` / `return accounts` with
     that name never bound in scope -> UnboundLocalError, which then
     masked whatever the real underlying error was (e.g. a missing IAM
     permission, or a table/row that genuinely doesn't exist). Both
     functions now initialize their return variable to None up front and
     raise a clear customErrors.GenericError if it's still None after
     every region has been tried, instead of crashing on an unrelated
     name error.

PATCH NOTE (2026-09-15) — getMasterAccountId() is now CACHED.

  getAwsClient()/getAwsResourceClient() call getMasterAccountId() on
  EVERY single client they build, to decide "am I already in this
  account, or do I need to assume a role?". Unchanged, that meant one
  full DynamoDB table scan per client — and this scanner builds a client
  per service, per region, per account (plus CloudTrail and CloudWatch
  clients on top). A 50-account table across several regions turns into
  many hundreds of redundant scans per run: pure latency inside a
  time-budgeted Lambda, and needless DynamoDB read cost.

  The value cannot change mid-run, so it is resolved once and memoized
  in _MASTER_ACCOUNT_ID_CACHE for the life of the execution environment.
  Every caller keeps calling getMasterAccountId() exactly as before —
  only the first call actually touches DynamoDB.
"""
import boto3
from botocore.config import Config
from src.utils import logUtils, customErrors
from src.config import config
from boto3.dynamodb.conditions import Attr

MODULE_NAME = __file__

# Shared fast-fail config — see config.py's CLIENT_* constants for why
# this exists and isn't in the remediation codebase's version of this
# file. Applied to every boto3.client/boto3.resource call below,
# INCLUDING the sts client used for assume_role, since a blocked/throttled
# AssumeRole call can hang just as long as a blocked service call.
BOTO_CONFIG = Config(
    connect_timeout=config.CLIENT_CONNECT_TIMEOUT,
    read_timeout=config.CLIENT_READ_TIMEOUT,
    retries={'max_attempts': config.MAX_API_RETRIES},
)

# Memoized master account id — see the PATCH NOTE above. Module-level, so
# it survives for the whole Lambda execution environment (and therefore
# across the self-re-invoke continuation chain when a warm container is
# reused). None means "not resolved yet", not "no master found" — a
# genuine failure raises rather than caching None.
_MASTER_ACCOUNT_ID_CACHE = None


# get AWS client in target account — SAME CODE as the remediation
# codebase's getAwsClient, PLUS BOTO_CONFIG applied to every client built
# here (see note above — this addition is AI-Inventory-specific).
# accountId == getMasterAccountId() means this Lambda is already running
# in that account, so no assume-role hop is needed; every other account
# is reached via sts:AssumeRole.
def getAwsClient(client, accountId, awsRegion):
    try:
        # str()-normalized on both sides: the master id comes out of
        # DynamoDB while accountId may have been round-tripped through
        # JSON run-state. A type mismatch here would silently send the
        # master account down the assume-role path and fail.
        if str(accountId) == str(getMasterAccountId()):
            serviceClient = boto3.client(client, region_name=awsRegion, config=BOTO_CONFIG)
        else:
            stsClient = boto3.client('sts', config=BOTO_CONFIG)
            roleName = config.TARGET_MGMT_ROLE
            sessionName = config.SESSION_NAME
            roleArn = f'arn:aws:iam::{accountId}:role/{roleName}'
            role = stsClient.assume_role(RoleArn=roleArn, RoleSessionName=sessionName)
            accessKey = role['Credentials']['AccessKeyId']
            secretKey = role['Credentials']['SecretAccessKey']
            sessionToken = role['Credentials']['SessionToken']
            serviceClient = boto3.client(client, region_name=awsRegion,
                                          aws_access_key_id=accessKey,
                                          aws_secret_access_key=secretKey,
                                          aws_session_token=sessionToken,
                                          config=BOTO_CONFIG)
        return serviceClient

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


# get AWS resource client in target account — SAME CODE as the
# remediation codebase's getAwsResourceClient, PLUS BOTO_CONFIG (see
# getAwsClient above). Not currently called by any handler (every AWS
# call in this scanner uses the low-level client, not the resource API),
# but kept available for parity / future use — e.g. a future handler
# that wants DynamoDB-Resource-style item access.
def getAwsResourceClient(client, accountId, awsRegion):
    try:
        if str(accountId) == str(getMasterAccountId()):
            serviceClient = boto3.resource(client, region_name=awsRegion, config=BOTO_CONFIG)

        else:
            stsClient = boto3.client('sts', config=BOTO_CONFIG)
            roleName = config.TARGET_MGMT_ROLE
            sessionName = config.SESSION_NAME
            roleArn = f'arn:aws:iam::{accountId}:role/{roleName}'
            role = stsClient.assume_role(RoleArn=roleArn, RoleSessionName=sessionName)
            accessKey = role['Credentials']['AccessKeyId']
            secretKey = role['Credentials']['SecretAccessKey']
            sessionToken = role['Credentials']['SessionToken']
            serviceClient = boto3.resource(client, region_name=awsRegion,
                                            aws_access_key_id=accessKey,
                                            aws_secret_access_key=secretKey,
                                            aws_session_token=sessionToken,
                                            config=BOTO_CONFIG)
        return serviceClient

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


# Function to capture any resources falling under Time-based exceptions —
# SAME CODE as the remediation codebase's recordTimeBasedException. Not
# called anywhere in the current scan flow (there's no "exception" concept
# for inventory discovery today), but kept per instruction so a future
# feature — e.g. "suppress an idle-resource flag for this bucket/endpoint
# for the next 30 days" — can reuse this without writing it from scratch.
def recordTimeBasedException(resource, ruleName, service, accountId, region, startTime, endTime):

    retry = config.RETRY_ATTEMPTS

    while retry >= 0:
        try:
            retry = retry - 1
            dynamoDbClient = boto3.client('dynamodb', region_name=config.DYNAMO_DB_REGION)
            response = dynamoDbClient.put_item(
                TableName=config.TRACK_TIME_BASED_EXCEPTION_TABLE,
                Item={
                    'uniqueIdentifier': {'S': resource + ' | ' + ruleName},
                    'resourceName': {'S': resource},
                    'accountId': {'S': accountId},
                    'ruleName': {'S': ruleName},
                    'region': {'S': region},
                    'service': {'S': service},
                    'startTime': {'S': str(startTime)},
                    'endTime': {'S': str(endTime)}
                }
            )

            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                logUtils.logInfo(MODULE_NAME, 'Time-based exception recorded successfully...')
                return

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            logUtils.logInfo(MODULE_NAME, 'Failed, Time-based exception not recorded ...')
            logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

            for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
                try:
                    dynamoDbClient = boto3.client('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])
                    response = dynamoDbClient.put_item(
                        TableName=config.TRACK_TIME_BASED_EXCEPTION_TABLE,
                        Item={
                            'uniqueIdentifier': {'S': resource + ' | ' + ruleName},
                            'resourceName': {'S': resource},
                            'accountId': {'S': accountId},
                            'ruleName': {'S': ruleName},
                            'region': {'S': region},
                            'service': {'S': service},
                            'startTime': {'S': str(startTime)},
                            'endTime': {'S': str(endTime)}
                        }
                    )

                    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                        logUtils.logInfo(MODULE_NAME, 'Time-based exception recorded successfully...')
                        break

                except Exception as e:
                    logUtils.logError(MODULE_NAME, e)
            return


# PATCHED: getMasterAccountId — scans CSAO_Sub_Account_Info for the one
# row where accountType == 'master'. Every other row leaves accountType
# empty, so this filter matches exactly that one row.
#
# Result is MEMOIZED (see PATCH NOTE at top of file) — the first call
# hits DynamoDB, every subsequent call in the same execution environment
# returns the cached value. `masterAccountId` is still initialized to
# None BEFORE either try block, and the function raises a clear
# customErrors.GenericError if it's still None after exhausting every
# region, instead of an UnboundLocalError that masks the real failure.
def getMasterAccountId():
    global _MASTER_ACCOUNT_ID_CACHE

    if _MASTER_ACCOUNT_ID_CACHE is not None:
        return _MASTER_ACCOUNT_ID_CACHE

    # Optional escape hatch — skips the table scan entirely when set.
    # Useful for local testing, or if the master row is ever unavailable.
    if config.MASTER_ACCOUNT_ID_OVERRIDE:
        _MASTER_ACCOUNT_ID_CACHE = str(config.MASTER_ACCOUNT_ID_OVERRIDE).strip()
        logUtils.logInfo(
            MODULE_NAME,
            f"Using MASTER_ACCOUNT_ID env override: {_MASTER_ACCOUNT_ID_CACHE} "
            "(skipping the accountType=='master' lookup)"
        )
        return _MASTER_ACCOUNT_ID_CACHE

    masterAccountId = None
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION)
        table = dynamodb.Table(config.TABLE_NAME['CSAO_MONITORED_SUB_ACCOUNTS'])
        response = table.scan(
            FilterExpression=Attr(config.ACCOUNT_TYPE_ATTRIBUTE).eq(config.MASTER_ACCOUNT_TYPE_VALUE)
        )
        masterAccountId = str(response['Items'][0][config.ACCOUNT_ID_ATTRIBUTE]).strip()
        _MASTER_ACCOUNT_ID_CACHE = masterAccountId
        logUtils.logInfo(MODULE_NAME, f"Resolved master account id: {masterAccountId}")
        return masterAccountId

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

        for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
            try:
                dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])

                table = dynamodb.Table(config.TABLE_NAME['CSAO_MONITORED_SUB_ACCOUNTS'])
                response = table.scan(
                    FilterExpression=Attr(config.ACCOUNT_TYPE_ATTRIBUTE).eq(config.MASTER_ACCOUNT_TYPE_VALUE)
                )
                masterAccountId = str(response['Items'][0][config.ACCOUNT_ID_ATTRIBUTE]).strip()
                break

            except Exception as e:
                logUtils.logError(MODULE_NAME, e)

        if masterAccountId is None:
            error = customErrors.GenericError(
                config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                "Could not resolve master account id from "
                f"{config.TABLE_NAME['CSAO_MONITORED_SUB_ACCOUNTS']} in any region "
                f"({[config.DYNAMO_DB_REGION] + config.DYNAMO_DB_REGION_BACKUP_GT}). "
                f"Check IAM permissions and that exactly one row has "
                f"{config.ACCOUNT_TYPE_ATTRIBUTE}='{config.MASTER_ACCOUNT_TYPE_VALUE}'. "
                "Alternatively set the MASTER_ACCOUNT_ID env var to bypass this lookup."
            )
            logUtils.logError(MODULE_NAME, error)
            raise error

        _MASTER_ACCOUNT_ID_CACHE = masterAccountId
        logUtils.logInfo(MODULE_NAME, f"Resolved master account id (backup region): {masterAccountId}")
        return masterAccountId


# PATCHED: getMonitoredSubAccounts — scans the SAME table as
# getMasterAccountId (see config.TABLE_NAME — both keys resolve to
# CSAO_Sub_Account_Info). NO filter of any kind: every row in the table
# is returned, which deliberately INCLUDES the accountType=='master' row.
# That is what puts the master account itself in scope for scanning,
# using its own `regions` list like any other row — getAwsClient() then
# recognises it as the master and skips the assume-role hop.
# `accounts` is initialized to None before either try block, and a
# failure in every region raises a clear customErrors.GenericError
# instead of an UnboundLocalError.
def getMonitoredSubAccounts():
    accounts = None
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION)
        table = dynamodb.Table(config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS'])
        response = table.scan()
        accounts = response['Items']

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            accounts.extend(response['Items'])

        return accounts

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

        for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
            try:
                dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])
                table = dynamodb.Table(config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS'])
                response = table.scan()
                accounts = response['Items']

                while 'LastEvaluatedKey' in response:
                    response = table.scan(
                        ExclusiveStartKey=response['LastEvaluatedKey']
                    )
                    accounts.extend(response['Items'])
                return accounts

            except Exception as e:
                logUtils.logError(MODULE_NAME, e)

        if accounts is None:
            error = customErrors.GenericError(
                config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE,
                "Could not read "
                f"{config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS']} in any region "
                f"({[config.DYNAMO_DB_REGION] + config.DYNAMO_DB_REGION_BACKUP_GT}). "
                "Check that this Lambda's execution role has dynamodb:Scan on that table "
                "in every listed region."
            )
            logUtils.logError(MODULE_NAME, error)
            raise error

        return accounts


# SAME CODE as the remediation codebase's getRegionCoordinates.
def getRegionCoordinates(region):

    coordinates = {
        "us-east-2": {"Latitude": "40.2253569", "Longitude": "-82.6881395", "Country": "United States of America"},
        "us-east-1": {"Latitude": "36.5615409", "Longitude": "-76.010467", "Country": "United States of America"},
        "us-west-1": {"Latitude": "34.1682408", "Longitude": "-117.3005188", "Country": "United States of America"},
        "us-west-2": {"Latitude": "43.9792797", "Longitude": "-120.737257", "Country": "United States of America"},
        "af-south-1": {"Latitude": "-33.928992", "Longitude": "18.417396", "Country": "South Africa"},
        "ap-east-1": {"Latitude": "22.2793278", "Longitude": "114.1628131", "Country": "China"},
        "ap-south-1": {"Latitude": "18.9387711", "Longitude": "72.8353355", "Country": "India"},
        "ap-northeast-3": {"Latitude": "34.7404526", "Longitude": "135.5232738", "Country": "Japan"},
        "ap-northeast-2": {"Latitude": "37.5666791", "Longitude": "126.9782914", "Country": "South Korea"},
        "ap-southeast-1": {"Latitude": "1.3408630000000001", "Longitude": "103.83039182212079", "Country": "Singapore"},
        "ap-southeast-2": {"Latitude": "-33.8548157", "Longitude": "151.2164539", "Country": "Australia"},
        "ap-northeast-1": {"Latitude": "35.6828387", "Longitude": "139.7594549", "Country": "Japan"},
        "ca-central-1": {"Latitude": "46.8928907", "Longitude": "-71.5253836", "Country": "Canada"},
        "cn-north-1": {"Latitude": "39.9020668", "Longitude": "116.718583", "Country": "China"},
        "cn-northwest-1": {"Latitude": "37.0000001", "Longitude": "105.9999999", "Country": "China"},
        "eu-central-1": {"Latitude": "50.1106444", "Longitude": "8.6820917", "Country": "Germany"},
        "eu-west-1": {"Latitude": "52.865196", "Longitude": "-7.9794599", "Country": "Ireland"},
        "eu-west-2": {"Latitude": "51.5073219", "Longitude": "-0.1276474", "Country": "United Kingdom"},
        "eu-south-1": {"Latitude": "45.4668", "Longitude": "9.1905", "Country": "Italy"},
        "eu-west-3": {"Latitude": "48.8566969", "Longitude": "2.3514616", "Country": "France"},
        "eu-north-1": {"Latitude": "59.3251172", "Longitude": "18.0710935", "Country": "Sweden"},
        "me-south-1": {"Latitude": "26.1551249", "Longitude": "50.5344606", "Country": "Bahrain"},
        "sa-east-1": {"Latitude": "-23.5506507", "Longitude": "-46.6333824", "Country": "Brazil"},
        "global": {"Latitude": "NA", "Longitude": "NA", "Country": "Global"},
    }

    return coordinates.get(region, {"Latitude": "NA", "Longitude": "NA", "Country": "Unknown"})


# SAME CODE as the remediation codebase's getRegionNameFromCode.
def getRegionNameFromCode():
    regionMapping = {
        "us-east-1": "North Virginia", "us-east-2": "Ohio", "us-west-1": "North California",
        "us-west-2": "Oregon", "ca-central-1": "Canada", "eu-west-1": "Ireland",
        "eu-central-1": "Frankfurt", "eu-west-2": "London", "eu-west-3": "Paris",
        "eu-north-1": "Stockholm", "ap-northeast-1": "Tokyo", "ap-northeast-2": "Seoul",
        "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney", "ap-south-1": "Mumbai",
        "sa-east-1": "São Paulo", "af-south-1": "Cape Town", "ap-east-1": "Hong Kong",
        "ap-northeast-3": "Osaka", "eu-south-1": "Milan", "me-south-1": "Bahrain",
        "global": "Global",
    }
    return regionMapping
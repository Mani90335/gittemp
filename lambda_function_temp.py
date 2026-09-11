'''
User Story: Check if the ECS instance has been created using a golden Image.
As a Security Professional, I want to check if ECS Instances are using a golden (approved) Image.
'''

'''
"Conditions for violations of creation of ECS instances-
.   Non-approved Image: The rule is violated when the Image is not from the shared services account i.e., <SHARED_SERVICES_ALI_UID>
.   Tag- format violation- The rule is violated when Name does not comply with Marriott format i.e.,
    Image name starts with "GAMI"
    Is followed by either an underscore or a hyphen
    Is followed by at least one character


Event pattern (ActionTrail):

  "source": ["ecs.aliyuncs.com", "csaoecs"],
  "detail-type": ["Alibaba Cloud API Call via ActionTrail", "Custom Initial Compliance Check CSAO"],
  "detail": {
    "eventSource": ["ecs.aliyuncs.com"],
    "eventName": ["RunInstances", "DeleteTags", "CreateTags", "InitialComplianceCheck", "ecsGamiCheck"]
  }

Notes on the AWS -> Ali Cloud translation used in this file:
    EC2                         -> ECS  (Elastic Compute Service)
    AMI                         -> Image
    boto3 / botocore ClientError -> Alibaba Cloud Tea SDK clients / TeaException
    CloudTrail                  -> ActionTrail
    accountId (AWS account)     -> accountId (Alibaba Cloud account UID, "aliUid")
    awsRegion                   -> acsRegion (ActionTrail's region field for Alibaba Cloud events)
    AWS Lambda                  -> Alibaba Cloud Function Compute (FC)
    describe_instances/images   -> DescribeInstances / DescribeImages (ECS API)
    stop_instances/start_instances -> StopInstance / StartInstance (ECS API)
    AMI OwnerId                 -> Ali Cloud images don't expose OwnerId the same way AMIs do; ownership is
                                    inferred from ImageOwnerAlias ('self'/'system'/'others'/'marketplace') plus
                                    ImageOwnerId (only meaningful when querying shared/community images). This
                                    file mirrors the AWS logic as closely as possible and flags where your
                                    helper/handler implementation will need to fill in the exact lookup.
'''

# Standard imports
import json
import logging
import os
import sys
import re
import datetime
import time
# libraries to connect to Ali Cloud
from Tea.exceptions import TeaException
import traceback
# Custom imports
from src.utils import MarriottCSAO_utils
from src.utils import MARRIOTTCSAOEventHandler_new
from src.utils import logUtils  # wrapper file for logging
from src.config import config  # Hard coded strings are stored in config
from src.utils import customErrors  # Used for raising custom errors
from src.helpers import helperInstance
from csao_utils.GetDetails import GetDetails
from csao_utils import config, customErrors, logUtils, MarriottCSAO_utils, MARRIOTTCSAOEventHandler

MODULE_NAME = __file__


def mapEvent(event):
    '''
    This function extracts information captured in event and sends the information back
    to parseEvent function
    '''
    logUtils.logInfo(MODULE_NAME,  "Inside " + mapEvent.__name__)

    # logging the event
    logUtils.logDebug(MODULE_NAME, event)

    # extracting details from event
    Event = GetDetails(json.loads(json.dumps(event)))

    # Cloud Config-style events (Alibaba Cloud Config)
    if Event.GetData(['eventSource'])['eventSource'] == 'config.aliyuncs.com':
        details = Event.GetData(['accountId', 'acsRegion', 'eventSource', 'eventName', 'userIdentity', 'eventTime', 'userAgent', 'evaluations'])

    # non-config events
    else:
        eventName = Event.GetData(['eventName'])

        # create event, update event
        if eventName['eventName'] == 'RunInstances' or eventName['eventName'] == 'StartInstance':
            details = Event.GetData(['accountId', 'acsRegion', 'eventSource', 'eventName', 'userIdentity', 'eventTime', 'instanceId'])
            details['resource'] = details['instanceId']

        # tag events
        elif "CreateTags" in eventName['eventName'] or eventName['eventName'] == 'DeleteTags':
            details = Event.GetData(['accountId', 'acsRegion', 'eventSource', 'eventName', 'userIdentity', 'eventTime', 'resourceId', 'tagSet'])
            details['resource'] = details['resourceId']
            details['tags'] = details['tagSet']['items']

        # initial compliance check events
        elif eventName['eventName'] == 'InitialComplianceCheck' or eventName['eventName'] == 'ecsGamiCheck':
            details = Event.GetData(['accountId', 'acsRegion', 'eventSource', 'eventName', 'userIdentity', 'time', 'resourceId'])
            details['eventTime'] = details['time']
            details['resource'] = details['resourceId']

        elif 'csaoRollback' in eventName['eventName']:
            details = Event.GetData(['accountId', 'acsRegion', 'eventName', 'userIdentity', 'resourceList'])

    details['userEmail'] = (details.get('userIdentity', {}).get('arn') or 'unknown').split('/')[-1]

    logUtils.logDebug(MODULE_NAME, details)
    return details


# the Function Compute handler function should only parse event and load rule config
def parseEvent(event, context):
    '''
    This function extracts information captured in event and sends the information to function
    doHandleEvent
    '''
    logUtils.logInfo(MODULE_NAME,  "Inside " + parseEvent.__name__)

    try:
        details = mapEvent(event)
    except BaseException as e:
        logUtils.logInfo(MODULE_NAME, "Error in mapping the event")
        tracebackDetail = traceback.format_exc()
        errorEvent = MarriottCSAO_utils.createErrorLogs(event, context, e, tracebackDetail, True)
        errorDetails = json.dumps(errorEvent)
        logUtils.logInfo(MODULE_NAME, errorDetails)
        raise

    try:

        logUtils.logInfo(MODULE_NAME, 'Event Triggered by : ' + details['eventName'])

        # check if the event got triggered by CSAO function to avoid infinite loops
        if config.FC_ROLE in (details.get('userIdentity', {}).get('arn') or ''):  # if "TagResource" not in details['eventName']
            if details['eventName'] not in ['CreateTags', 'DeleteTags']:  # ecs tagging events(adding,removing)
                logUtils.logInfo(MODULE_NAME, "Event triggered by CSAO, ignoring...")
                return

        # check if it is a tag event and if resource is NOT an ECS instance then exit (ignoring non-ECS resources)
        if details['eventName'] in ['CreateTags', 'DeleteTags'] and not details['resource'].startswith('i-'):
            logUtils.logInfo(MODULE_NAME, "The tag event is not applicable to this user story, exiting")
            return

        # set service name to ECS
        service = config.SERVICE_NAME['ECS']
        ruleName = os.environ['ruleName']  # get rule name from environment variable (ex: ecsGamiCheck)

        # Handle Ali Cloud Config Evaluations
        # run for all resources in config (triggered when Cloud Config submits compliance results and loop through evaluations and process only)
        if details['eventName'] == 'PutEvaluations':
            for resourceEval in details['evaluations']:
                # non-compliant and ECS resources only
                if resourceEval['complianceType'] == 'NON_COMPLIANT' and resourceEval['complianceResourceType'] == 'ACS::ECS::Instance':
                    # set resource id (i-1234)
                    details['resource'] = resourceEval['complianceResourceId']
                    tag = helperInstance.getTags(service, details['accountId'], details['acsRegion'], details['resource'])
                    doHandleEvent(ruleName, service, event, tag, details)
            return

        # Handle Rollback Events
        # Checks whether the event is a rollback operation.(csaoRollback, csaoRollbackECS)
        elif 'csaoRollback' in details['eventName']:
            for resource in details['resourceList']:
                details['resource'] = resource
                # rollback doesn't require tag retrieval
                tag = []
                doHandleEvent(ruleName, service, event, tag, details)
            return

        # Standard Event processing
        tag = helperInstance.getTags(service, details['accountId'], details['acsRegion'], details['resource'])

        # getting tags due to tag events and storing in event
        # if "TagResource" in details['eventName']: (triggers when tags are added)
        # Create tag handling
        if details['eventName'] == 'CreateTags':
            # tags = details['tags']
            # tagList=[]
            # for k,v in tags.items():
            #     tagList.append({'Key':k, 'Value':v})
            # Convert tags into a standard format ({"key": "owner"})
            event['eventTagInfo'] = helperInstance.extractTagInfo(details['tags'])

        # Delete tag Handling
        elif details['eventName'] == 'DeleteTags':
            event['eventTagInfo'] = helperInstance.extractTagInfo(details['tags'])  # stores removed tag info
        # Other Events
        else:
            event['eventTagInfo'] = []

        doHandleEvent(ruleName, service, event, tag, details)

    # Handles missing dictionary keys
    except KeyError as key:
        logUtils.logDebug(MODULE_NAME, f"Failed to parse event or config {key} key is expected but not found")
        tracebackDetail = traceback.format_exc()
        errorEvent = MarriottCSAO_utils.createErrorLogs(details, context, key, tracebackDetail, False)
        errorDetails = json.dumps(errorEvent)
        logUtils.logInfo(MODULE_NAME, errorDetails)
        logUtils.logInfo(MODULE_NAME, "Error details published to Splunk")

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)
        tracebackDetail = traceback.format_exc()
        errorEvent = MarriottCSAO_utils.createErrorLogs(details, context, e, tracebackDetail, False)
        errorDetails = json.dumps(errorEvent)
        logUtils.logInfo(MODULE_NAME, errorDetails)
        logUtils.logInfo(MODULE_NAME, "Error details published to Splunk")


def doHandleEvent(ruleName, service, event, tag, details):
    '''
    This function calls the class with arguments extracted from event which assume role, extract information
    from the database and decide whether the remediation to be performed or not
    '''
    logUtils.logInfo(MODULE_NAME,  "Inside " + doHandleEvent.__name__)
    try:
        # create an object of the class
        handler = MarriottCSAOEventHandlerAliEcsCheckApprovedImage(ruleName, service, event, tag, details)
        # call the handleEvent()
        return handler.handleEvent()

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))

        logUtils.logError(MODULE_NAME, error)
        raise


class MarriottCSAOEventHandlerAliEcsCheckApprovedImage(MARRIOTTCSAOEventHandler.MARRIOTTCSAOEventHandlerAliService):

    # checks if the ecs instance has been created using an Image from the approved Image list

    def isRuleViolated(self):
        '''
        This functions checks whether the Image for the ecs resource is launched from a golden Image.

        Returns:
            True: If not from a golden Image
            False: If from a golden Image
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.isRuleViolated.__name__)
        # code for flag support
        # violation flag variables for dashboards/alerts
        self.violationCategory = None
        self.violationDetail = None
        self.tagMatched = None
        self.imageOwnerAccount = None
        try:
            # calls Ali Cloud ECS API (tell me everything about this ECS instance)
            describeResponse = self.client.describe_instances(instance_ids=json.dumps([self.resource]), region_id=self.region)
            # Extract Image ID from describeResponse
            imageId = describeResponse.body.instances.instance[0].image_id
            print(describeResponse)
            print(imageId)
            # Ali Cloud API call: tell me everything about this Image
            # NOTE: DescribeImages does not return an "OwnerId" the way AWS DescribeImages does.
            # Ownership is inferred from ImageOwnerAlias ('self'/'system'/'others'/'marketplace').
            # If the shared services account's UID is known ahead of time, querying with
            # ImageOwnerAlias='others' and ImageOwnerId=<shared account UID> is the closest
            # equivalent to AWS's cross-account AMI ownership check. Your helper implementation
            # (helperInstance / MarriottCSAO_utils) is expected to encapsulate that lookup.
            describeImageResponse = self.client.describe_images(image_id=imageId, region_id=self.region)
            print(describeImageResponse)
            # get Alibaba Cloud account that owns the Image
            imageOwnerAccount = describeImageResponse.body.images.image[0].image_owner_alias
            # The below logic is for exception for instances created by DSPM (It is only related to prod account for Ali Cloud)
            if self.region == "cn-hangzhou" and self.accountId == "798268158912":  # if it is cn-hangzhou and that account then only execute this
                # creates ActionTrail client. ActionTrail stores Alibaba Cloud activity history
                at = MarriottCSAO_utils.getAliClient("actiontrail", self.accountId, self.region)
                # searches ActionTrail for RunInstances events (who launched ECS instances)
                resp = at.lookup_events(
                    lookup_attributes=[
                        {"Key": "EventName", "Value": "RunInstances"},
                    ],
                    max_results=50,
                )
                # sorts events by time oldest to newest
                events = sorted(resp.body.events, key=lambda e: e["eventTime"])
                # if there are no events found, just write into log
                if not events:
                    logUtils.logInfo(MODULE_NAME, "No RunInstances event found for DSPM.")
                else:
                    # if events found, converts JSON text into Python Dictionary
                    at_event = json.loads(events[0]["event"])
                    # get ARN of the role/user that launched instance
                    assumed_role_arn = (at_event.get("userIdentity") or {}).get("arn", "")
                    # check whether launcher role is approved DSPM role
                    if assumed_role_arn in self.accountInfo['roleArn']:
                        logUtils.logInfo(MODULE_NAME, "The instance is created by DSPM. Exiting....")
                        return False

            # if 'Tags' in describeImageResponse['Images'][0]:
            #     tagResponse = describeImageResponse['Images'][0]['Tags']
            # else:
            #     logUtils.logDebug(MODULE_NAME,"No tags found on the Image")
            #     return True

            imageTagsDict = {}
            # stores Image name
            imageTagsDict['Name'] = describeImageResponse.body.images.image[0].image_name

            print(imageTagsDict)

            marriottKeyAbsent = []
            # for key in marriottKeys:
            #     if key not in imageTagsDict:
            #         marriottKeyAbsent.append(key)

            # if marriottKeyAbsent!=[]:
            #     logUtils.logInfo(MODULE_NAME, "Following Marriott keys are not present: ")
            #     logUtils.logInfo(MODULE_NAME, marriottKeyAbsent)
            #     return True
            # else:
            #     logUtils.logInfo(MODULE_NAME, "All Marriott tag keys are present. Checking values")

            # loads approved regex naming pattern
            regexMarriott = config.gamiRegexMarriott
            # regexMarriott['location'] = self.region

            # ---------- Non-Approved Owner Category ----------
            if imageOwnerAccount not in self.accountInfo['sharedAccountList']:
                logUtils.logInfo(MODULE_NAME, "Image is not from the Marriott accounts. The ECS instance will be stopped.")
                self.violationCategory = "NON_APPROVED_OWNER"
                self.violationDetail = f"Image owned by {imageOwnerAccount} is not in approved Marriott Ali Cloud accounts."
                self.imageOwnerAccount = imageOwnerAccount
                return True

            # ---------- Tag Format Violation Category ----------
            tagMatched = {}
            for pattern in regexMarriott:
                re.compile(regexMarriott[pattern])
                # response = re.search(pattern, tags['cloudservice'])
                response = re.match(regexMarriott[pattern], imageTagsDict[pattern])
                if response is None:
                    tagMatched[pattern] = imageTagsDict[pattern]

            if tagMatched != {}:
                logUtils.logInfo(MODULE_NAME, "The following key values are incorrect with respect to Marriott tag format:")
                logUtils.logInfo(MODULE_NAME, tagMatched)
                self.violationCategory = "TAG_FORMAT_VIOLATION"
                self.violationDetail = f"Tag(s) failed Marriott tag format: {tagMatched}"
                self.tagMatched = tagMatched
                return True

            logUtils.logInfo(MODULE_NAME, "All tag values are inline with Marriott tag format.")
            return False

        except TeaException as e:
            if e.message == 'Not Found' and getattr(e, 'statusCode', None) == 404:
                logUtils.logInfo(MODULE_NAME, "Description Does Not Exist")
                return False
            else:
                logUtils.logInfo(MODULE_NAME, e)
                return False

        except Exception as e:
            if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
                error = e
            else:
                error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
            logUtils.logError(MODULE_NAME, error)
            raise
        return False

    # remediates the violation
    def remediate(self):
        '''
        The instance with the Image apart from the approved Image list will be stopped.
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.remediate.__name__)

        try:
            stopInstanceResponse = self.client.stop_instance(instance_id=self.resource)
            if stopInstanceResponse.status_code == 200:
                logUtils.logInfo(MODULE_NAME, "Instance stopped.")
            return True

        except Exception as e:
            if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
                error = e
            else:
                error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
            logUtils.logError(MODULE_NAME, error)

            # If the remediation fails at any point in time, retry it again

            if self.retryAttempts <= 0:
                logUtils.logInfo(MODULE_NAME, "Remediation NOT performed, maximum retry attempts done! EXITING")
                self.ruleConfiguration['alertsEnabled'] = False
                raise
            else:
                logUtils.logInfo(MODULE_NAME, "Remediation not performed, retrying in 20s ..")
                time.sleep(20)
                self.retryAttempts = self.retryAttempts - 1
                self.remediate()  # retry remediation again
        return False

    def rollback(self):
        '''
        This function rolls back the remediation
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.rollback.__name__)

        try:
            self.client.start_instance(instance_id=self.resource)
            logUtils.logInfo(MODULE_NAME, "Remediation rolled back successfully.")

        except Exception as e:
            logUtils.logError(MODULE_NAME, "Unable to rollback remediation: " + str(e))
            raise

    def getEventCustomPayload(self):
        try:
            payload = {
                "imageOwnerAccount": self.imageOwnerAccount,
                "violationCategory": self.violationCategory,
                "violationDetail": self.violationDetail,
            }
            if self.tagMatched:
                payload["failedTags"] = self.tagMatched
            return payload
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return {"error": str(e)}
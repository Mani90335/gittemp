"""
sagemakerHandler.py
Leaf class — the ONLY place that knows how to enumerate SageMaker
resources. Everything else (getting a client in the right account,
resolving owner/last-used, building a row, collecting errors) comes from
AIInventoryEventHandlerAWSService.

PATCH NOTE (2026-09-15): every _scanX() here now fetches tags BEFORE
calling resolveOwnerAndLastUsed(), instead of passing {} for the six
methods that previously skipped it (Endpoint already fetched tags; the
rest didn't). resolveOwnerAndLastUsed()'s tag-first, CloudTrail-fallback
logic was always correct — the gap was that most callers never gave it
any tags to check.

Three resource types (list_training_jobs, list_processing_jobs,
list_domains, list_notebook_instances) return their own Arn field
directly in the list response — used as-is. Two do NOT
(list_spaces, list_apps) — their ARNs are constructed here from the
documented ARN format, since SageMaker's list-summary responses for
these two resource types don't include one. A wrong construction
degrades to the exact same "no tags found" behavior as before this
patch (tagHelper's try/except catches it) — it cannot make anything
worse than the current CloudTrail-only behavior; a permissions error
still means all is fine as tags fetch is best-effort.
"""
from src.utils import logUtils
from src.utils.AIInventoryEventHandler import AIInventoryEventHandlerAWSService
from src.helpers import tagHelper
from src.config import config

MODULE_NAME = __file__


class SageMakerHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['SAGEMAKER']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanEndpoints())
            rows.extend(self._scanNotebooks())
            rows.extend(self._scanTrainingJobs())
            rows.extend(self._scanStudioDomains())
            rows.extend(self._scanStudioSpaces())
            rows.extend(self._scanStudioApps())
            rows.extend(self._scanProcessingJobs())
            rows.extend(self._scanCodeRepositories())
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    def _scanEndpoints(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEndpoints.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_endpoints").paginate():
                for ep in page["Endpoints"]:
                    name = ep["EndpointName"]
                    tags = tagHelper.getSageMakerTags(self.client, ep["EndpointArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, ep.get("LastModifiedTime"))
                    rows.append(self.makeRow(name, "Endpoint", owner, lastUsed, {
                        "status": ep["EndpointStatus"],
                        "created": ep["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("endpoints", e)
        return rows

    def _scanNotebooks(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanNotebooks.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_notebook_instances").paginate():
                for nb in page["NotebookInstances"]:
                    name = nb["NotebookInstanceName"]
                    tags = tagHelper.getSageMakerTags(self.client, nb["NotebookInstanceArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, nb.get("LastModifiedTime"))
                    rows.append(self.makeRow(name, "NotebookInstance", owner, lastUsed, {
                        "status": nb["NotebookInstanceStatus"],
                        "instance_type": nb.get("InstanceType"),
                        "created": nb["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("notebooks", e)
        return rows

    def _scanTrainingJobs(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanTrainingJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_training_jobs").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for tj in page["TrainingJobSummaries"]:
                    name = tj["TrainingJobName"]
                    tags = tagHelper.getSageMakerTags(self.client, tj["TrainingJobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, tj.get("LastModifiedTime", tj["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "TrainingJob", owner, lastUsed, {
                        "status": tj["TrainingJobStatus"],
                        "created": tj["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("training_jobs", e)
        return rows

    # Studio resources use a different resource model than classic
    # Notebook Instances: a Studio notebook lives inside a Domain, runs
    # inside a Space, and the actual running compute is an "App".
    def _scanStudioDomains(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanStudioDomains.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_domains").paginate():
                for d in page["Domains"]:
                    name = d["DomainName"]
                    tags = tagHelper.getSageMakerTags(self.client, d["DomainArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, d.get("LastModifiedTime", d.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "StudioDomain", owner, lastUsed, {
                        "domain_id": d.get("DomainId"), "status": d.get("Status"),
                        "created": str(d.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_domains", e)
        return rows

    def _scanStudioSpaces(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanStudioSpaces.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_spaces").paginate():
                for s in page["Spaces"]:
                    name = s.get("SpaceName")
                    # list_spaces' summary has no SpaceArn field (unlike
                    # describe_space) — constructed from the documented
                    # ARN format instead. See module docstring.
                    spaceArn = f"arn:aws:sagemaker:{self.region}:{self.accountId}:space/{s.get('DomainId')}/{name}"
                    tags = tagHelper.getSageMakerTags(self.client, spaceArn)
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, s.get("LastModifiedTime", s.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "StudioSpace", owner, lastUsed, {
                        "domain_id": s.get("DomainId"), "status": s.get("Status"),
                        "space_sharing_type": s.get("SpaceSharingSettingsSummary", {}).get("SharingType"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_spaces", e)
        return rows

    def _scanStudioApps(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanStudioApps.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_apps").paginate():
                for a in page["Apps"]:
                    name = a.get("AppName")
                    # list_apps' summary has no AppArn field either — the
                    # "owner" segment of the ARN is the user profile name
                    # for a private app, or the space name for a
                    # (newer) shared-space app; use whichever is present.
                    owner_segment = a.get("UserProfileName") or a.get("SpaceName")
                    appArn = (f"arn:aws:sagemaker:{self.region}:{self.accountId}:app/"
                              f"{a.get('DomainId')}/{owner_segment}/{a.get('AppType')}/{name}")
                    tags = tagHelper.getSageMakerTags(self.client, appArn)
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, a.get("LastHealthCheckTimestamp", a.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, f"StudioApp({a.get('AppType')})", owner, lastUsed, {
                        "domain_id": a.get("DomainId"), "space_name": a.get("SpaceName"),
                        "user_profile_name": a.get("UserProfileName"), "status": a.get("Status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_apps", e)
        return rows

    def _scanProcessingJobs(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanProcessingJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_processing_jobs").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for pj in page["ProcessingJobSummaries"]:
                    name = pj["ProcessingJobName"]
                    tags = tagHelper.getSageMakerTags(self.client, pj["ProcessingJobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, pj.get("LastModifiedTime", pj["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "ProcessingJob", owner, lastUsed, {
                        "status": pj["ProcessingJobStatus"], "created": pj["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_processing_jobs", e)
        return rows

    def _scanCodeRepositories(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanCodeRepositories.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_code_repositories").paginate():
                for cr in page["CodeRepositorySummaryList"]:
                    name = cr["CodeRepositoryName"]
                    tags = tagHelper.getSageMakerTags(self.client, cr["CodeRepositoryArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, cr.get("LastModifiedTime", cr["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "CodeRepository", owner, lastUsed, {
                        "created": cr["CreationTime"].isoformat(),
                        "repository_url": cr.get("GitConfig", {}).get("RepositoryUrl"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_code_repositories", e)
        return rows

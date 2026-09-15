"""
sagemakerHandler.py
Leaf class — the ONLY place that knows how to enumerate SageMaker
resources. Everything else (getting a client in the right account,
resolving owner/last-used, building a row, collecting errors) comes from
AIInventoryEventHandlerAWSService.

PATCH NOTE (2026-09-15b): added the resource types the team flagged as
gaps against the full SageMaker feature catalog:
  - Model (the artifact itself, distinct from an Endpoint)
  - Model Package / Model Package Group (Model Registry)
  - Endpoint Config (what an Endpoint is built from)
  - Transform Job (Batch Transform)
  - Hyperparameter Tuning Job
  - Pipeline / Pipeline Execution
  - Feature Group (Feature Store)
  - Model Explainability / Bias Job — NOT a new list call. These run AS
    Processing Jobs, so _scanProcessingJobs() now does one extra
    describe_processing_job call per job to detect a SageMaker Clarify
    container and relabel that row's Type accordingly, instead of every
    Clarify run being invisible inside an undifferentiated
    "ProcessingJob" bucket. See _scanProcessingJobs()'s docstring.
  - Inference Recommender Job
  - Lifecycle Config — BOTH flavors: classic Notebook Instance Lifecycle
    Configs and Studio Lifecycle Configs (two different list calls,
    two different resource shapes, same underlying idea)
  - Ground Truth Labeling Job
  - MLflow Tracking Server

VERIFY-BEFORE-DEPLOY: MLflow Tracking Servers (list_mlflow_tracking_servers)
is the newest API surface touched in this patch. Every other addition
here has existed in the SageMaker API for multiple years and follows the
same list_* + paginator + ARN-in-summary shape already used everywhere
in this file, so those are lower-risk. As with the rest of this
codebase, every call is wrapped in its own try/except — a wrong field
name degrades to a missing Details field, never a broken scan — but
still worth a real-account smoke test before trusting the MLflow rows.

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

# Container image name fragment SageMaker Clarify processing jobs run
# under — used by _scanProcessingJobs() to relabel a Clarify run instead
# of leaving it as an undifferentiated "ProcessingJob". If AWS ever
# changes this image naming, the job just falls back to being reported
# as a plain "ProcessingJob" (same as today), never an error.
CLARIFY_IMAGE_FRAGMENT = "sagemaker-clarify-processing"


class SageMakerHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['SAGEMAKER']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanEndpoints())
            rows.extend(self._scanEndpointConfigs())
            rows.extend(self._scanModels())
            rows.extend(self._scanNotebooks())
            rows.extend(self._scanTrainingJobs())
            rows.extend(self._scanStudioDomains())
            rows.extend(self._scanStudioSpaces())
            rows.extend(self._scanStudioApps())
            rows.extend(self._scanProcessingJobs())
            rows.extend(self._scanCodeRepositories())
            rows.extend(self._scanModelPackageGroups())
            rows.extend(self._scanModelPackages())
            rows.extend(self._scanTransformJobs())
            rows.extend(self._scanHyperparameterTuningJobs())
            pipelineRows, pipelineNames = self._scanPipelines()
            rows.extend(pipelineRows)
            rows.extend(self._scanPipelineExecutions(pipelineNames))
            rows.extend(self._scanFeatureGroups())
            rows.extend(self._scanInferenceRecommendationsJobs())
            rows.extend(self._scanNotebookLifecycleConfigs())
            rows.extend(self._scanStudioLifecycleConfigs())
            rows.extend(self._scanLabelingJobs())
            rows.extend(self._scanMlflowTrackingServers())
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    # -- Existing resource types -------------------------------------

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
        """PATCH (2026-09-15b): now does one describe_processing_job call
        per job to detect a SageMaker Clarify container image and
        relabel that row's Type as "ProcessingJob(ModelBiasOrExplainability)"
        instead of a plain "ProcessingJob" — Clarify has no list call of
        its own; a bias/explainability run IS a Processing Job, just an
        undistinguished one until this describe call is made. The extra
        describe call is best-effort: any failure just leaves the job
        labeled as a plain ProcessingJob, same as before this patch."""
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
                    resourceType = "ProcessingJob"
                    isClarify = False
                    try:
                        detail = self.client.describe_processing_job(ProcessingJobName=name)
                        imageUri = detail.get("AppSpecification", {}).get("ImageUri", "")
                        if CLARIFY_IMAGE_FRAGMENT in imageUri:
                            isClarify = True
                            resourceType = "ProcessingJob(ModelBiasOrExplainability)"
                    except Exception as e:
                        logUtils.logDebug(
                            MODULE_NAME,
                            f"Could not describe processing job {name} to check for Clarify — "
                            f"leaving it labeled as a plain ProcessingJob: {e}"
                        )
                    rows.append(self.makeRow(name, resourceType, owner, lastUsed, {
                        "status": pj["ProcessingJobStatus"], "created": pj["CreationTime"].isoformat(),
                        "is_clarify_job": isClarify,
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

    # -- New resource types (2026-09-15b) ------------------------------

    def _scanEndpointConfigs(self):
        """list_endpoint_configs — the config an Endpoint is built from
        (instance type, variants). Distinct from the Endpoint itself; a
        config can exist with no live Endpoint using it any more."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEndpointConfigs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_endpoint_configs").paginate():
                for ec in page["EndpointConfigs"]:
                    name = ec["EndpointConfigName"]
                    tags = tagHelper.getSageMakerTags(self.client, ec["EndpointConfigArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, ec.get("CreationTime"))
                    rows.append(self.makeRow(name, "EndpointConfig", owner, lastUsed, {
                        "created": str(ec.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_endpoint_configs", e)
        return rows

    def _scanModels(self):
        """list_models — the registered Model artifact/inference-code
        pointer itself. Distinct from an Endpoint: a Model can exist
        (an approved-but-unused artifact worth tracking) without ever
        being deployed."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanModels.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_models").paginate():
                for m in page["Models"]:
                    name = m["ModelName"]
                    tags = tagHelper.getSageMakerTags(self.client, m["ModelArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, m.get("CreationTime"))
                    rows.append(self.makeRow(name, "Model", owner, lastUsed, {
                        "created": str(m.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_models", e)
        return rows

    def _scanModelPackageGroups(self):
        """list_model_package_groups — Model Registry governance grouping
        (approval status/versioning lives on the packages inside it)."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanModelPackageGroups.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_model_package_groups").paginate():
                for g in page["ModelPackageGroupSummaryList"]:
                    name = g["ModelPackageGroupName"]
                    tags = tagHelper.getSageMakerTags(self.client, g["ModelPackageGroupArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, g.get("CreationTime"))
                    rows.append(self.makeRow(name, "ModelPackageGroup", owner, lastUsed, {
                        "status": g.get("ModelPackageGroupStatus"),
                        "created": str(g.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_model_package_groups", e)
        return rows

    def _scanModelPackages(self):
        """list_model_packages — versioned Model Registry entries
        (covers both standalone packages and versioned packages that
        belong to a ModelPackageGroup; the group membership, if any,
        shows up in ModelPackageGroupName)."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanModelPackages.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_model_packages").paginate():
                for p in page["ModelPackageSummaryList"]:
                    name = p.get("ModelPackageName")
                    version = p.get("ModelPackageVersion")
                    resourceName = f"{name}/v{version}" if version else name
                    tags = tagHelper.getSageMakerTags(self.client, p["ModelPackageArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        resourceName, tags, p.get("CreationTime")
                    )
                    rows.append(self.makeRow(resourceName, "ModelPackage", owner, lastUsed, {
                        "model_package_group_name": p.get("ModelPackageGroupName"),
                        "approval_status": p.get("ModelApprovalStatus"),
                        "created": str(p.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_model_packages", e)
        return rows

    def _scanTransformJobs(self):
        """list_transform_jobs — offline/batch inference (Batch
        Transform), a whole inference pattern separate from real-time
        Endpoints."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanTransformJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_transform_jobs").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for tj in page["TransformJobSummaries"]:
                    name = tj["TransformJobName"]
                    tags = tagHelper.getSageMakerTags(self.client, tj["TransformJobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, tj.get("LastModifiedTime", tj["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "TransformJob", owner, lastUsed, {
                        "status": tj["TransformJobStatus"],
                        "created": tj["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_transform_jobs", e)
        return rows

    def _scanHyperparameterTuningJobs(self):
        """list_hyper_parameter_tuning_jobs — can spin up many concurrent
        Training Jobs, so it's cost-relevant on its own even though the
        individual Training Jobs it spawns are already scanned."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanHyperparameterTuningJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_hyper_parameter_tuning_jobs").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for hj in page["HyperParameterTuningJobSummaries"]:
                    name = hj["HyperParameterTuningJobName"]
                    tags = tagHelper.getSageMakerTags(self.client, hj["HyperParameterTuningJobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, hj.get("LastModifiedTime", hj["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "HyperparameterTuningJob", owner, lastUsed, {
                        "status": hj["HyperParameterTuningJobStatus"],
                        "created": hj["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_hyper_parameter_tuning_jobs", e)
        return rows

    def _scanPipelines(self):
        """list_pipelines — SageMaker Pipelines (MLOps workflow
        orchestration). Returns (rows, pipelineNames) so executions can
        be scanned per pipeline below, same pattern as
        _scanAgents()/_scanAgentAliases() in bedrockHandler.py."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanPipelines.__name__)
        rows, pipelineNames = [], []
        try:
            for page in self.client.get_paginator("list_pipelines").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for p in page["PipelineSummaries"]:
                    name = p["PipelineName"]
                    pipelineNames.append(name)
                    tags = tagHelper.getSageMakerTags(self.client, p["PipelineArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, p.get("LastModifiedTime", p.get("LastExecutionTime", p.get("CreationTime")))
                    )
                    rows.append(self.makeRow(name, "Pipeline", owner, lastUsed, {
                        "created": str(p.get("CreationTime")),
                        "last_execution_time": str(p.get("LastExecutionTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_pipelines", e)
        return rows, pipelineNames

    def _scanPipelineExecutions(self, pipelineNames):
        """list_pipeline_executions(PipelineName=...) — per pipeline, no
        account-wide call exists. No tags of their own (executions
        inherit the parent Pipeline's tags/ownership), so ownership here
        is resolved from the execution's own timestamp/CloudTrail only,
        same as FlowVersion in bedrockHandler.py."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanPipelineExecutions.__name__)
        rows = []
        for pipelineName in pipelineNames:
            try:
                for page in self.client.get_paginator("list_pipeline_executions").paginate(
                    PipelineName=pipelineName, SortBy="CreationTime", SortOrder="Descending"
                ):
                    for ex in page["PipelineExecutionSummaries"]:
                        execArn = ex.get("PipelineExecutionArn", "")
                        execId = execArn.split("/")[-1] if execArn else "unknown-execution"
                        resourceName = f"{pipelineName}/{execId}"
                        owner, lastUsed = self.resolveOwnerAndLastUsed(
                            resourceName, {}, ex.get("LastModifiedTime", ex.get("StartTime"))
                        )
                        rows.append(self.makeRow(resourceName, "PipelineExecution", owner, lastUsed, {
                            "pipeline_name": pipelineName,
                            "status": ex.get("PipelineExecutionStatus"),
                            "started": str(ex.get("StartTime")),
                        }))
            except Exception as e:
                self.logScanError(f"list_pipeline_executions:{pipelineName}", e)
        return rows

    def _scanFeatureGroups(self):
        """list_feature_groups — Feature Store. May contain sensitive/PII
        feature data with no other inventory trail, per the coverage
        catalog's own note."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanFeatureGroups.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_feature_groups").paginate():
                for fg in page["FeatureGroupSummaries"]:
                    name = fg["FeatureGroupName"]
                    tags = tagHelper.getSageMakerTags(self.client, fg["FeatureGroupArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, fg.get("CreationTime"))
                    rows.append(self.makeRow(name, "FeatureGroup", owner, lastUsed, {
                        "status": fg.get("FeatureGroupStatus"),
                        "created": str(fg.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_feature_groups", e)
        return rows

    def _scanInferenceRecommendationsJobs(self):
        """list_inference_recommendations_jobs — right-sizing
        recommendation jobs."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanInferenceRecommendationsJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_inference_recommendations_jobs").paginate():
                for j in page["InferenceRecommendationsJobs"]:
                    name = j["JobName"]
                    tags = tagHelper.getSageMakerTags(self.client, j["JobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, j.get("LastModifiedTime", j.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "InferenceRecommendationsJob", owner, lastUsed, {
                        "status": j.get("Status"),
                        "created": str(j.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_inference_recommendations_jobs", e)
        return rows

    def _scanNotebookLifecycleConfigs(self):
        """list_notebook_instance_lifecycle_configs — startup scripts for
        classic Notebook Instances. Security-relevant: arbitrary code
        runs at notebook startup."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanNotebookLifecycleConfigs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_notebook_instance_lifecycle_configs").paginate():
                for lc in page["NotebookInstanceLifecycleConfigs"]:
                    name = lc["NotebookInstanceLifecycleConfigName"]
                    tags = tagHelper.getSageMakerTags(self.client, lc["NotebookInstanceLifecycleConfigArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, lc.get("LastModifiedTime", lc.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "NotebookInstanceLifecycleConfig", owner, lastUsed, {
                        "created": str(lc.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_notebook_instance_lifecycle_configs", e)
        return rows

    def _scanStudioLifecycleConfigs(self):
        """list_studio_lifecycle_configs — the Studio-domain equivalent
        of the classic Notebook Instance Lifecycle Config above; same
        security relevance (arbitrary code at Studio app/space startup)."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanStudioLifecycleConfigs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_studio_lifecycle_configs").paginate():
                for lc in page["StudioLifecycleConfigs"]:
                    name = lc["StudioLifecycleConfigName"]
                    tags = tagHelper.getSageMakerTags(self.client, lc["StudioLifecycleConfigArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, lc.get("CreationTime"))
                    rows.append(self.makeRow(name, "StudioLifecycleConfig", owner, lastUsed, {
                        "app_type": lc.get("StudioLifecycleConfigAppType"),
                        "created": str(lc.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_studio_lifecycle_configs", e)
        return rows

    def _scanLabelingJobs(self):
        """list_labeling_jobs — Ground Truth labeling jobs. Often touches
        raw, unlabeled — sometimes sensitive — data, per the coverage
        catalog's own note."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanLabelingJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_labeling_jobs").paginate(
                SortBy="CreationTime", SortOrder="Descending"
            ):
                for lj in page["LabelingJobSummaryList"]:
                    name = lj["LabelingJobName"]
                    tags = tagHelper.getSageMakerTags(self.client, lj["LabelingJobArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, lj.get("LastModifiedTime", lj["CreationTime"])
                    )
                    rows.append(self.makeRow(name, "LabelingJob", owner, lastUsed, {
                        "status": lj["LabelingJobStatus"],
                        "created": lj["CreationTime"].isoformat(),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_labeling_jobs", e)
        return rows

    def _scanMlflowTrackingServers(self):
        """list_mlflow_tracking_servers — managed MLflow. Newest API
        surface touched in this patch — see module docstring's
        VERIFY-BEFORE-DEPLOY note."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanMlflowTrackingServers.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_mlflow_tracking_servers").paginate():
                for ts in page["TrackingServerSummaries"]:
                    name = ts["TrackingServerName"]
                    tags = tagHelper.getSageMakerTags(self.client, ts["TrackingServerArn"])
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, ts.get("LastModifiedTime", ts.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "MlflowTrackingServer", owner, lastUsed, {
                        "status": ts.get("TrackingServerStatus"),
                        "created": str(ts.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_mlflow_tracking_servers", e)
        return rows

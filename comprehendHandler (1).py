"""
comprehendHandler.py
Leaf class for Comprehend — batch jobs, custom Entity Recognizers,
custom Document Classifiers, real-time custom Endpoints, Flywheels, and
Flywheel-associated Datasets.

PATCH NOTE (2026-09-15c): fixed "operation cannot be paginated:
list_flywheels". ListFlywheels and ListDatasets both support NextToken/
MaxResults in their actual request shape, but neither one has a
botocore-generated paginator config (confirmed by inspecting botocore's
own paginators-1.json for comprehend — most Comprehend list calls are
in there, these two are not). get_paginator("list_flywheels") /
get_paginator("list_datasets") therefore raise
OperationNotPageableError unconditionally, regardless of how many
flywheels or datasets actually exist. Both now page manually with a
plain while-loop over NextToken instead. TopicsDetectionJob IS a real
paginated operation (ListTopicsDetectionJobs), but _scanBatchJobs()
below never used get_paginator for any job type in the first place —
it only fetches one page per job type — so it isn't affected by this
same bug, though FYI it means DocumentClassificationJob etc. have
always been single-page-only reads too, in case a large backlog of any
job type is not fully appearing in the output.

PATCH NOTE (2026-09-15b): added the resource types the team flagged as
gaps against the full Comprehend feature catalog:
  - Document Classifier (custom-trained classification model) — same
    shape as EntityRecognizer below, just a different resource family.
  - Topics Detection Job / Targeted Sentiment Detection Job — these
    slot straight into the existing _scanBatchJobs() jobCalls dict,
    since both follow the exact same "<JobType>JobPropertiesList" /
    "<JobType>Arn" shape every other batch job type here already uses.
    No new method needed for either.
  - Flywheel (continuous model-retraining pipeline / AutoML-MLOps
    feature) and Dataset (training/test data tied to a Flywheel) — a
    Dataset has no account-wide list call; list_datasets requires a
    FlywheelArn, so Datasets are scanned per Flywheel found, same
    parent/child pattern as Agent -> AgentAlias in bedrockHandler.py.

PATCH NOTE (2026-09-15): _scanBatchJobs() and _scanEntityRecognizers()
now fetch tags before resolving owner, same as _scanEndpoints() already
did. Every Comprehend batch-job response carries its own
`<JobType>JobArn` field (e.g. DocumentClassificationJobArn,
EntitiesDetectionJobArn) — used directly, no ARN construction needed
here (unlike some of the SageMaker Studio resources).
"""
from src.utils import logUtils
from src.utils.AIInventoryEventHandler import AIInventoryEventHandlerAWSService
from src.helpers import tagHelper
from src.config import config

MODULE_NAME = __file__


class ComprehendHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['COMPREHEND']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanBatchJobs())
            rows.extend(self._scanEntityRecognizers())
            rows.extend(self._scanDocumentClassifiers())
            rows.extend(self._scanEndpoints())
            flywheelRows, flywheelArns = self._scanFlywheels()
            rows.extend(flywheelRows)
            rows.extend(self._scanDatasets(flywheelArns))
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    # Job types whose list operation DOES have a botocore paginator
    # config (confirmed against botocore's own paginators-1.json for
    # comprehend). Paged properly via get_paginator() below.
    _PAGINATED_JOB_TYPES = {
        "DocumentClassificationJob": "list_document_classification_jobs",
        "EntitiesDetectionJob": "list_entities_detection_jobs",
        "SentimentDetectionJob": "list_sentiment_detection_jobs",
        "KeyPhrasesDetectionJob": "list_key_phrases_detection_jobs",
        "PiiEntitiesDetectionJob": "list_pii_entities_detection_jobs",
        "TopicsDetectionJob": "list_topics_detection_jobs",
    }
    # TargetedSentimentDetectionJob is the odd one out — same situation
    # as ListFlywheels/ListDatasets: the operation supports NextToken/
    # MaxResults, but botocore has no paginator config for it, so
    # get_paginator() would raise OperationNotPageableError. Paged
    # manually below instead.
    _MANUALLY_PAGED_JOB_TYPE = ("TargetedSentimentDetectionJob", "list_targeted_sentiment_detection_jobs")

    def _scanBatchJobs(self):
        """PATCH (2026-09-15d): every job type now pages to exhaustion
        instead of reading only the first page. Previously ALL seven job
        types here read a single page via one direct call — silently
        under-reporting any job type with enough jobs to span multiple
        pages, even though six of the seven (all but
        TargetedSentimentDetectionJob) support real pagination."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanBatchJobs.__name__)
        rows = []

        for jobType, operationName in self._PAGINATED_JOB_TYPES.items():
            try:
                for page in self.client.get_paginator(operationName).paginate():
                    listKey = [k for k in page if k.endswith("JobPropertiesList")]
                    jobs = page[listKey[0]] if listKey else []
                    rows.extend(self._rowsForJobs(jobType, jobs))
            except Exception as e:
                self.logScanError(jobType, e)

        manualJobType, manualOperationName = self._MANUALLY_PAGED_JOB_TYPE
        try:
            call = getattr(self.client, manualOperationName)
            nextToken = None
            while True:
                resp = call(**({"NextToken": nextToken} if nextToken else {}))
                listKey = [k for k in resp if k.endswith("JobPropertiesList")]
                jobs = resp[listKey[0]] if listKey else []
                rows.extend(self._rowsForJobs(manualJobType, jobs))
                nextToken = resp.get("NextToken")
                if not nextToken:
                    break
        except Exception as e:
            self.logScanError(manualJobType, e)

        return rows

    def _rowsForJobs(self, jobType, jobs):
        """Shared per-job-type row-building logic, factored out so both
        the paginated loop and the manually-paged
        TargetedSentimentDetectionJob loop above build identical rows."""
        rows = []
        for j in jobs:
            try:
                name = j.get("JobName") or j.get("JobId")
                submitTime = j.get("SubmitTime")
                endTime = j.get("EndTime", submitTime)
                # Every job type's own ARN field follows the pattern
                # "<JobType>Arn" (e.g. DocumentClassificationJobArn).
                # tagHelper's try/except covers the (unlikely) case
                # this key is ever missing on a given job type.
                jobArn = j.get(f"{jobType}Arn")
                tags = tagHelper.getComprehendTags(self.client, jobArn) if jobArn else {}
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, endTime)
                rows.append(self.makeRow(name, jobType, owner, lastUsed, {
                    "status": j.get("JobStatus"),
                    "submitted": submitTime.isoformat() if submitTime else None,
                    "tags": tags,
                }))
            except Exception as e:
                # One malformed job entry shouldn't drop the rest of the
                # page — logged and skipped, same as every other
                # per-item failure in this codebase.
                self.logScanError(f"{jobType}:row", e)
        return rows

    # Not a batch job — a custom-trained model.
    def _scanEntityRecognizers(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEntityRecognizers.__name__)
        rows = []
        try:
            for r in self.client.list_entity_recognizers().get("EntityRecognizerPropertiesList", []):
                name = r["EntityRecognizerArn"].split("/")[-1]
                tags = tagHelper.getComprehendTags(self.client, r["EntityRecognizerArn"])
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, r.get("EndTime", r.get("SubmitTime")))
                rows.append(self.makeRow(name, "EntityRecognizer", owner, lastUsed, {
                    "status": r.get("Status"),
                    "tags": tags,
                }))
        except Exception as e:
            self.logScanError("entity_recognizers", e)
        return rows

    # Also not a batch job — a custom-trained classification model.
    # Same shape as EntityRecognizer above: list_document_classifiers
    # (no paginator needed — same as list_entity_recognizers, which
    # this mirrors), name parsed from the ARN since the summary has no
    # separate "name" field of its own.
    def _scanDocumentClassifiers(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanDocumentClassifiers.__name__)
        rows = []
        try:
            for c in self.client.list_document_classifiers().get("DocumentClassifierPropertiesList", []):
                arn = c["DocumentClassifierArn"]
                name = arn.split("/")[-1]
                tags = tagHelper.getComprehendTags(self.client, arn)
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, c.get("EndTime", c.get("SubmitTime")))
                rows.append(self.makeRow(name, "DocumentClassifier", owner, lastUsed, {
                    "status": c.get("Status"),
                    "language_code": c.get("LanguageCode"),
                    "tags": tags,
                }))
        except Exception as e:
            self.logScanError("document_classifiers", e)
        return rows

    # Real-time custom Endpoints — the only Comprehend resource type with
    # a real CloudWatch usage metric (ConsumedInferenceUnits).
    def _scanEndpoints(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEndpoints.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_endpoints").paginate():
                for ep in page.get("EndpointPropertiesList", []):
                    endpointArn = ep.get("EndpointArn", "")
                    name = endpointArn.split("/")[-1] if endpointArn else "unknown-endpoint"
                    tags = tagHelper.getComprehendTags(self.client, endpointArn) if endpointArn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, ep.get("LastModifiedTime", ep.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "Endpoint", owner, lastUsed, {
                        "endpoint_arn": endpointArn,
                        "status": ep.get("Status"),
                        "model_arn": ep.get("ModelArn"),
                        "desired_inference_units": ep.get("DesiredInferenceUnits"),
                        "current_inference_units": ep.get("CurrentInferenceUnits"),
                        "created": str(ep.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_endpoints", e)
        return rows

    def _scanFlywheels(self):
        """list_flywheels — continuous model-retraining pipeline
        (AutoML/MLOps feature). Automates creating new classifier/
        recognizer versions — invisible today without this. Returns
        (rows, flywheelArns) so Datasets can be scanned per flywheel
        below, same parent/child pattern as Agent -> AgentAlias in
        bedrockHandler.py.

        Paged MANUALLY via NextToken, not get_paginator() — ListFlywheels
        has no botocore paginator config even though the API itself
        supports NextToken. See module docstring."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanFlywheels.__name__)
        rows, flywheelArns = [], []
        try:
            nextToken = None
            while True:
                kwargs = {"NextToken": nextToken} if nextToken else {}
                resp = self.client.list_flywheels(**kwargs)
                for f in resp.get("FlywheelSummaryList", []):
                    arn = f.get("FlywheelArn")
                    name = arn.split("/")[-1] if arn else "unknown-flywheel"
                    if arn:
                        flywheelArns.append((arn, name))
                    tags = tagHelper.getComprehendTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, f.get("LastModifiedTime", f.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "Flywheel", owner, lastUsed, {
                        "status": f.get("Status"),
                        "model_type": f.get("ModelType"),
                        "active_model_arn": f.get("ActiveModelArn"),
                        "tags": tags,
                    }))
                nextToken = resp.get("NextToken")
                if not nextToken:
                    break
        except Exception as e:
            self.logScanError("list_flywheels", e)
        return rows, flywheelArns

    def _scanDatasets(self, flywheelArns):
        """list_datasets(FlywheelArn=...) — training/test data tied to a
        Flywheel. No account-wide list call exists; scanned per flywheel
        found above. No separate tagging API for Datasets, so ownership
        here comes from the dataset's own timestamp/CloudTrail only,
        same as PipelineExecution in sagemakerHandler.py.

        Paged MANUALLY via NextToken, not get_paginator() — same
        situation as ListFlywheels above; ListDatasets has no botocore
        paginator config either."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanDatasets.__name__)
        rows = []
        for flywheelArn, flywheelName in flywheelArns:
            try:
                nextToken = None
                while True:
                    kwargs = {"FlywheelArn": flywheelArn}
                    if nextToken:
                        kwargs["NextToken"] = nextToken
                    resp = self.client.list_datasets(**kwargs)
                    for d in resp.get("DatasetPropertiesList", []):
                        name = d.get("DatasetName")
                        resourceName = f"{flywheelName}/{name}" if flywheelName else name
                        owner, lastUsed = self.resolveOwnerAndLastUsed(
                            resourceName, {}, d.get("LastModifiedTime", d.get("CreationTime"))
                        )
                        rows.append(self.makeRow(resourceName, "Dataset", owner, lastUsed, {
                            "flywheel_arn": flywheelArn,
                            "dataset_type": d.get("DatasetType"),
                            "status": d.get("Status"),
                        }))
                    nextToken = resp.get("NextToken")
                    if not nextToken:
                        break
            except Exception as e:
                self.logScanError(f"list_datasets:{flywheelArn}", e)
        return rows

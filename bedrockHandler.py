"""
bedrockHandler.py
Leaf class for Bedrock — Custom Models, Provisioned Throughput, Agents,
Agent Aliases, Knowledge Bases, Guardrails, Prompts, Flows (+ Flow
Aliases/Versions), Model Evaluation Jobs, Model Customization Jobs,
Model Import Jobs, Imported Models, Batch Inference Jobs, Application
Inference Profiles, Marketplace Model Endpoints, Automated Reasoning
Policies, Prompt Routers, plus the account/region's invocation-logging
config.

Deliberately does NOT list Foundation Models (bedrock:ListFoundationModels)
— that's AWS's built-in catalog, identical across every account, not
something this account created or used. For the same reason,
_scanInferenceProfiles() only keeps type == "APPLICATION" (skips
"SYSTEM_DEFINED" profiles AWS publishes for every foundation model), and
_scanPromptRouters() only keeps routers this account actually created
(skips AWS's built-in default routers) — see each method's docstring.

Needs a second client — bedrock-agent — for Agents/Aliases/Knowledge
Bases/Prompts/Flows, which self.client (built from self.service =
'bedrock' by the base class) doesn't cover. Built the same way, via
MarriottCSAO_utils.getAwsClient, just for a different service name.

PATCH NOTE (2026-09-15b): added the resource types the team flagged as
gaps against the full Bedrock feature catalog (Guardrails, Prompt
Management, Flows, Model Evaluation Jobs, Model Customization Jobs,
Model Import Jobs / Imported Models, Batch Inference Jobs, Application
Inference Profiles, Marketplace Model Endpoints, Automated Reasoning
Policies, Prompt Routers). NOT included in this pass:
  - "On-demand Foundation Model usage" — not a resource, no List API
    exists for it. It's a CloudWatch-only signal, and it's already
    captured today: accountOrchestrator._mergeBedrockUsage() pulls
    AWS/Bedrock Invocations by ModelId, which IS on-demand foundation
    model usage. Nothing to add here.
  - "AgentCore resources" — a separate, newer control-plane API
    (bedrock-agentcore), distinct from everything else in this file.
    Left for a follow-up leaf class rather than bolted on here.

VERIFY-BEFORE-DEPLOY: the resource types added in this patch use newer
Bedrock APIs (Guardrails, Prompt Management, Flows, Evaluation,
Customization, Model Import, Batch Inference, Inference Profiles,
Marketplace, Automated Reasoning, Prompt Routers). Every field name
below is written from the documented API shape, but several of these
APIs have shipped changes over time — before relying on this in
production, run one scan against a real account and diff the emitted
rows' "Details" against the actual list_* response for each of these
methods, the same way you'd sanity-check any brand-new integration.
Every call is still wrapped the same defensive try/except as the rest
of this codebase, so a wrong field name degrades to "that field is
missing/None in Details" or "no tags found" — it cannot break the scan.

Two DIFFERENT tag helpers are used, because the `bedrock` and
`bedrock-agent` control planes have different tagging APIs (see
tagHelper.py's module docstring for the full explanation):
  - CustomModel / ProvisionedThroughput / Guardrail / EvaluationJob /
    ModelCustomizationJob / ModelImportJob / ImportedModel /
    BatchInferenceJob / ApplicationInferenceProfile /
    MarketplaceModelEndpoint / AutomatedReasoningPolicy / PromptRouter
    -> tagHelper.getBedrockTags() (the `bedrock` client; self.client).
    Every one of these list calls returns its own ARN field directly.
  - Agent / AgentAlias / KnowledgeBase / Prompt / Flow / FlowAlias /
    FlowVersion -> tagHelper.getBedrockAgentTags() (the `bedrock-agent`
    client). Agent/AgentAlias/KnowledgeBase summaries don't return an
    ARN (constructed here from Bedrock's documented ARN format);
    Prompt/Flow/FlowAlias summaries DO return their own `arn` field
    directly.
"""
from src.utils import logUtils, MarriottCSAO_utils
from src.utils.AIInventoryEventHandler import AIInventoryEventHandlerAWSService
from src.helpers import tagHelper
from src.config import config

MODULE_NAME = __file__


class BedrockHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['BEDROCK']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanCustomModels())
            rows.extend(self._scanProvisionedThroughput())
            rows.extend(self._scanGuardrails())
            rows.extend(self._scanEvaluationJobs())
            rows.extend(self._scanModelCustomizationJobs())
            rows.extend(self._scanModelImportJobs())
            rows.extend(self._scanImportedModels())
            rows.extend(self._scanBatchInferenceJobs())
            rows.extend(self._scanApplicationInferenceProfiles())
            rows.extend(self._scanMarketplaceModelEndpoints())
            rows.extend(self._scanAutomatedReasoningPolicies())
            rows.extend(self._scanPromptRouters())

            bedrockAgentClient = MarriottCSAO_utils.getAwsClient(
                config.SERVICE_NAME['BEDROCK_AGENT'], self.accountId, self.region
            )
            if bedrockAgentClient:
                agentRows, agentIds = self._scanAgents(bedrockAgentClient)
                rows.extend(agentRows)
                rows.extend(self._scanAgentAliases(bedrockAgentClient, agentIds))
                rows.extend(self._scanKnowledgeBases(bedrockAgentClient))
                rows.extend(self._scanPrompts(bedrockAgentClient))
                flowRows, flowIds = self._scanFlows(bedrockAgentClient)
                rows.extend(flowRows)
                rows.extend(self._scanFlowAliases(bedrockAgentClient, flowIds))
                rows.extend(self._scanFlowVersions(bedrockAgentClient, flowIds))
            else:
                self.logScanError("bedrock-agent:client", Exception("getAwsClient returned None"))

            rows.extend(self._scanLoggingConfig())
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    def getLoggingStatus(self):
        """Account/region-level flag for the run summary — separate from
        the per-resource logging-config row scan() also appends."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self.getLoggingStatus.__name__)
        try:
            cfg = self.client.get_model_invocation_logging_configuration().get("loggingConfig", {})
            return {"account": self.accountId, "region": self.region, "invocation_logging_enabled": bool(cfg)}
        except Exception as e:
            self.logScanError("logging_status", e)
            return {"account": self.accountId, "region": self.region,
                     "invocation_logging_enabled": False, "error": str(e)}

    # -- Existing resource types -------------------------------------

    def _scanCustomModels(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanCustomModels.__name__)
        rows = []
        try:
            for m in self.client.list_custom_models().get("modelSummaries", []):
                name = m.get("modelName")
                tags = tagHelper.getBedrockTags(self.client, m.get("modelArn")) if m.get("modelArn") else {}
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, m.get("creationTime"))
                rows.append(self.makeRow(name, "CustomModel", owner, lastUsed, {
                    "base_model": m.get("baseModelArn"),
                    "tags": tags,
                }))
        except Exception as e:
            self.logScanError("custom_models", e)
        return rows

    def _scanProvisionedThroughput(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanProvisionedThroughput.__name__)
        rows = []
        try:
            for p in self.client.list_provisioned_model_throughputs().get("provisionedModelSummaries", []):
                name = p.get("provisionedModelName")
                provisionedArn = p.get("provisionedModelArn")
                tags = tagHelper.getBedrockTags(self.client, provisionedArn) if provisionedArn else {}
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, p.get("lastModifiedTime"))
                rows.append(self.makeRow(name, "ProvisionedThroughput", owner, lastUsed, {
                    "status": p.get("status"), "model_arn": p.get("modelArn"),
                    "tags": tags,
                }))
        except Exception as e:
            self.logScanError("provisioned_throughput", e)
        return rows

    def _scanAgents(self, bedrockAgentClient):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanAgents.__name__)
        rows, agentIds = [], []
        try:
            for page in bedrockAgentClient.get_paginator("list_agents").paginate():
                for a in page.get("agentSummaries", []):
                    name = a.get("agentName")
                    agentId = a.get("agentId")
                    if agentId:
                        agentIds.append((agentId, name))
                    # list_agents' summary has no agentArn field —
                    # constructed from Bedrock's documented Agent ARN
                    # format. See module docstring.
                    agentArn = f"arn:aws:bedrock:{self.region}:{self.accountId}:agent/{agentId}" if agentId else None
                    tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, agentArn) if agentArn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, a.get("updatedAt"))
                    rows.append(self.makeRow(name, "Agent", owner, lastUsed, {
                        "agent_id": agentId, "status": a.get("agentStatus"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_agents", e)
        return rows, agentIds

    def _scanAgentAliases(self, bedrockAgentClient, agentIds):
        # No account-wide "list all aliases" call — aliases are listed
        # per agent, so this loops over every agent found above.
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanAgentAliases.__name__)
        rows = []
        for agentId, agentName in agentIds:
            try:
                for page in bedrockAgentClient.get_paginator("list_agent_aliases").paginate(agentId=agentId):
                    for alias in page.get("agentAliasSummaries", []):
                        aliasName = alias.get("agentAliasName")
                        resourceName = f"{agentName}/{aliasName}" if agentName else aliasName
                        aliasId = alias.get("agentAliasId")
                        # Same situation as Agent above — no ARN in the
                        # summary, constructed from the documented
                        # AgentAlias ARN format (nested under agentId).
                        aliasArn = (f"arn:aws:bedrock:{self.region}:{self.accountId}:agent-alias/"
                                    f"{agentId}/{aliasId}") if aliasId else None
                        tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, aliasArn) if aliasArn else {}
                        owner, lastUsed = self.resolveOwnerAndLastUsed(resourceName, tags, alias.get("updatedAt"))
                        rows.append(self.makeRow(resourceName, "AgentAlias", owner, lastUsed, {
                            "agent_id": agentId,
                            "agent_alias_id": aliasId,
                            "status": alias.get("agentAliasStatus"),
                            "tags": tags,
                        }))
            except Exception as e:
                self.logScanError(f"list_agent_aliases:{agentId}", e)
        return rows

    def _scanKnowledgeBases(self, bedrockAgentClient):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanKnowledgeBases.__name__)
        rows = []
        try:
            for page in bedrockAgentClient.get_paginator("list_knowledge_bases").paginate():
                for kb in page.get("knowledgeBaseSummaries", []):
                    name = kb.get("name")
                    kbId = kb.get("knowledgeBaseId")
                    # Same situation again — no ARN in the summary,
                    # constructed from the documented KnowledgeBase ARN
                    # format.
                    kbArn = f"arn:aws:bedrock:{self.region}:{self.accountId}:knowledge-base/{kbId}" if kbId else None
                    tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, kbArn) if kbArn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, kb.get("updatedAt"))
                    rows.append(self.makeRow(name, "KnowledgeBase", owner, lastUsed, {
                        "knowledge_base_id": kbId, "status": kb.get("status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_knowledge_bases", e)
        return rows

    def _scanLoggingConfig(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanLoggingConfig.__name__)
        rows = []
        try:
            cfg = self.client.get_model_invocation_logging_configuration().get("loggingConfig")
            enabled = bool(cfg)
            rows.append(self.makeRow(
                f"{self.region}-model-invocation-logging",
                "ModelInvocationLoggingConfiguration",
                "N/A (account-level config)",
                "N/A (config object, not a usage record)",
                {
                    "invocation_logging_enabled": enabled,
                    "s3_destination": (cfg or {}).get("s3Config"),
                    "cloudwatch_destination": (cfg or {}).get("cloudWatchConfig"),
                },
            ))
        except Exception as e:
            self.logScanError("logging_config_resource", e)
        return rows

    # -- New resource types (2026-09-15b) ------------------------------

    def _scanGuardrails(self):
        """bedrock:ListGuardrails — content-filtering/safety policies.
        A GOVERNANCE resource: which accounts/regions actually have a
        Guardrail defined is itself the thing worth inventorying, same
        rationale as flagged in the coverage catalog."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanGuardrails.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_guardrails").paginate():
                for g in page.get("guardrails", []):
                    name = g.get("name")
                    arn = g.get("arn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, g.get("updatedAt", g.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "Guardrail", owner, lastUsed, {
                        "guardrail_id": g.get("id"),
                        "version": g.get("version"),
                        "status": g.get("status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_guardrails", e)
        return rows

    def _scanEvaluationJobs(self):
        """bedrock:ListEvaluationJobs — automated or human model-evaluation
        jobs (Model Evaluation)."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEvaluationJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_evaluation_jobs").paginate():
                for j in page.get("jobSummaries", []):
                    name = j.get("jobName")
                    arn = j.get("jobArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, j.get("jobEndTime", j.get("creationTime"))
                    )
                    rows.append(self.makeRow(name, "ModelEvaluationJob", owner, lastUsed, {
                        "status": j.get("status"),
                        "evaluation_task_types": j.get("evaluationTaskTypes"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_evaluation_jobs", e)
        return rows

    def _scanModelCustomizationJobs(self):
        """bedrock:ListModelCustomizationJobs — fine-tuning / continued
        pretraining / distillation jobs IN Bedrock."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanModelCustomizationJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_model_customization_jobs").paginate():
                for j in page.get("modelCustomizationJobSummaries", []):
                    name = j.get("jobName")
                    arn = j.get("jobArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, j.get("lastModifiedTime", j.get("creationTime"))
                    )
                    rows.append(self.makeRow(name, "ModelCustomizationJob", owner, lastUsed, {
                        "status": j.get("status"),
                        "customization_type": j.get("customizationType"),
                        "output_model_name": j.get("outputModelName"),
                        "output_model_arn": j.get("outputModelArn"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_model_customization_jobs", e)
        return rows

    def _scanModelImportJobs(self):
        """bedrock:ListModelImportJobs — jobs that import a model trained
        outside Bedrock. Distinct from _scanImportedModels() below, which
        is the resulting model resource, not the job that created it."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanModelImportJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_model_import_jobs").paginate():
                for j in page.get("modelImportJobSummaries", []):
                    name = j.get("jobName")
                    arn = j.get("jobArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, j.get("lastModifiedTime", j.get("creationTime"))
                    )
                    rows.append(self.makeRow(name, "ModelImportJob", owner, lastUsed, {
                        "status": j.get("status"),
                        "imported_model_name": j.get("importedModelName"),
                        "imported_model_arn": j.get("importedModelArn"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_model_import_jobs", e)
        return rows

    def _scanImportedModels(self):
        """bedrock:ListImportedModels — the model artifact resulting from
        a completed Model Import Job (a distinct, standing resource)."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanImportedModels.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_imported_models").paginate():
                for m in page.get("modelSummaries", []):
                    name = m.get("modelName")
                    arn = m.get("modelArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, tags, m.get("creationTime"))
                    rows.append(self.makeRow(name, "ImportedModel", owner, lastUsed, {
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_imported_models", e)
        return rows

    def _scanBatchInferenceJobs(self):
        """bedrock:ListModelInvocationJobs — large-scale offline/batch
        model inference. A second major invocation path beyond on-demand
        (CloudWatch-only) and Provisioned Throughput."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanBatchInferenceJobs.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_model_invocation_jobs").paginate():
                for j in page.get("invocationJobSummaries", []):
                    name = j.get("jobName")
                    arn = j.get("jobArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, j.get("lastModifiedTime", j.get("submitTime"))
                    )
                    rows.append(self.makeRow(name, "BatchInferenceJob", owner, lastUsed, {
                        "status": j.get("status"),
                        "model_id": j.get("modelId"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_model_invocation_jobs", e)
        return rows

    def _scanApplicationInferenceProfiles(self):
        """bedrock:ListInferenceProfiles — custom profiles for tracking
        cost/usage per app. Only APPLICATION-type profiles are kept —
        SYSTEM_DEFINED ones are AWS's built-in per-model profiles,
        identical across every account, same reason Foundation Models
        themselves are excluded from _scanCustomModels()."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanApplicationInferenceProfiles.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_inference_profiles").paginate():
                for p in page.get("inferenceProfileSummaries", []):
                    if p.get("type") != "APPLICATION":
                        continue
                    name = p.get("inferenceProfileName")
                    arn = p.get("inferenceProfileArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, p.get("updatedAt", p.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "ApplicationInferenceProfile", owner, lastUsed, {
                        "inference_profile_id": p.get("inferenceProfileId"),
                        "status": p.get("status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_inference_profiles", e)
        return rows

    def _scanMarketplaceModelEndpoints(self):
        """bedrock:ListMarketplaceModelEndpoints — third-party models
        deployed via Bedrock Marketplace. A distinct data-handling/
        compliance risk vs. first-party Bedrock models."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanMarketplaceModelEndpoints.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_marketplace_model_endpoints").paginate():
                for ep in page.get("marketplaceModelEndpoints", []):
                    arn = ep.get("endpointArn")
                    name = arn.split("/")[-1] if arn else "unknown-marketplace-endpoint"
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, ep.get("updatedAt", ep.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "MarketplaceModelEndpoint", owner, lastUsed, {
                        "endpoint_arn": arn,
                        "model_source_identifier": ep.get("modelSourceIdentifier"),
                        "status": ep.get("status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_marketplace_model_endpoints", e)
        return rows

    def _scanAutomatedReasoningPolicies(self):
        """bedrock:ListAutomatedReasoningPolicies — formal-verification
        guardrail policies. Newer capability; field names here are the
        least certain in this file — see module docstring's
        VERIFY-BEFORE-DEPLOY note."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanAutomatedReasoningPolicies.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_automated_reasoning_policies").paginate():
                for p in page.get("automatedReasoningPolicySummaries", []):
                    name = p.get("name")
                    arn = p.get("policyArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, p.get("updatedAt", p.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "AutomatedReasoningPolicy", owner, lastUsed, {
                        "policy_id": p.get("policyId"),
                        "version": p.get("version"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_automated_reasoning_policies", e)
        return rows

    def _scanPromptRouters(self):
        """bedrock:ListPromptRouters — routes requests across multiple
        models by criteria. Only routers this account created are kept
        — AWS's built-in default routers are filtered out the same way
        SYSTEM_DEFINED inference profiles are, since those aren't
        something this account owns or configured."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanPromptRouters.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_prompt_routers").paginate():
                for r in page.get("promptRouterSummaries", []):
                    if str(r.get("type", "")).upper() == "DEFAULT":
                        continue
                    name = r.get("promptRouterName")
                    arn = r.get("promptRouterArn")
                    tags = tagHelper.getBedrockTags(self.client, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, r.get("updatedAt", r.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "PromptRouter", owner, lastUsed, {
                        "status": r.get("status"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_prompt_routers", e)
        return rows

    def _scanPrompts(self, bedrockAgentClient):
        """bedrock-agent:ListPrompts — saved/versioned prompt templates
        (Prompt Management). Unlike Agents/KnowledgeBases, list_prompts
        returns its own `arn` field directly — no ARN construction
        needed."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanPrompts.__name__)
        rows = []
        try:
            for page in bedrockAgentClient.get_paginator("list_prompts").paginate():
                for p in page.get("promptSummaries", []):
                    name = p.get("name")
                    arn = p.get("arn")
                    tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, p.get("updatedAt", p.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "Prompt", owner, lastUsed, {
                        "prompt_id": p.get("id"),
                        "version": p.get("version"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_prompts", e)
        return rows

    def _scanFlows(self, bedrockAgentClient):
        """bedrock-agent:ListFlows — visual multi-step AI workflows
        (Bedrock Flows), which chain models/KBs/Lambdas together.
        Returns (rows, flowIds) so aliases/versions can be scanned per
        flow below, same pattern as _scanAgents()/_scanAgentAliases()."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanFlows.__name__)
        rows, flowIds = [], []
        try:
            for page in bedrockAgentClient.get_paginator("list_flows").paginate():
                for f in page.get("flowSummaries", []):
                    name = f.get("name")
                    flowId = f.get("id")
                    if flowId:
                        flowIds.append((flowId, name))
                    arn = f.get("arn")
                    tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, arn) if arn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, f.get("updatedAt", f.get("createdAt"))
                    )
                    rows.append(self.makeRow(name, "Flow", owner, lastUsed, {
                        "flow_id": flowId,
                        "status": f.get("status"),
                        "version": f.get("version"),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_flows", e)
        return rows, flowIds

    def _scanFlowAliases(self, bedrockAgentClient, flowIds):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanFlowAliases.__name__)
        rows = []
        for flowId, flowName in flowIds:
            try:
                for page in bedrockAgentClient.get_paginator("list_flow_aliases").paginate(flowIdentifier=flowId):
                    for alias in page.get("flowAliasSummaries", []):
                        aliasName = alias.get("name")
                        resourceName = f"{flowName}/{aliasName}" if flowName else aliasName
                        arn = alias.get("arn")
                        tags = tagHelper.getBedrockAgentTags(bedrockAgentClient, arn) if arn else {}
                        owner, lastUsed = self.resolveOwnerAndLastUsed(
                            resourceName, tags, alias.get("updatedAt", alias.get("createdAt"))
                        )
                        rows.append(self.makeRow(resourceName, "FlowAlias", owner, lastUsed, {
                            "flow_id": flowId,
                            "flow_alias_id": alias.get("id"),
                            "tags": tags,
                        }))
            except Exception as e:
                self.logScanError(f"list_flow_aliases:{flowId}", e)
        return rows

    def _scanFlowVersions(self, bedrockAgentClient, flowIds):
        """FlowVersions are immutable snapshots of a Flow — no tagging
        API of their own (they inherit the parent Flow's tags), so no
        tag lookup here, only ownership/last-used via CloudTrail/fallback
        timestamp like every other resource."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanFlowVersions.__name__)
        rows = []
        for flowId, flowName in flowIds:
            try:
                for page in bedrockAgentClient.get_paginator("list_flow_versions").paginate(flowIdentifier=flowId):
                    for v in page.get("flowVersionSummaries", []):
                        version = v.get("version")
                        resourceName = f"{flowName}/v{version}" if flowName else f"{flowId}/v{version}"
                        owner, lastUsed = self.resolveOwnerAndLastUsed(resourceName, {}, v.get("createdAt"))
                        rows.append(self.makeRow(resourceName, "FlowVersion", owner, lastUsed, {
                            "flow_id": flowId,
                            "status": v.get("status"),
                        }))
            except Exception as e:
                self.logScanError(f"list_flow_versions:{flowId}", e)
        return rows

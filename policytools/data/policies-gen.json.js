app.PolicyEditorConfig = {
    "conditionOperators": ["ArnEquals", "ArnEqualsIfExists", "ArnLike", "ArnLikeIfExists", "ArnNotEquals", "ArnNotEqualsIfExists", "ArnNotLike", "ArnNotLikeIfExists", "BinaryEquals", "BinaryEqualsIfExists", "BinaryNotEquals", "BinaryNotEqualsIfExists", "Bool", "BoolIfExists", "DateEquals", "DateEqualsIfExists", "DateGreaterThan", "DateGreaterThanEquals", "DateGreaterThanEqualsIfExists", "DateGreaterThanIfExists", "DateLessThan", "DateLessThanEquals", "DateLessThanEqualsIfExists", "DateLessThanIfExists", "DateNotEquals", "DateNotEqualsIfExists", "IpAddress", "IpAddressIfExists", "NotIpAddress", "NotIpAddressIfExists", "Null", "NumericEquals", "NumericEqualsIfExists", "NumericGreaterThan", "NumericGreaterThanEquals", "NumericGreaterThanEqualsIfExists", "NumericGreaterThanIfExists", "NumericLessThan", "NumericLessThanEquals", "NumericLessThanEqualsIfExists", "NumericLessThanIfExists", "NumericNotEquals", "NumericNotEqualsIfExists", "StringEquals", "StringEqualsIfExists", "StringEqualsIgnoreCase", "StringEqualsIgnoreCaseIfExists", "StringLike", "StringLikeIfExists", "StringNotEquals", "StringNotEqualsIfExists", "StringNotEqualsIgnoreCase", "StringNotEqualsIgnoreCaseIfExists", "StringNotLike", "StringNotLikeIfExists"],
    "conditionKeys": ["aws:CurrentTime", "aws:EpochTime", "aws:MultiFactorAuthAge", "aws:MultiFactorAuthPresent", "aws:PrincipalArn", "aws:PrincipalOrgID", "aws:PrincipalTag/${TagKey}", "aws:PrincipalType", "aws:Referer", "aws:RequestTag/${TagKey}", "aws:RequestedRegion", "aws:SecureTransport", "aws:SourceAccount", "aws:SourceArn", "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce", "aws:TagKeys", "aws:TokenIssueTime", "aws:UserAgent", "aws:userid", "aws:username"],
    "serviceMap": {
        "Amazon Comprehend": {
            "StringPrefix": "comprehend",
            "Actions": ["BatchDetectDominantLanguage", "BatchDetectEntities", "BatchDetectKeyPhrases", "BatchDetectSentiment", "BatchDetectSyntax", "ClassifyDocument", "CreateDocumentClassifier", "CreateEndpoint", "CreateEntityRecognizer", "DeleteDocumentClassifier", "DeleteEndpoint", "DeleteEntityRecognizer", "DescribeDocumentClassificationJob", "DescribeDocumentClassifier", "DescribeDominantLanguageDetectionJob", "DescribeEndpoint", "DescribeEntitiesDetectionJob", "DescribeEntityRecognizer", "DescribeKeyPhrasesDetectionJob", "DescribeSentimentDetectionJob", "DescribeTopicsDetectionJob", "DetectDominantLanguage", "DetectEntities", "DetectKeyPhrases", "DetectSentiment", "DetectSyntax", "ListDocumentClassificationJobs", "ListDocumentClassifiers", "ListDominantLanguageDetectionJobs", "ListEndpoints", "ListEntitiesDetectionJobs", "ListEntityRecognizers", "ListKeyPhrasesDetectionJobs", "ListSentimentDetectionJobs", "ListTagsForResource", "ListTopicsDetectionJobs", "StartDocumentClassificationJob", "StartDominantLanguageDetectionJob", "StartEntitiesDetectionJob", "StartKeyPhrasesDetectionJob", "StartSentimentDetectionJob", "StartTopicsDetectionJob", "StopDominantLanguageDetectionJob", "StopEntitiesDetectionJob", "StopKeyPhrasesDetectionJob", "StopSentimentDetectionJob", "StopTrainingDocumentClassifier", "StopTrainingEntityRecognizer", "TagResource", "UntagResource", "UpdateEndpoint"],
            "ARNFormat": "arn:${Partition}:comprehend:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:comprehend:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Elastic File System": {
            "StringPrefix": "elasticfilesystem",
            "Actions": ["Backup", "ClientMount", "ClientRootAccess", "ClientWrite", "CreateAccessPoint", "CreateFileSystem", "CreateMountTarget", "CreateTags", "DeleteAccessPoint", "DeleteFileSystem", "DeleteFileSystemPolicy", "DeleteMountTarget", "DeleteTags", "DescribeAccessPoints", "DescribeFileSystemPolicy", "DescribeFileSystems", "DescribeLifecycleConfiguration", "DescribeMountTargetSecurityGroups", "DescribeMountTargets", "DescribeTags", "ListTagsForResource", "ModifyMountTargetSecurityGroups", "PutFileSystemPolicy", "PutLifecycleConfiguration", "Restore", "TagResource", "UntagResource", "UpdateFileSystem"],
            "ARNFormat": "arn:${Partition}:elasticfilesystem:${Region}:${Account}:${ResourceType}/${ResourcePath}",
            "ARNRegex": "^arn:${Partition}:elasticfilesystem:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "elasticfilesystem:AccessPointArn"],
            "HasResource": true
        },
        "AWS Glue": {
            "StringPrefix": "glue",
            "Actions": ["BatchCreatePartition", "BatchDeleteConnection", "BatchDeletePartition", "BatchDeleteTable", "BatchDeleteTableVersion", "BatchGetCrawlers", "BatchGetDevEndpoints", "BatchGetJobs", "BatchGetPartition", "BatchGetTriggers", "BatchGetWorkflows", "BatchStopJobRun", "CancelMLTaskRun", "CreateClassifier", "CreateConnection", "CreateCrawler", "CreateDatabase", "CreateDevEndpoint", "CreateJob", "CreateMLTransform", "CreatePartition", "CreateScript", "CreateSecurityConfiguration", "CreateTable", "CreateTrigger", "CreateUserDefinedFunction", "CreateWorkflow", "DeleteClassifier", "DeleteConnection", "DeleteCrawler", "DeleteDatabase", "DeleteDevEndpoint", "DeleteJob", "DeleteMLTransform", "DeletePartition", "DeleteResourcePolicy", "DeleteSecurityConfiguration", "DeleteTable", "DeleteTableVersion", "DeleteTrigger", "DeleteUserDefinedFunction", "DeleteWorkflow", "GetCatalogImportStatus", "GetClassifier", "GetClassifiers", "GetConnection", "GetConnections", "GetCrawler", "GetCrawlerMetrics", "GetCrawlers", "GetDataCatalogEncryptionSettings", "GetDatabase", "GetDatabases", "GetDataflowGraph", "GetDevEndpoint", "GetDevEndpoints", "GetJob", "GetJobBookmark", "GetJobRun", "GetJobRuns", "GetJobs", "GetMLTaskRun", "GetMLTaskRuns", "GetMLTransform", "GetMLTransforms", "GetMapping", "GetPartition", "GetPartitions", "GetPlan", "GetResourcePolicy", "GetSecurityConfiguration", "GetSecurityConfigurations", "GetTable", "GetTableVersion", "GetTableVersions", "GetTables", "GetTags", "GetTrigger", "GetTriggers", "GetUserDefinedFunction", "GetUserDefinedFunctions", "GetWorkflow", "GetWorkflowRun", "GetWorkflowRunProperties", "GetWorkflowRuns", "ImportCatalogToGlue", "ListCrawlers", "ListDevEndpoints", "ListJobs", "ListMLTransforms", "ListTriggers", "ListWorkflows", "PutDataCatalogEncryptionSettings", "PutResourcePolicy", "PutWorkflowRunProperties", "ResetJobBookmark", "SearchTables", "StartCrawler", "StartCrawlerSchedule", "StartExportLabelsTaskRun", "StartImportLabelsTaskRun", "StartJobRun", "StartMLEvaluationTaskRun", "StartMLLabelingSetGenerationTaskRun", "StartTrigger", "StartWorkflowRun", "StopCrawler", "StopCrawlerSchedule", "StopTrigger", "TagResource", "UntagResource", "UpdateClassifier", "UpdateConnection", "UpdateCrawler", "UpdateCrawlerSchedule", "UpdateDatabase", "UpdateDevEndpoint", "UpdateJob", "UpdateMLTransform", "UpdatePartition", "UpdateTable", "UpdateTrigger", "UpdateUserDefinedFunction", "UpdateWorkflow", "UseMLTransforms"],
            "ARNFormat": "arn:aws:glue:<region>:<accountID>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:glue:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS IoT Things Graph": {
            "StringPrefix": "iotthingsgraph",
            "Actions": ["AssociateEntityToThing", "CreateFlowTemplate", "CreateSystemInstance", "CreateSystemTemplate", "DeleteFlowTemplate", "DeleteNamespace", "DeleteSystemInstance", "DeleteSystemTemplate", "DeploySystemInstance", "DeprecateFlowTemplate", "DeprecateSystemTemplate", "DescribeNamespace", "DissociateEntityFromThing", "GetEntities", "GetFlowTemplate", "GetFlowTemplateRevisions", "GetNamespaceDeletionStatus", "GetSystemInstance", "GetSystemTemplate", "GetSystemTemplateRevisions", "GetUploadStatus", "ListFlowExecutionMessages", "ListTagsForResource", "SearchEntities", "SearchFlowExecutions", "SearchFlowTemplates", "SearchSystemInstances", "SearchSystemTemplates", "SearchThings", "TagResource", "UndeploySystemInstance", "UntagResource", "UpdateFlowTemplate", "UpdateSystemTemplate", "UploadEntityDefinitions"],
            "ARNFormat": "arn:aws:iotthingsgraph:<region>:<account_id>:<type>/<name>",
            "ARNRegex": "^arn:aws:iotthingsgraph:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Savings Plans": {
            "StringPrefix": "savingsplans",
            "Actions": ["CreateSavingsPlan", "DescribeSavingsPlanRates", "DescribeSavingsPlans", "DescribeSavingsPlansOfferingRates", "DescribeSavingsPlansOfferings", "ListTagsForResource", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:savingsplans::${Account}:${ResourceType}/${ResourcePath}",
            "ARNRegex": "^arn:aws:savingsplans:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Systems Manager": {
            "StringPrefix": "ssm",
            "Actions": ["AddTagsToResource", "CancelCommand", "CancelMaintenanceWindowExecution", "CreateActivation", "CreateAssociation", "CreateAssociationBatch", "CreateDocument", "CreateMaintenanceWindow", "CreateOpsItem", "CreatePatchBaseline", "CreateResourceDataSync", "DeleteActivation", "DeleteAssociation", "DeleteDocument", "DeleteInventory", "DeleteMaintenanceWindow", "DeleteParameter", "DeleteParameters", "DeletePatchBaseline", "DeleteResourceDataSync", "DeregisterManagedInstance", "DeregisterPatchBaselineForPatchGroup", "DeregisterTargetFromMaintenanceWindow", "DeregisterTaskFromMaintenanceWindow", "DescribeActivations", "DescribeAssociation", "DescribeAssociationExecutionTargets", "DescribeAssociationExecutions", "DescribeAutomationExecutions", "DescribeAutomationStepExecutions", "DescribeAvailablePatches", "DescribeDocument", "DescribeDocumentParameters", "DescribeDocumentPermission", "DescribeEffectiveInstanceAssociations", "DescribeEffectivePatchesForPatchBaseline", "DescribeInstanceAssociationsStatus", "DescribeInstanceInformation", "DescribeInstancePatchStates", "DescribeInstancePatchStatesForPatchGroup", "DescribeInstancePatches", "DescribeInstanceProperties", "DescribeInventoryDeletions", "DescribeMaintenanceWindowExecutionTaskInvocations", "DescribeMaintenanceWindowExecutionTasks", "DescribeMaintenanceWindowExecutions", "DescribeMaintenanceWindowSchedule", "DescribeMaintenanceWindowTargets", "DescribeMaintenanceWindowTasks", "DescribeMaintenanceWindows", "DescribeMaintenanceWindowsForTarget", "DescribeOpsItems", "DescribeParameters", "DescribePatchBaselines", "DescribePatchGroupState", "DescribePatchGroups", "DescribePatchProperties", "DescribeSessions", "GetAutomationExecution", "GetCommandInvocation", "GetConnectionStatus", "GetDefaultPatchBaseline", "GetDeployablePatchSnapshotForInstance", "GetDocument", "GetInventory", "GetInventorySchema", "GetMaintenanceWindow", "GetMaintenanceWindowExecution", "GetMaintenanceWindowExecutionTask", "GetMaintenanceWindowExecutionTaskInvocation", "GetMaintenanceWindowTask", "GetManifest", "GetOpsItem", "GetOpsSummary", "GetParameter", "GetParameterHistory", "GetParameters", "GetParametersByPath", "GetPatchBaseline", "GetPatchBaselineForPatchGroup", "GetServiceSetting", "LabelParameterVersion", "ListAssociationVersions", "ListAssociations", "ListCommandInvocations", "ListCommands", "ListComplianceItems", "ListComplianceSummaries", "ListDocumentVersions", "ListDocuments", "ListInstanceAssociations", "ListInventoryEntries", "ListResourceComplianceSummaries", "ListResourceDataSync", "ListTagsForResource", "ModifyDocumentPermission", "PutComplianceItems", "PutConfigurePackageResult", "PutInventory", "PutParameter", "RegisterDefaultPatchBaseline", "RegisterPatchBaselineForPatchGroup", "RegisterTargetWithMaintenanceWindow", "RegisterTaskWithMaintenanceWindow", "RemoveTagsFromResource", "ResetServiceSetting", "ResumeSession", "SendAutomationSignal", "SendCommand", "StartAssociationsOnce", "StartAutomationExecution", "StartSession", "StopAutomationExecution", "TerminateSession", "UpdateAssociation", "UpdateAssociationStatus", "UpdateDocument", "UpdateDocumentDefaultVersion", "UpdateInstanceAssociationStatus", "UpdateInstanceInformation", "UpdateMaintenanceWindow", "UpdateMaintenanceWindowTarget", "UpdateMaintenanceWindowTask", "UpdateManagedInstanceRole", "UpdateOpsItem", "UpdatePatchBaseline", "UpdateResourceDataSync", "UpdateServiceSetting"],
            "ARNFormat": "arn:aws:ssm:<region>:<account_ID>:<relative-id>",
            "ARNRegex": "^arn:aws:(ssm|ec2):.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "ssm:Overwrite", "ssm:Recursive", "ssm:SessionDocumentAccessCheck", "ssm:SyncType", "ssm:resourceTag/tag-key"],
            "HasResource": true
        },
        "AWS SSO": {
            "StringPrefix": "sso",
            "Actions": ["AssociateDirectory", "AssociateProfile", "CreateApplicationInstance", "CreateApplicationInstanceCertificate", "CreateManagedApplicationInstance", "CreatePermissionSet", "CreateProfile", "CreateTrust", "DeleteApplicationInstance", "DeleteApplicationInstanceCertificate", "DeleteManagedApplicationInstance", "DeletePermissionSet", "DeletePermissionsPolicy", "DeleteProfile", "DescribePermissionsPolicies", "DescribeRegisteredRegions", "DisassociateDirectory", "DisassociateProfile", "GetApplicationInstance", "GetApplicationTemplate", "GetManagedApplicationInstance", "GetMfaDeviceManagementForDirectory", "GetPermissionSet", "GetPermissionsPolicy", "GetProfile", "GetSSOStatus", "GetSharedSsoConfiguration", "GetSsoConfiguration", "GetTrust", "ImportApplicationInstanceServiceProviderMetadata", "ListApplicationInstanceCertificates", "ListApplicationInstances", "ListApplicationTemplates", "ListApplications", "ListDirectoryAssociations", "ListPermissionSets", "ListProfileAssociations", "ListProfiles", "PutMfaDeviceManagementForDirectory", "PutPermissionsPolicy", "StartSSO", "UpdateApplicationInstanceActiveCertificate", "UpdateApplicationInstanceDisplayData", "UpdateApplicationInstanceResponseConfiguration", "UpdateApplicationInstanceResponseSchemaConfiguration", "UpdateApplicationInstanceSecurityConfiguration", "UpdateApplicationInstanceServiceProviderConfiguration", "UpdateApplicationInstanceStatus", "UpdateDirectoryAssociation", "UpdateManagedApplicationInstanceStatus", "UpdatePermissionSet", "UpdateProfile", "UpdateSSOConfiguration", "UpdateTrust"],
            "ARNFormat": "arn:${Partition}:sso:${Region}:${Account}:<relative-id>",
            "ARNRegex": "^arn:${Partition}:sso:${Region}:.+",
            "HasResource": false
        },
        "AWS IoT": {
            "StringPrefix": "iot",
            "Actions": ["AcceptCertificateTransfer", "AddThingToBillingGroup", "AddThingToThingGroup", "AssociateTargetsWithJob", "AttachPolicy", "AttachPrincipalPolicy", "AttachSecurityProfile", "AttachThingPrincipal", "CancelAuditTask", "CancelCertificateTransfer", "CancelJob", "CancelJobExecution", "ClearDefaultAuthorizer", "CloseTunnel", "Connect", "CreateAuthorizer", "CreateBillingGroup", "CreateCertificateFromCsr", "CreateDynamicThingGroup", "CreateJob", "CreateKeysAndCertificate", "CreateOTAUpdate", "CreatePolicy", "CreatePolicyVersion", "CreateProvisioningClaim", "CreateProvisioningTemplate", "CreateProvisioningTemplateVersion", "CreateRoleAlias", "CreateScheduledAudit", "CreateSecurityProfile", "CreateStream", "CreateThing", "CreateThingGroup", "CreateThingType", "CreateTopicRule", "DeleteAccountAuditConfiguration", "DeleteAuthorizer", "DeleteBillingGroup", "DeleteCACertificate", "DeleteCertificate", "DeleteDynamicThingGroup", "DeleteJob", "DeleteJobExecution", "DeleteOTAUpdate", "DeletePolicy", "DeletePolicyVersion", "DeleteProvisioningTemplate", "DeleteProvisioningTemplateVersion", "DeleteRegistrationCode", "DeleteRoleAlias", "DeleteScheduledAudit", "DeleteSecurityProfile", "DeleteStream", "DeleteThing", "DeleteThingGroup", "DeleteThingShadow", "DeleteThingType", "DeleteTopicRule", "DeleteV2LoggingLevel", "DeprecateThingType", "DescribeAccountAuditConfiguration", "DescribeAuditTask", "DescribeAuthorizer", "DescribeBillingGroup", "DescribeCACertificate", "DescribeCertificate", "DescribeDefaultAuthorizer", "DescribeEndpoint", "DescribeEventConfigurations", "DescribeIndex", "DescribeJob", "DescribeJobExecution", "DescribeProvisioningTemplate", "DescribeProvisioningTemplateVersion", "DescribeRoleAlias", "DescribeScheduledAudit", "DescribeSecurityProfile", "DescribeStream", "DescribeThing", "DescribeThingGroup", "DescribeThingRegistrationTask", "DescribeThingType", "DescribeTunnel", "DetachPolicy", "DetachPrincipalPolicy", "DetachSecurityProfile", "DetachThingPrincipal", "DisableTopicRule", "EnableTopicRule", "GetCardinality", "GetEffectivePolicies", "GetIndexingConfiguration", "GetJobDocument", "GetLoggingOptions", "GetOTAUpdate", "GetPendingJobExecutions", "GetPercentiles", "GetPolicy", "GetPolicyVersion", "GetRegistrationCode", "GetStatistics", "GetThingShadow", "GetTopicRule", "GetV2LoggingOptions", "ListActiveViolations", "ListAttachedPolicies", "ListAuditFindings", "ListAuditTasks", "ListAuthorizers", "ListBillingGroups", "ListCACertificates", "ListCertificates", "ListCertificatesByCA", "ListIndices", "ListJobExecutionsForJob", "ListJobExecutionsForThing", "ListJobs", "ListOTAUpdates", "ListOutgoingCertificates", "ListPolicies", "ListPolicyPrincipals", "ListPolicyVersions", "ListPrincipalPolicies", "ListPrincipalThings", "ListProvisioningTemplateVersions", "ListProvisioningTemplates", "ListRoleAliases", "ListScheduledAudits", "ListSecurityProfiles", "ListSecurityProfilesForTarget", "ListStreams", "ListTagsForResource", "ListTargetsForPolicy", "ListTargetsForSecurityProfile", "ListThingGroups", "ListThingGroupsForThing", "ListThingPrincipals", "ListThingRegistrationTaskReports", "ListThingRegistrationTasks", "ListThingTypes", "ListThings", "ListThingsInBillingGroup", "ListThingsInThingGroup", "ListTopicRules", "ListTunnels", "ListV2LoggingLevels", "ListViolationEvents", "OpenTunnel", "Publish", "Receive", "RegisterCACertificate", "RegisterCertificate", "RegisterCertificateWithoutCA", "RegisterThing", "RejectCertificateTransfer", "RemoveThingFromBillingGroup", "RemoveThingFromThingGroup", "ReplaceTopicRule", "SearchIndex", "SetDefaultAuthorizer", "SetDefaultPolicyVersion", "SetLoggingOptions", "SetV2LoggingLevel", "SetV2LoggingOptions", "StartNextPendingJobExecution", "StartOnDemandAuditTask", "StartThingRegistrationTask", "StopThingRegistrationTask", "Subscribe", "TagResource", "TestAuthorization", "TestInvokeAuthorizer", "TransferCertificate", "UntagResource", "UpdateAccountAuditConfiguration", "UpdateAuthorizer", "UpdateBillingGroup", "UpdateCACertificate", "UpdateCertificate", "UpdateDynamicThingGroup", "UpdateEventConfigurations", "UpdateIndexingConfiguration", "UpdateJob", "UpdateJobExecution", "UpdateProvisioningTemplate", "UpdateRoleAlias", "UpdateScheduledAudit", "UpdateSecurityProfile", "UpdateStream", "UpdateThing", "UpdateThingGroup", "UpdateThingGroupsForThing", "UpdateThingShadow", "ValidateSecurityProfileBehaviors"],
            "ARNFormat": "arn:aws:iot:<region>:<account_ID>:<type>/<name>",
            "ARNRegex": "^arn:aws:iot:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "iot:Delete", "iot:ThingGroupArn", "iot:TunnelDestinationService"],
            "HasResource": true
        },
        "AWS Migration Hub": {
            "StringPrefix": "mgh",
            "Actions": ["AssociateCreatedArtifact", "AssociateDiscoveredResource", "CreateHomeRegionControl", "CreateProgressUpdateStream", "DeleteProgressUpdateStream", "DescribeApplicationState", "DescribeHomeRegionControls", "DescribeMigrationTask", "DisassociateCreatedArtifact", "DisassociateDiscoveredResource", "GetHomeRegion", "ImportMigrationTask", "ListCreatedArtifacts", "ListDiscoveredResources", "ListMigrationTasks", "ListProgressUpdateStreams", "NotifyApplicationState", "NotifyMigrationTaskState", "PutResourceAttributes"],
            "ARNFormat": "arn:aws:mgh:<region>:<namespace>:<relative-id>",
            "ARNRegex": "^arn:aws:mgh:[a-z0-9-]+:[0-9]{12}:.+",
            "HasResource": true
        },
        "AWS Lambda": {
            "StringPrefix": "lambda",
            "Actions": ["AddLayerVersionPermission", "AddPermission", "CreateAlias", "CreateEventSourceMapping", "CreateFunction", "DeleteAlias", "DeleteEventSourceMapping", "DeleteFunction", "DeleteFunctionConcurrency", "DeleteFunctionEventInvokeConfig", "DeleteLayerVersion", "DeleteProvisionedConcurrencyConfig", "DisableReplication", "EnableReplication", "GetAccountSettings", "GetAlias", "GetEventSourceMapping", "GetFunction", "GetFunctionConcurrency", "GetFunctionConfiguration", "GetFunctionEventInvokeConfig", "GetLayerVersion", "GetLayerVersionByArn", "GetLayerVersionPolicy", "GetPolicy", "GetProvisionedConcurrencyConfig", "InvokeAsync", "InvokeFunction", "ListAliases", "ListEventSourceMappings", "ListFunctionEventInvokeConfigs", "ListFunctions", "ListLayerVersions", "ListLayers", "ListProvisionedConcurrencyConfigs", "ListTags", "ListVersionsByFunction", "PublishLayerVersion", "PublishVersion", "PutFunctionConcurrency", "PutFunctionEventInvokeConfig", "PutProvisionedConcurrencyConfig", "RemoveLayerVersionPermission", "RemovePermission", "TagResource", "UntagResource", "UpdateAlias", "UpdateEventSourceMapping", "UpdateFunctionCode", "UpdateFunctionConfiguration", "UpdateFunctionEventInvokeConfig"],
            "ARNFormat": "arn:aws:lambda:<region>:<account>:<resourceType>:<resourceId>",
            "ARNRegex": "^arn:aws:lambda:.+",
            "conditionKeys": ["lambda:FunctionArn", "lambda:Layer", "lambda:Principal"],
            "HasResource": true
        },
        "AWS Data Exchange": {
            "StringPrefix": "dataexchange",
            "Actions": ["CancelJob", "CreateAsset", "CreateDataSet", "CreateJob", "CreateRevision", "DeleteAsset", "DeleteDataSet", "DeleteRevision", "GetAsset", "GetDataSet", "GetJob", "GetRevision", "ListDataSetRevisions", "ListDataSets", "ListJobs", "ListRevisionAssets", "ListTagsForResource", "StartJob", "TagResource", "UntagResource", "UpdateAsset", "UpdateDataSet", "UpdateRevision"],
            "ARNFormat": "arn:aws:dataexchange:<region>:<account-id>:<resource-type>/<resource_id>",
            "ARNRegex": "^arn:aws:dataexchange:.+:.*:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "dataexchange:JobType"],
            "HasResource": true
        },
        "Amazon Machine Learning": {
            "StringPrefix": "machinelearning",
            "Actions": ["AddTags", "CreateBatchPrediction", "CreateDataSourceFromRDS", "CreateDataSourceFromRedshift", "CreateDataSourceFromS3", "CreateEvaluation", "CreateMLModel", "CreateRealtimeEndpoint", "DeleteBatchPrediction", "DeleteDataSource", "DeleteEvaluation", "DeleteMLModel", "DeleteRealtimeEndpoint", "DeleteTags", "DescribeBatchPredictions", "DescribeDataSources", "DescribeEvaluations", "DescribeMLModels", "DescribeTags", "GetBatchPrediction", "GetDataSource", "GetEvaluation", "GetMLModel", "Predict", "UpdateBatchPrediction", "UpdateDataSource", "UpdateEvaluation", "UpdateMLModel"],
            "ARNFormat": "arn:aws:machinelearning:<region>:<account_ID>:<resource_type>/<relative_ID>",
            "ARNRegex": "^arn:aws:machinelearning:.+",
            "HasResource": true
        },
        "Amazon GuardDuty": {
            "StringPrefix": "guardduty",
            "Actions": ["AcceptInvitation", "ArchiveFindings", "CreateDetector", "CreateFilter", "CreateIPSet", "CreateMembers", "CreatePublishingDestination", "CreateSampleFindings", "CreateThreatIntelSet", "DeclineInvitations", "DeleteDetector", "DeleteFilter", "DeleteIPSet", "DeleteInvitations", "DeleteMembers", "DeletePublishingDestination", "DeleteThreatIntelSet", "DescribePublishingDestination", "DisassociateFromMasterAccount", "DisassociateMembers", "GetDetector", "GetFilter", "GetFindings", "GetFindingsStatistics", "GetIPSet", "GetInvitationsCount", "GetMasterAccount", "GetMembers", "GetThreatIntelSet", "InviteMembers", "ListDetectors", "ListFilters", "ListFindings", "ListInvitations", "ListMembers", "ListPublishingDestinations", "ListTagsForResource", "ListThreatIntelSets", "StartMonitoringMembers", "StopMonitoringMembers", "TagResource", "UnarchiveFindings", "UntagResource", "UpdateDetector", "UpdateFilter", "UpdateFindingsFeedback", "UpdateIPSet", "UpdatePublishingDestination", "UpdateThreatIntelSet"],
            "ARNFormat": "arn:aws:guardduty:<region>:<account_ID>:.+",
            "ARNRegex": "^arn:aws:guardduty:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon EventBridge": {
            "StringPrefix": "events",
            "Actions": ["ActivateEventSource", "CreateEventBus", "CreatePartnerEventSource", "DeactivateEventSource", "DeleteEventBus", "DeletePartnerEventSource", "DeleteRule", "DescribeEventBus", "DescribeEventSource", "DescribePartnerEventSource", "DescribeRule", "DisableRule", "EnableRule", "ListEventBuses", "ListEventSources", "ListPartnerEventSourceAccounts", "ListPartnerEventSources", "ListRuleNamesByTarget", "ListRules", "ListTagsForResource", "ListTargetsByRule", "PutEvents", "PutPartnerEvents", "PutPermission", "PutRule", "PutTargets", "RemovePermission", "RemoveTargets", "TagResource", "TestEventPattern", "UntagResource"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:events:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "events:TargetArn", "events:detail-type", "events:detail.eventTypeCode", "events:detail.service", "events:detail.userIdentity.principalId", "events:source"],
            "HasResource": true
        },
        "Amazon Lex": {
            "StringPrefix": "lex",
            "Actions": ["CreateBotVersion", "CreateIntentVersion", "CreateSlotTypeVersion", "DeleteBot", "DeleteBotAlias", "DeleteBotChannelAssociation", "DeleteBotVersion", "DeleteIntent", "DeleteIntentVersion", "DeleteSession", "DeleteSlotType", "DeleteSlotTypeVersion", "DeleteUtterances", "GetBot", "GetBotAlias", "GetBotAliases", "GetBotChannelAssociation", "GetBotChannelAssociations", "GetBotVersions", "GetBots", "GetBuiltinIntent", "GetBuiltinIntents", "GetBuiltinSlotTypes", "GetExport", "GetImport", "GetIntent", "GetIntentVersions", "GetIntents", "GetSession", "GetSlotType", "GetSlotTypeVersions", "GetSlotTypes", "GetUtterancesView", "ListTagsForResource", "PostContent", "PostText", "PutBot", "PutBotAlias", "PutIntent", "PutSession", "PutSlotType", "StartImport", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:lex:<region>:<account_ID>:<type>:<name>",
            "ARNRegex": "^arn:aws:lex:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "lex:associatedIntents", "lex:associatedSlotTypes", "lex:channelType"],
            "HasResource": true
        },
        "AWS Resource Access Manager": {
            "StringPrefix": "ram",
            "Actions": ["AcceptResourceShareInvitation", "AssociateResourceShare", "AssociateResourceSharePermission", "CreateResourceShare", "DeleteResourceShare", "DisassociateResourceShare", "DisassociateResourceSharePermission", "EnableSharingWithAwsOrganization", "GetPermission", "GetResourcePolicies", "GetResourceShareAssociations", "GetResourceShareInvitations", "GetResourceShares", "ListPendingInvitationResources", "ListPermissions", "ListPrincipals", "ListResourceSharePermissions", "ListResources", "RejectResourceShareInvitation", "TagResource", "UntagResource", "UpdateResourceShare"],
            "ARNFormat": "arn:aws:ram:<region>:<account-id>:resource-share/<resource-uuid>",
            "ARNRegex": "^arn:aws:ram:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "ram:AllowsExternalPrincipals", "ram:PermissionArn", "ram:Principal", "ram:RequestedAllowsExternalPrincipals", "ram:RequestedResourceType", "ram:ResourceArn", "ram:ResourceShareName", "ram:ShareOwnerAccountId"],
            "HasResource": true
        },
        "AWS Elemental MediaConnect": {
            "StringPrefix": "mediaconnect",
            "Actions": ["AddFlowOutputs", "CreateFlow", "DeleteFlow", "DescribeFlow", "GrantFlowEntitlements", "ListEntitlements", "ListFlows", "RemoveFlowOutput", "RevokeFlowEntitlement", "StartFlow", "StopFlow", "UpdateFlowEntitlement", "UpdateFlowOutput", "UpdateFlowSource"],
            "ARNFormat": "arn:${Partition}:mediaconnect:${Region}:${Account}:<namespace>:<relative-id>:<relative-name>",
            "ARNRegex": "^arn:${Partition}:mediaconnect:.+",
            "HasResource": true
        },
        "Amazon S3": {
            "StringPrefix": "s3",
            "Actions": ["AbortMultipartUpload", "BypassGovernanceRetention", "CreateAccessPoint", "CreateBucket", "CreateJob", "DeleteAccessPoint", "DeleteAccessPointPolicy", "DeleteBucket", "DeleteBucketPolicy", "DeleteBucketWebsite", "DeleteObject", "DeleteObjectTagging", "DeleteObjectVersion", "DeleteObjectVersionTagging", "DescribeJob", "GetAccelerateConfiguration", "GetAccessPoint", "GetAccessPointPolicy", "GetAccessPointPolicyStatus", "GetAccountPublicAccessBlock", "GetAnalyticsConfiguration", "GetBucketAcl", "GetBucketCORS", "GetBucketLocation", "GetBucketLogging", "GetBucketNotification", "GetBucketObjectLockConfiguration", "GetBucketPolicy", "GetBucketPolicyStatus", "GetBucketPublicAccessBlock", "GetBucketRequestPayment", "GetBucketTagging", "GetBucketVersioning", "GetBucketWebsite", "GetEncryptionConfiguration", "GetInventoryConfiguration", "GetLifecycleConfiguration", "GetMetricsConfiguration", "GetObject", "GetObjectAcl", "GetObjectLegalHold", "GetObjectRetention", "GetObjectTagging", "GetObjectTorrent", "GetObjectVersion", "GetObjectVersionAcl", "GetObjectVersionForReplication", "GetObjectVersionTagging", "GetObjectVersionTorrent", "GetReplicationConfiguration", "HeadBucket", "ListAccessPoints", "ListAllMyBuckets", "ListBucket", "ListBucketMultipartUploads", "ListBucketVersions", "ListJobs", "ListMultipartUploadParts", "ObjectOwnerOverrideToBucketOwner", "PutAccelerateConfiguration", "PutAccessPointPolicy", "PutAccountPublicAccessBlock", "PutAnalyticsConfiguration", "PutBucketAcl", "PutBucketCORS", "PutBucketLogging", "PutBucketNotification", "PutBucketObjectLockConfiguration", "PutBucketPolicy", "PutBucketPublicAccessBlock", "PutBucketRequestPayment", "PutBucketTagging", "PutBucketVersioning", "PutBucketWebsite", "PutEncryptionConfiguration", "PutInventoryConfiguration", "PutLifecycleConfiguration", "PutMetricsConfiguration", "PutObject", "PutObjectAcl", "PutObjectLegalHold", "PutObjectRetention", "PutObjectTagging", "PutObjectVersionAcl", "PutObjectVersionTagging", "PutReplicationConfiguration", "ReplicateDelete", "ReplicateObject", "ReplicateTags", "RestoreObject", "UpdateJobPriority", "UpdateJobStatus"],
            "ARNFormat": "arn:aws:s3:::<bucket_name>/<key_name>",
            "ARNRegex": "^arn:aws:s3:::.+",
            "conditionKeys": ["s3:AccessPointNetworkOrigin", "s3:DataAccessPointAccount", "s3:DataAccessPointArn", "s3:ExistingJobOperation", "s3:ExistingJobPriority", "s3:ExistingObjectTag/<key>", "s3:JobSuspendedCause", "s3:LocationConstraint", "s3:RequestJobOperation", "s3:RequestJobPriority", "s3:RequestObjectTag/<key>", "s3:RequestObjectTagKeys", "s3:VersionId", "s3:authtype", "s3:delimiter", "s3:locationconstraint", "s3:max-keys", "s3:object-lock-legal-hold", "s3:object-lock-mode", "s3:object-lock-remaining-retention-days", "s3:object-lock-retain-until-date", "s3:prefix", "s3:signatureage", "s3:signatureversion", "s3:versionid", "s3:x-amz-acl", "s3:x-amz-content-sha256", "s3:x-amz-copy-source", "s3:x-amz-grant-full-control", "s3:x-amz-grant-read", "s3:x-amz-grant-read-acp", "s3:x-amz-grant-write", "s3:x-amz-grant-write-acp", "s3:x-amz-metadata-directive", "s3:x-amz-server-side-encryption", "s3:x-amz-server-side-encryption-aws-kms-key-id", "s3:x-amz-storage-class", "s3:x-amz-website-redirect-location"],
            "HasResource": true
        },
        "Amazon SageMaker": {
            "StringPrefix": "sagemaker",
            "Actions": ["AddTags", "AssociateTrialComponent", "BatchGetMetrics", "BatchPutMetrics", "CreateAlgorithm", "CreateApp", "CreateAutoMLJob", "CreateCodeRepository", "CreateCompilationJob", "CreateDomain", "CreateEndpoint", "CreateEndpointConfig", "CreateExperiment", "CreateFlowDefinition", "CreateHumanTaskUi", "CreateHyperParameterTuningJob", "CreateLabelingJob", "CreateModel", "CreateModelPackage", "CreateMonitoringSchedule", "CreateNotebookInstance", "CreateNotebookInstanceLifecycleConfig", "CreatePresignedDomainUrl", "CreatePresignedNotebookInstanceUrl", "CreateProcessingJob", "CreateTrainingJob", "CreateTransformJob", "CreateTrial", "CreateTrialComponent", "CreateUserProfile", "CreateWorkteam", "DeleteAlgorithm", "DeleteApp", "DeleteCodeRepository", "DeleteDomain", "DeleteEndpoint", "DeleteEndpointConfig", "DeleteExperiment", "DeleteFlowDefinition", "DeleteHumanLoop", "DeleteModel", "DeleteModelPackage", "DeleteMonitoringSchedule", "DeleteNotebookInstance", "DeleteNotebookInstanceLifecycleConfig", "DeleteTags", "DeleteTrial", "DeleteTrialComponent", "DeleteUserProfile", "DeleteWorkteam", "DescribeAlgorithm", "DescribeApp", "DescribeAutoMLJob", "DescribeCodeRepository", "DescribeCompilationJob", "DescribeDomain", "DescribeEndpoint", "DescribeEndpointConfig", "DescribeExperiment", "DescribeFlowDefinition", "DescribeHumanLoop", "DescribeHumanTaskUi", "DescribeHyperParameterTuningJob", "DescribeLabelingJob", "DescribeModel", "DescribeModelPackage", "DescribeMonitoringSchedule", "DescribeNotebookInstance", "DescribeNotebookInstanceLifecycleConfig", "DescribeProcessingJob", "DescribeSubscribedWorkteam", "DescribeTrainingJob", "DescribeTransformJob", "DescribeTrial", "DescribeTrialComponent", "DescribeUserProfile", "DescribeWorkforce", "DescribeWorkteam", "DisassociateTrialComponent", "GetSearchSuggestions", "InvokeEndpoint", "ListAlgorithms", "ListApps", "ListAutoMLJobs", "ListCandidatesForAutoMLJob", "ListCodeRepositories", "ListCompilationJobs", "ListDomains", "ListEndpointConfigs", "ListEndpoints", "ListExperiments", "ListFlowDefinitions", "ListHumanLoops", "ListHumanTaskUis", "ListHyperParameterTuningJobs", "ListLabelingJobs", "ListLabelingJobsForWorkteam", "ListModelPackages", "ListModels", "ListMonitoringExecutions", "ListMonitoringSchedules", "ListNotebookInstanceLifecycleConfigs", "ListNotebookInstances", "ListProcessingJobs", "ListSubscribedWorkteams", "ListTags", "ListTrainingJobs", "ListTrainingJobsForHyperParameterTuningJob", "ListTransformJobs", "ListTrialComponents", "ListTrials", "ListUserProfiles", "ListWorkteams", "RenderUiTemplate", "Search", "StartHumanLoop", "StartMonitoringSchedule", "StartNotebookInstance", "StopAutoMLJob", "StopCompilationJob", "StopHumanLoop", "StopHyperParameterTuningJob", "StopLabelingJob", "StopMonitoringSchedule", "StopNotebookInstance", "StopProcessingJob", "StopTrainingJob", "StopTransformJob", "UpdateCodeRepository", "UpdateDomain", "UpdateEndpoint", "UpdateEndpointWeightsAndCapacities", "UpdateExperiment", "UpdateMonitoringSchedule", "UpdateNotebookInstance", "UpdateNotebookInstanceLifecycleConfig", "UpdateTrial", "UpdateTrialComponent", "UpdateUserProfile", "UpdateWorkforce", "UpdateWorkteam"],
            "ARNFormat": "arn:aws:sagemaker:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:${Partition}:sagemaker:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "sagemaker:AcceleratorTypes", "sagemaker:AppNetworkAccess", "sagemaker:DirectInternetAccess", "sagemaker:DomainSharingOutputKmsKey", "sagemaker:FileSystemAccessMode", "sagemaker:FileSystemDirectoryPath", "sagemaker:FileSystemId", "sagemaker:FileSystemType", "sagemaker:HomeEfsFileSystemKmsKey", "sagemaker:InstanceTypes", "sagemaker:InterContainerTrafficEncryption", "sagemaker:MaxRuntimeInSeconds", "sagemaker:ModelArn", "sagemaker:NetworkIsolation", "sagemaker:OutputKmsKey", "sagemaker:ResourceTag/", "sagemaker:ResourceTag/${TagKey}", "sagemaker:RootAccess", "sagemaker:VolumeKmsKey", "sagemaker:VpcSecurityGroupIds", "sagemaker:VpcSubnets", "sagemaker:WorkteamArn", "sagemaker:WorkteamType"],
            "HasResource": true
        },
        "AWS Lake Formation": {
            "StringPrefix": "lakeformation",
            "Actions": ["BatchGrantPermissions", "BatchRevokePermissions", "DeregisterResource", "DescribeResource", "GetDataAccess", "GetDataLakeSettings", "GetEffectivePermissionsForPath", "GrantPermissions", "ListPermissions", "ListResources", "PutDataLakeSettings", "RegisterResource", "RevokePermissions", "UpdateResource"],
            "HasResource": false
        },
        "AWS Mobile Hub": {
            "StringPrefix": "mobilehub",
            "Actions": ["CreateProject", "CreateServiceRole", "DeleteProject", "DeleteProjectSnapshot", "DeployToStage", "DescribeBundle", "ExportBundle", "ExportProject", "GenerateProjectParameters", "GetProject", "GetProjectSnapshot", "ImportProject", "InstallBundle", "ListAvailableConnectors", "ListAvailableFeatures", "ListAvailableRegions", "ListBundles", "ListProjectSnapshots", "ListProjects", "SynchronizeProject", "UpdateProject", "ValidateProject", "VerifyServiceRole"],
            "ARNFormat": "arn:aws:mobilehub:<region>:<aws_account_ID>:project/<project_ID>",
            "ARNRegex": "^arn:aws:mobilehub:.+:[0-9]+:.+",
            "HasResource": true
        },
        "AWS Global Accelerator": {
            "StringPrefix": "globalaccelerator",
            "Actions": ["AdvertiseByoipCidr", "CreateAccelerator", "CreateEndpointGroup", "CreateListener", "DeleteAccelerator", "DeleteEndpointGroup", "DeleteListener", "DeprovisionByoipCidr", "DescribeAccelerator", "DescribeAcceleratorAttributes", "DescribeEndpointGroup", "DescribeListener", "ListAccelerators", "ListByoipCidrs", "ListEndpointGroups", "ListListeners", "ListTagsForResource", "ProvisionByoipCidr", "TagResource", "UntagResource", "UpdateAccelerator", "UpdateAcceleratorAttributes", "UpdateEndpointGroup", "UpdateListener", "WithdrawByoipCidr"],
            "ARNFormat": "arn:aws:globalaccelerator::<account>:accelerator/<AcceleratorId>",
            "ARNRegex": "^arn:aws:globalaccelerator::.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Serverless Application Repository": {
            "StringPrefix": "serverlessrepo",
            "Actions": ["CreateApplication", "CreateApplicationVersion", "CreateCloudFormationChangeSet", "CreateCloudFormationTemplate", "DeleteApplication", "GetApplication", "GetApplicationPolicy", "GetCloudFormationTemplate", "ListApplicationDependencies", "ListApplicationVersions", "ListApplications", "PutApplicationPolicy", "SearchApplications", "UnshareApplication", "UpdateApplication"],
            "ARNFormat": "arn:aws:serverlessrepo:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:serverlessrepo:.+:.+:.+",
            "conditionKeys": ["serverlessrepo:applicationType"],
            "HasResource": true
        },
        "Amazon Forecast": {
            "StringPrefix": "forecast",
            "Actions": ["CreateDataset", "CreateDatasetGroup", "CreateDatasetImportJob", "CreateForecast", "CreateForecastExportJob", "CreatePredictor", "DeleteDataset", "DeleteDatasetGroup", "DeleteDatasetImportJob", "DeleteForecast", "DeleteForecastExportJob", "DeletePredictor", "DescribeDataset", "DescribeDatasetGroup", "DescribeDatasetImportJob", "DescribeForecast", "DescribeForecastExportJob", "DescribePredictor", "GetAccuracyMetrics", "ListDatasetGroups", "ListDatasetImportJobs", "ListDatasets", "ListForecastExportJobs", "ListForecasts", "ListPredictors", "QueryForecast", "UpdateDatasetGroup"],
            "ARNFormat": "arn:aws:forecast:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:forecast:.+:.+:.+",
            "HasResource": true
        },
        "Amazon Cloud Directory": {
            "StringPrefix": "clouddirectory",
            "Actions": ["AddFacetToObject", "ApplySchema", "AttachObject", "AttachPolicy", "AttachToIndex", "AttachTypedLink", "BatchRead", "BatchWrite", "CreateDirectory", "CreateFacet", "CreateIndex", "CreateObject", "CreateSchema", "CreateTypedLinkFacet", "DeleteDirectory", "DeleteFacet", "DeleteObject", "DeleteSchema", "DeleteTypedLinkFacet", "DetachFromIndex", "DetachObject", "DetachPolicy", "DetachTypedLink", "DisableDirectory", "EnableDirectory", "GetDirectory", "GetFacet", "GetLinkAttributes", "GetObjectAttributes", "GetObjectInformation", "GetSchemaAsJson", "GetTypedLinkFacetInformation", "ListAppliedSchemaArns", "ListAttachedIndices", "ListDevelopmentSchemaArns", "ListDirectories", "ListFacetAttributes", "ListFacetNames", "ListIncomingTypedLinks", "ListIndex", "ListObjectAttributes", "ListObjectChildren", "ListObjectParentPaths", "ListObjectParents", "ListObjectPolicies", "ListOutgoingTypedLinks", "ListPolicyAttachments", "ListPublishedSchemaArns", "ListTagsForResource", "ListTypedLinkFacetAttributes", "ListTypedLinkFacetNames", "LookupPolicy", "PublishSchema", "PutSchemaFromJson", "RemoveFacetFromObject", "TagResource", "UntagResource", "UpdateFacet", "UpdateLinkAttributes", "UpdateObjectAttributes", "UpdateSchema", "UpdateTypedLinkFacet"],
            "ARNFormat": "arn:aws:clouddirectory:<region>:<accountId>:<relative-id>",
            "ARNRegex": "^arn:${Partition}:clouddirectory:.+:[0-9]+:(directory|schema)/.+",
            "HasResource": true
        },
        "AWS Elemental MediaTailor": {
            "StringPrefix": "mediatailor",
            "Actions": ["DeletePlaybackConfiguration", "GetPlaybackConfiguration", "ListPlaybackConfigurations", "ListTagsForResource", "PutPlaybackConfiguration", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:mediatailor:<region>:<account-id>:<resource-type>/<resource-name>",
            "ARNRegex": "^arn:aws:mediatailor:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Route 53": {
            "StringPrefix": "route53",
            "Actions": ["AssociateVPCWithHostedZone", "ChangeResourceRecordSets", "ChangeTagsForResource", "CreateHealthCheck", "CreateHostedZone", "CreateQueryLoggingConfig", "CreateReusableDelegationSet", "CreateTrafficPolicy", "CreateTrafficPolicyInstance", "CreateTrafficPolicyVersion", "CreateVPCAssociationAuthorization", "DeleteHealthCheck", "DeleteHostedZone", "DeleteQueryLoggingConfig", "DeleteReusableDelegationSet", "DeleteTrafficPolicy", "DeleteTrafficPolicyInstance", "DeleteVPCAssociationAuthorization", "DisassociateVPCFromHostedZone", "GetAccountLimit", "GetChange", "GetCheckerIpRanges", "GetGeoLocation", "GetHealthCheck", "GetHealthCheckCount", "GetHealthCheckLastFailureReason", "GetHealthCheckStatus", "GetHostedZone", "GetHostedZoneCount", "GetHostedZoneLimit", "GetQueryLoggingConfig", "GetReusableDelegationSet", "GetReusableDelegationSetLimit", "GetTrafficPolicy", "GetTrafficPolicyInstance", "GetTrafficPolicyInstanceCount", "ListGeoLocations", "ListHealthChecks", "ListHostedZones", "ListHostedZonesByName", "ListQueryLoggingConfigs", "ListResourceRecordSets", "ListReusableDelegationSets", "ListTagsForResource", "ListTagsForResources", "ListTrafficPolicies", "ListTrafficPolicyInstances", "ListTrafficPolicyInstancesByHostedZone", "ListTrafficPolicyInstancesByPolicy", "ListTrafficPolicyVersions", "ListVPCAssociationAuthorizations", "TestDNSAnswer", "UpdateHealthCheck", "UpdateHostedZoneComment", "UpdateTrafficPolicyComment", "UpdateTrafficPolicyInstance"],
            "ARNFormat": "arn:aws:route53:::<resource>/<id>",
            "ARNRegex": "^arn:aws:route53:::.+",
            "HasResource": true
        },
        "Amazon SimpleDB": {
            "StringPrefix": "sdb",
            "Actions": ["BatchDeleteAttributes", "BatchPutAttributes", "CreateDomain", "DeleteAttributes", "DeleteDomain", "DomainMetadata", "GetAttributes", "ListDomains", "PutAttributes", "Select"],
            "ARNFormat": "arn:aws:sdb:<region>:<account_ID>:domain/<domain_name>",
            "ARNRegex": "^arn:aws:sdb:.+",
            "HasResource": true
        },
        "AWS Security Token Service": {
            "StringPrefix": "sts",
            "Actions": ["AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "DecodeAuthorizationMessage", "GetAccessKeyInfo", "GetCallerIdentity", "GetFederationToken", "GetSessionToken", "TagSession"],
            "ARNFormat": "arn:aws:iam::<namespace>:<relative-id>",
            "ARNRegex": "^arn:aws:iam::.+",
            "conditionKeys": ["accounts.google.com:aud", "accounts.google.com:oaud", "accounts.google.com:sub", "aws:FederatedProvider", "aws:PrincipalTag/${TagKey}", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "cognito-identity.amazonaws.com:amr", "cognito-identity.amazonaws.com:aud", "cognito-identity.amazonaws.com:sub", "graph.facebook.com:app_id", "graph.facebook.com:id", "saml:aud", "saml:cn", "saml:commonName", "saml:doc", "saml:eduorghomepageuri", "saml:eduorgidentityauthnpolicyuri", "saml:eduorglegalname", "saml:eduorgsuperioruri", "saml:eduorgwhitepagesuri", "saml:edupersonaffiliation", "saml:edupersonassurance", "saml:edupersonentitlement", "saml:edupersonnickname", "saml:edupersonorgdn", "saml:edupersonorgunitdn", "saml:edupersonprimaryaffiliation", "saml:edupersonprimaryorgunitdn", "saml:edupersonprincipalname", "saml:edupersonscopedaffiliation", "saml:edupersontargetedid", "saml:givenName", "saml:iss", "saml:mail", "saml:name", "saml:namequalifier", "saml:organizationStatus", "saml:primaryGroupSID", "saml:sub", "saml:sub_type", "saml:surname", "saml:uid", "saml:x500UniqueIdentifier", "sts:ExternalId", "sts:RoleSessionName", "sts:TransitiveTagKeys", "www.amazon.com:app_id", "www.amazon.com:user_id"],
            "HasResource": true
        },
        "AWS Elemental MediaPackage": {
            "StringPrefix": "mediapackage",
            "Actions": ["CreateChannel", "CreateOriginEndpoint", "DeleteChannel", "DeleteOriginEndpoint", "DescribeChannel", "DescribeOriginEndpoint", "ListChannels", "ListOriginEndpoints", "ListTagsForResource", "RotateIngestEndpointCredentials", "TagResource", "UntagResource", "UpdateChannel", "UpdateOriginEndpoint"],
            "ARNFormat": "arn:aws:mediapackage:<region>:<account_ID>:<resource>/<identifier>",
            "ARNRegex": "^arn:aws:mediapackage:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Keyspaces (for Apache Cassandra)": {
            "StringPrefix": "cassandra",
            "Actions": ["Alter", "Create", "Drop", "Modify", "Select", "TagResource", "UntagResource"],
            "ARNFormat": "arn:${Partition}:cassandra:${region}:${account}:/${resourceType}/${resourcePath}/",
            "ARNRegex": "^arn:${Partition}:cassandra:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Athena": {
            "StringPrefix": "athena",
            "Actions": ["BatchGetNamedQuery", "BatchGetQueryExecution", "CancelQueryExecution", "CreateNamedQuery", "CreateWorkGroup", "DeleteNamedQuery", "DeleteWorkGroup", "GetCatalogs", "GetExecutionEngine", "GetExecutionEngines", "GetNamedQuery", "GetNamespace", "GetNamespaces", "GetQueryExecution", "GetQueryExecutions", "GetQueryResults", "GetQueryResultsStream", "GetTable", "GetTables", "GetWorkGroup", "ListNamedQueries", "ListQueryExecutions", "ListTagsForResource", "ListWorkGroups", "RunQuery", "StartQueryExecution", "StopQueryExecution", "TagResource", "UntagResource", "UpdateWorkGroup"],
            "ARNFormat": "arn:${Partition}:athena:${Region}:${Account}:workgroup/${WorkGroupName}",
            "ARNRegex": "^arn:${Partition}:athena:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Marketplace Metering Service": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["BatchMeterUsage", "MeterUsage", "RegisterUsage", "ResolveCustomer"],
            "HasResource": false
        },
        "AWS Marketplace Procurement Systems Integration": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["DescribeProcurementSystemConfiguration", "PutProcurementSystemConfiguration"],
            "HasResource": false
        },
        "AWS Marketplace Catalog": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["CancelChangeSet", "CompleteTask", "DescribeChangeSet", "DescribeEntity", "DescribeTask", "ListChangeSets", "ListEntities", "ListTasks", "StartChangeSet", "UpdateTask"],
            "ARNFormat": "arn:aws:aws-marketplace:<region>:<account>:<catalog>/<resource_type>/<resource_id>",
            "ARNRegex": "^arn:aws:aws-marketplace:::.+",
            "conditionKeys": ["catalog:ChangeType"],
            "HasResource": true
        },
        "AWS Marketplace Image Building Service": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["DescribeBuilds", "ListBuilds", "StartBuild"],
            "HasResource": false
        },
        "AWS Marketplace Entitlement Service": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["GetEntitlements"],
            "HasResource": false
        },
        "AWS Marketplace": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["AcceptAgreementApprovalRequest", "CancelAgreementRequest", "GetAgreementApprovalRequest", "GetAgreementRequest", "ListAgreementApprovalRequests", "ListAgreementRequests", "RejectAgreementApprovalRequest", "Subscribe", "Unsubscribe", "UpdateAgreementApprovalRequest", "ViewSubscriptions"],
            "HasResource": false
        },
        "AWS Private Marketplace": {
            "StringPrefix": "aws-marketplace",
            "Actions": ["AssociateProductsWithPrivateMarketplace", "CreatePrivateMarketplace", "CreatePrivateMarketplaceProfile", "CreatePrivateMarketplaceRequests", "DescribePrivateMarketplaceProducts", "DescribePrivateMarketplaceProfile", "DescribePrivateMarketplaceRequests", "DescribePrivateMarketplaceSettings", "DescribePrivateMarketplaceStatus", "DisassociateProductsFromPrivateMarketplace", "ListPrivateMarketplaceProducts", "ListPrivateMarketplaceRequests", "StartPrivateMarketplace", "StopPrivateMarketplace", "UpdatePrivateMarketplaceProfile", "UpdatePrivateMarketplaceSettings"],
            "HasResource": false
        },
        "Amazon Pinpoint": {
            "StringPrefix": "mobiletargeting",
            "Actions": ["CreateApp", "CreateCampaign", "CreateEmailTemplate", "CreateExportJob", "CreateImportJob", "CreateJourney", "CreatePushTemplate", "CreateRecommenderConfiguration", "CreateSegment", "CreateSmsTemplate", "CreateVoiceTemplate", "DeleteAdmChannel", "DeleteApnsChannel", "DeleteApnsSandboxChannel", "DeleteApnsVoipChannel", "DeleteApnsVoipSandboxChannel", "DeleteApp", "DeleteBaiduChannel", "DeleteCampaign", "DeleteEmailChannel", "DeleteEmailTemplate", "DeleteEndpoint", "DeleteEventStream", "DeleteGcmChannel", "DeleteJourney", "DeletePushTemplate", "DeleteRecommenderConfiguration", "DeleteSegment", "DeleteSmsChannel", "DeleteSmsTemplate", "DeleteUserEndpoints", "DeleteVoiceChannel", "DeleteVoiceTemplate", "GetAdmChannel", "GetApnsChannel", "GetApnsSandboxChannel", "GetApnsVoipChannel", "GetApnsVoipSandboxChannel", "GetApp", "GetApplicationSettings", "GetApps", "GetBaiduChannel", "GetCampaign", "GetCampaignActivities", "GetCampaignVersion", "GetCampaignVersions", "GetCampaigns", "GetChannels", "GetEmailChannel", "GetEmailTemplate", "GetEndpoint", "GetEventStream", "GetExportJob", "GetExportJobs", "GetGcmChannel", "GetImportJob", "GetImportJobs", "GetJourney", "GetPushTemplate", "GetRecommenderConfiguration", "GetRecommenderConfigurations", "GetSegment", "GetSegmentExportJobs", "GetSegmentImportJobs", "GetSegmentVersion", "GetSegmentVersions", "GetSegments", "GetSmsChannel", "GetSmsTemplate", "GetUserEndpoints", "GetVoiceChannel", "GetVoiceTemplate", "ListJourneys", "ListTagsForResource", "ListTemplateVersions", "ListTemplates", "PhoneNumberValidate", "PutEventStream", "PutEvents", "RemoveAttributes", "SendMessages", "SendUsersMessages", "TagResource", "UntagResource", "UpdateAdmChannel", "UpdateApnsChannel", "UpdateApnsSandboxChannel", "UpdateApnsVoipChannel", "UpdateApnsVoipSandboxChannel", "UpdateApplicationSettings", "UpdateBaiduChannel", "UpdateCampaign", "UpdateEmailChannel", "UpdateEmailTemplate", "UpdateEndpoint", "UpdateEndpointsBatch", "UpdateGcmChannel", "UpdateJourney", "UpdateJourneyState", "UpdatePushTemplate", "UpdateRecommenderConfiguration", "UpdateSegment", "UpdateSmsChannel", "UpdateSmsTemplate", "UpdateTemplateActiveVersion", "UpdateVoiceChannel", "UpdateVoiceTemplate"],
            "ARNFormat": "arn:aws:mobiletargeting:<region>:<account_ID>:.+",
            "ARNRegex": "^arn:aws:mobiletargeting:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Sumerian": {
            "StringPrefix": "sumerian",
            "Actions": ["Login", "ViewRelease"],
            "ARNFormat": "arn:aws:sumerian:<region>:<account-id>:<sumerian_resource_path>",
            "ARNRegex": "^arn:aws:sumerian:.+:.+:.+",
            "HasResource": true
        },
        "AWS Auto Scaling": {
            "StringPrefix": "autoscaling-plans",
            "Actions": ["CreateScalingPlan", "DeleteScalingPlan", "DescribeScalingPlanResources", "DescribeScalingPlans", "GetScalingPlanResourceForecastData", "UpdateScalingPlan"],
            "HasResource": false
        },
        "AWS Cost and Usage Report": {
            "StringPrefix": "cur",
            "Actions": ["DeleteReportDefinition", "DescribeReportDefinitions", "ModifyReportDefinition", "PutReportDefinition"],
            "ARNFormat": "arn:aws:cur:<region>:<account_ID>:definition/<reportname>",
            "ARNRegex": "^arn:aws:cur:.+:.+:.+",
            "HasResource": true
        },
        "Amazon Route53 Domains": {
            "StringPrefix": "route53domains",
            "Actions": ["CheckDomainAvailability", "DeleteTagsForDomain", "DisableDomainAutoRenew", "DisableDomainTransferLock", "EnableDomainAutoRenew", "EnableDomainTransferLock", "GetContactReachabilityStatus", "GetDomainDetail", "GetDomainSuggestions", "GetOperationDetail", "ListDomains", "ListOperations", "ListTagsForDomain", "RegisterDomain", "RenewDomain", "ResendContactReachabilityEmail", "RetrieveDomainAuthCode", "TransferDomain", "UpdateDomainContact", "UpdateDomainContactPrivacy", "UpdateDomainNameservers", "UpdateTagsForDomain", "ViewBilling"],
            "HasResource": false
        },
        "AWS OpsWorks": {
            "StringPrefix": "opsworks",
            "Actions": ["AssignInstance", "AssignVolume", "AssociateElasticIp", "AttachElasticLoadBalancer", "CloneStack", "CreateApp", "CreateDeployment", "CreateInstance", "CreateLayer", "CreateStack", "CreateUserProfile", "DeleteApp", "DeleteInstance", "DeleteLayer", "DeleteStack", "DeleteUserProfile", "DeregisterEcsCluster", "DeregisterElasticIp", "DeregisterInstance", "DeregisterRdsDbInstance", "DeregisterVolume", "DescribeAgentVersions", "DescribeApps", "DescribeCommands", "DescribeDeployments", "DescribeEcsClusters", "DescribeElasticIps", "DescribeElasticLoadBalancers", "DescribeInstances", "DescribeLayers", "DescribeLoadBasedAutoScaling", "DescribeMyUserProfile", "DescribePermissions", "DescribeRaidArrays", "DescribeRdsDbInstances", "DescribeServiceErrors", "DescribeStackProvisioningParameters", "DescribeStackSummary", "DescribeStacks", "DescribeTimeBasedAutoScaling", "DescribeUserProfiles", "DescribeVolumes", "DetachElasticLoadBalancer", "DisassociateElasticIp", "GetHostnameSuggestion", "GrantAccess", "ListTags", "RebootInstance", "RegisterEcsCluster", "RegisterElasticIp", "RegisterInstance", "RegisterRdsDbInstance", "RegisterVolume", "SetLoadBasedAutoScaling", "SetPermission", "SetTimeBasedAutoScaling", "StartInstance", "StartStack", "StopInstance", "StopStack", "TagResource", "UnassignInstance", "UnassignVolume", "UntagResource", "UpdateApp", "UpdateElasticIp", "UpdateInstance", "UpdateLayer", "UpdateMyUserProfile", "UpdateRdsDbInstance", "UpdateStack", "UpdateUserProfile", "UpdateVolume"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:opsworks:.+",
            "HasResource": true
        },
        "Amazon FreeRTOS": {
            "StringPrefix": "freertos",
            "Actions": ["CreateSoftwareConfiguration", "DeleteSoftwareConfiguration", "DescribeHardwarePlatform", "DescribeSoftwareConfiguration", "GetSoftwareURL", "GetSoftwareURLForConfiguration", "ListFreeRTOSVersions", "ListHardwarePlatforms", "ListHardwareVendors", "ListSoftwareConfigurations", "UpdateSoftwareConfiguration"],
            "ARNFormat": "arn:${Partition}:freertos:<region>:<account_ID>:<type>/<name>",
            "ARNRegex": "^arn:${Partition}:freertos:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS CodeDeploy": {
            "StringPrefix": "codedeploy",
            "Actions": ["AddTagsToOnPremisesInstances", "BatchGetApplicationRevisions", "BatchGetApplications", "BatchGetDeploymentGroups", "BatchGetDeploymentInstances", "BatchGetDeploymentTargets", "BatchGetDeployments", "BatchGetOnPremisesInstances", "ContinueDeployment", "CreateApplication", "CreateDeployment", "CreateDeploymentConfig", "CreateDeploymentGroup", "DeleteApplication", "DeleteDeploymentConfig", "DeleteDeploymentGroup", "DeleteGitHubAccountToken", "DeregisterOnPremisesInstance", "GetApplication", "GetApplicationRevision", "GetDeployment", "GetDeploymentConfig", "GetDeploymentGroup", "GetDeploymentInstance", "GetDeploymentTarget", "GetOnPremisesInstance", "ListApplicationRevisions", "ListApplications", "ListDeploymentConfigs", "ListDeploymentGroups", "ListDeploymentInstances", "ListDeploymentTargets", "ListDeployments", "ListGitHubAccountTokenNames", "ListOnPremisesInstances", "ListTagsForResource", "PutLifecycleEventHookExecutionStatus", "RegisterApplicationRevision", "RegisterOnPremisesInstance", "RemoveTagsFromOnPremisesInstances", "SkipWaitTimeForInstanceTermination", "StopDeployment", "TagResource", "UntagResource", "UpdateApplication", "UpdateDeploymentGroup"],
            "ARNFormat": "arn:aws:codedeploy:region:account:resource-type:resource-specifier",
            "ARNRegex": "^arn:aws:codedeploy:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Identity And Access Management": {
            "StringPrefix": "iam",
            "Actions": ["AddClientIDToOpenIDConnectProvider", "AddRoleToInstanceProfile", "AddUserToGroup", "AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "ChangePassword", "CreateAccessKey", "CreateAccountAlias", "CreateGroup", "CreateInstanceProfile", "CreateLoginProfile", "CreateOpenIDConnectProvider", "CreatePolicy", "CreatePolicyVersion", "CreateRole", "CreateSAMLProvider", "CreateServiceLinkedRole", "CreateServiceSpecificCredential", "CreateUser", "CreateVirtualMFADevice", "DeactivateMFADevice", "DeleteAccessKey", "DeleteAccountAlias", "DeleteAccountPasswordPolicy", "DeleteGroup", "DeleteGroupPolicy", "DeleteInstanceProfile", "DeleteLoginProfile", "DeleteOpenIDConnectProvider", "DeletePolicy", "DeletePolicyVersion", "DeleteRole", "DeleteRolePermissionsBoundary", "DeleteRolePolicy", "DeleteSAMLProvider", "DeleteSSHPublicKey", "DeleteServerCertificate", "DeleteServiceLinkedRole", "DeleteServiceSpecificCredential", "DeleteSigningCertificate", "DeleteUser", "DeleteUserPermissionsBoundary", "DeleteUserPolicy", "DeleteVirtualMFADevice", "DetachGroupPolicy", "DetachRolePolicy", "DetachUserPolicy", "EnableMFADevice", "GenerateCredentialReport", "GenerateOrganizationsAccessReport", "GenerateServiceLastAccessedDetails", "GetAccessKeyLastUsed", "GetAccountAuthorizationDetails", "GetAccountPasswordPolicy", "GetAccountSummary", "GetContextKeysForCustomPolicy", "GetContextKeysForPrincipalPolicy", "GetCredentialReport", "GetGroup", "GetGroupPolicy", "GetInstanceProfile", "GetLoginProfile", "GetOpenIDConnectProvider", "GetOrganizationsAccessReport", "GetPolicy", "GetPolicyVersion", "GetRole", "GetRolePolicy", "GetSAMLProvider", "GetSSHPublicKey", "GetServerCertificate", "GetServiceLastAccessedDetails", "GetServiceLastAccessedDetailsWithEntities", "GetServiceLinkedRoleDeletionStatus", "GetUser", "GetUserPolicy", "ListAccessKeys", "ListAccountAliases", "ListAttachedGroupPolicies", "ListAttachedRolePolicies", "ListAttachedUserPolicies", "ListEntitiesForPolicy", "ListGroupPolicies", "ListGroups", "ListGroupsForUser", "ListInstanceProfiles", "ListInstanceProfilesForRole", "ListMFADevices", "ListOpenIDConnectProviders", "ListPolicies", "ListPoliciesGrantingServiceAccess", "ListPolicyVersions", "ListRolePolicies", "ListRoleTags", "ListRoles", "ListSAMLProviders", "ListSSHPublicKeys", "ListServerCertificates", "ListServiceSpecificCredentials", "ListSigningCertificates", "ListUserPolicies", "ListUserTags", "ListUsers", "ListVirtualMFADevices", "PassRole", "PutGroupPolicy", "PutRolePermissionsBoundary", "PutRolePolicy", "PutUserPermissionsBoundary", "PutUserPolicy", "RemoveClientIDFromOpenIDConnectProvider", "RemoveRoleFromInstanceProfile", "RemoveUserFromGroup", "ResetServiceSpecificCredential", "ResyncMFADevice", "SetDefaultPolicyVersion", "SetSecurityTokenServicePreferences", "SimulateCustomPolicy", "SimulatePrincipalPolicy", "TagRole", "TagUser", "UntagRole", "UntagUser", "UpdateAccessKey", "UpdateAccountPasswordPolicy", "UpdateAssumeRolePolicy", "UpdateGroup", "UpdateLoginProfile", "UpdateOpenIDConnectProviderThumbprint", "UpdateRole", "UpdateRoleDescription", "UpdateSAMLProvider", "UpdateSSHPublicKey", "UpdateServerCertificate", "UpdateServiceSpecificCredential", "UpdateSigningCertificate", "UpdateUser", "UploadSSHPublicKey", "UploadServerCertificate", "UploadSigningCertificate"],
            "ARNFormat": "arn:aws:iam::<namespace>:<relative-id>",
            "ARNRegex": "^arn:aws:iam::.+",
            "conditionKeys": ["iam:AWSServiceName", "iam:AssociatedResourceArn", "iam:OrganizationsPolicyId", "iam:PassedToService", "iam:PermissionsBoundary", "iam:PolicyARN", "iam:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "Amazon Route 53 Resolver": {
            "StringPrefix": "route53resolver",
            "Actions": ["AssociateResolverEndpointIpAddress", "AssociateResolverRule", "CreateResolverEndpoint", "CreateResolverRule", "DeleteResolverEndpoint", "DeleteResolverRule", "DisassociateResolverEndpointIpAddress", "DisassociateResolverRule", "GetResolverEndpoint", "GetResolverRule", "GetResolverRuleAssociation", "GetResolverRulePolicy", "ListResolverEndpointIpAddresses", "ListResolverEndpoints", "ListResolverRuleAssociations", "ListResolverRules", "ListTagsForResource", "PutResolverRulePolicy", "TagResource", "UntagResource", "UpdateResolverEndpoint", "UpdateResolverRule"],
            "ARNFormat": "arn:aws:route53resolver:<region>:<account-id>:<resource-type>/<resource-id>",
            "ARNRegex": "^arn:aws:route53resolver:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon WorkMail": {
            "StringPrefix": "workmail",
            "Actions": ["AddMembersToGroup", "AssociateDelegateToResource", "AssociateMemberToGroup", "CreateAlias", "CreateGroup", "CreateInboundMailFlowRule", "CreateMailDomain", "CreateMailUser", "CreateOrganization", "CreateOutboundMailFlowRule", "CreateResource", "CreateSmtpGateway", "CreateUser", "DeleteAccessControlRule", "DeleteAlias", "DeleteGroup", "DeleteInboundMailFlowRule", "DeleteMailDomain", "DeleteMailboxPermissions", "DeleteMobileDevice", "DeleteOrganization", "DeleteOutboundMailFlowRule", "DeleteResource", "DeleteSmtpGateway", "DeleteUser", "DeregisterFromWorkMail", "DescribeDirectories", "DescribeGroup", "DescribeInboundMailFlowRule", "DescribeKmsKeys", "DescribeMailDomains", "DescribeMailGroups", "DescribeMailUsers", "DescribeOrganization", "DescribeOrganizations", "DescribeOutboundMailFlowRule", "DescribeResource", "DescribeSmtpGateway", "DescribeUser", "DisableMailGroups", "DisableMailUsers", "DisassociateDelegateFromResource", "DisassociateMemberFromGroup", "EnableMailDomain", "EnableMailGroups", "EnableMailUsers", "GetAccessControlEffect", "GetJournalingRules", "GetMailDomainDetails", "GetMailGroupDetails", "GetMailUserDetails", "GetMailboxDetails", "GetMobileDeviceDetails", "GetMobileDevicesForUser", "GetMobilePolicyDetails", "ListAccessControlRules", "ListAliases", "ListGroupMembers", "ListGroups", "ListInboundMailFlowRules", "ListMailboxPermissions", "ListMembersInMailGroup", "ListOrganizations", "ListOutboundMailFlowRules", "ListResourceDelegates", "ListResources", "ListSmtpGateways", "ListTagsForResource", "ListUsers", "PutAccessControlRule", "PutMailboxPermissions", "RegisterToWorkMail", "RemoveMembersFromGroup", "ResetPassword", "ResetUserPassword", "SearchMembers", "SetAdmin", "SetDefaultMailDomain", "SetJournalingRules", "SetMailGroupDetails", "SetMailUserDetails", "SetMobilePolicyDetails", "TagResource", "TestInboundMailFlowRules", "TestOutboundMailFlowRules", "UntagResource", "UpdateInboundMailFlowRule", "UpdateMailboxQuota", "UpdateOutboundMailFlowRule", "UpdatePrimaryEmailAddress", "UpdateResource", "UpdateSmtpGateway", "WipeMobileDevice"],
            "ARNFormat": "arn:${Partition}:workmail:${Region}:${Account}:${ResourceType}/${ResourceId}",
            "ARNRegex": "^arn:${Partition}:workmail:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS CodeBuild": {
            "StringPrefix": "codebuild",
            "Actions": ["BatchDeleteBuilds", "BatchGetBuilds", "BatchGetProjects", "BatchGetReportGroups", "BatchGetReports", "BatchPutTestCases", "CreateProject", "CreateReport", "CreateReportGroup", "CreateWebhook", "DeleteOAuthToken", "DeleteProject", "DeleteReport", "DeleteReportGroup", "DeleteResourcePolicy", "DeleteSourceCredentials", "DeleteWebhook", "DescribeTestCases", "GetResourcePolicy", "ImportSourceCredentials", "InvalidateProjectCache", "ListBuilds", "ListBuildsForProject", "ListConnectedOAuthAccounts", "ListCuratedEnvironmentImages", "ListProjects", "ListReportGroups", "ListReports", "ListReportsForReportGroup", "ListRepositories", "ListSharedProjects", "ListSharedReportGroups", "ListSourceCredentials", "PersistOAuthToken", "PutResourcePolicy", "StartBuild", "StopBuild", "UpdateProject", "UpdateReport", "UpdateReportGroup", "UpdateWebhook"],
            "ARNFormat": "arn:${Partition}:codebuild:<region>:<account_ID>:<resource_type>/<resource_id>",
            "ARNRegex": "^arn:${Partition}:codebuild:.+:[0-9]+:.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS IoT Analytics": {
            "StringPrefix": "iotanalytics",
            "Actions": ["BatchPutMessage", "CancelPipelineReprocessing", "CreateChannel", "CreateDataset", "CreateDatasetContent", "CreateDatastore", "CreatePipeline", "DeleteChannel", "DeleteDataset", "DeleteDatasetContent", "DeleteDatastore", "DeletePipeline", "DescribeChannel", "DescribeDataset", "DescribeDatastore", "DescribeLoggingOptions", "DescribePipeline", "GetDatasetContent", "ListChannels", "ListDatasets", "ListDatastores", "ListPipelines", "ListTagsForResource", "PutLoggingOptions", "RunPipelineActivity", "SampleChannelData", "StartPipelineReprocessing", "TagResource", "UntagResource", "UpdateChannel", "UpdateDataset", "UpdateDatastore", "UpdatePipeline"],
            "ARNFormat": "arn:aws:iotanalytics:<region>:<account_ID>:<type>/<name>",
            "ARNRegex": "^arn:aws:iotanalytics:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:TagKeys", "iotanalytics:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "Amazon Connect": {
            "StringPrefix": "connect",
            "Actions": ["CreateInstance", "CreateUser", "DeleteUser", "DescribeInstance", "DescribeUser", "DescribeUserHierarchyGroup", "DescribeUserHierarchyStructure", "DestroyInstance", "GetContactAttributes", "GetCurrentMetricData", "GetFederationToken", "GetFederationTokens", "GetMetricData", "ListContactFlows", "ListHoursOfOperations", "ListInstances", "ListPhoneNumbers", "ListQueues", "ListRoutingProfiles", "ListSecurityProfiles", "ListTagsForResource", "ListUserHierarchyGroups", "ListUsers", "ModifyInstance", "StartChatContact", "StartOutboundVoiceContact", "StopContact", "TagResource", "UntagResource", "UpdateContactAttributes", "UpdateUserHierarchy", "UpdateUserIdentityInfo", "UpdateUserPhoneConfig", "UpdateUserRoutingProfile", "UpdateUserSecurityProfiles"],
            "ARNFormat": "arn:${Partition}:connect:${Region}:${Account}:instance/${InstanceId}",
            "ARNRegex": "^arn:${Partition}:connect:.+:.+:instance/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Pinpoint Email Service": {
            "StringPrefix": "ses",
            "Actions": ["CreateConfigurationSet", "CreateConfigurationSetEventDestination", "CreateDedicatedIpPool", "CreateDeliverabilityTestReport", "CreateEmailIdentity", "DeleteConfigurationSet", "DeleteConfigurationSetEventDestination", "DeleteDedicatedIpPool", "DeleteEmailIdentity", "GetAccount", "GetBlacklistReports", "GetConfigurationSet", "GetConfigurationSetEventDestinations", "GetDedicatedIp", "GetDedicatedIps", "GetDeliverabilityDashboardOptions", "GetDeliverabilityTestReport", "GetDomainStatisticsReport", "GetEmailIdentity", "ListConfigurationSets", "ListDedicatedIpPools", "ListDeliverabilityTestReports", "ListEmailIdentities", "ListTagsForResource", "PutAccountDedicatedIpWarmupAttributes", "PutAccountSendingAttributes", "PutConfigurationSetDeliveryOptions", "PutConfigurationSetReputationOptions", "PutConfigurationSetSendingOptions", "PutConfigurationSetTrackingOptions", "PutDedicatedIpInPool", "PutDedicatedIpWarmupAttributes", "PutDeliverabilityDashboardOption", "PutEmailIdentityDkimAttributes", "PutEmailIdentityFeedbackAttributes", "PutEmailIdentityMailFromAttributes", "SendEmail", "TagResource", "UntagResource", "UpdateConfigurationSetEventDestination"],
            "ARNFormat": "arn:aws:ses:<region>:<account_ID>:<arn_type>/<resource_id>",
            "ARNRegex": "^arn:aws:ses:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "ses:FeedbackAddress", "ses:FromAddress", "ses:FromDisplayName", "ses:Recipients"],
            "HasResource": true
        },
        "Amazon SES": {
            "StringPrefix": "ses",
            "Actions": ["CloneReceiptRuleSet", "CreateConfigurationSet", "CreateConfigurationSetEventDestination", "CreateConfigurationSetTrackingOptions", "CreateCustomVerificationEmailTemplate", "CreateReceiptFilter", "CreateReceiptRule", "CreateReceiptRuleSet", "CreateTemplate", "DeleteConfigurationSet", "DeleteConfigurationSetEventDestination", "DeleteConfigurationSetTrackingOptions", "DeleteCustomVerificationEmailTemplate", "DeleteIdentity", "DeleteIdentityPolicy", "DeleteReceiptFilter", "DeleteReceiptRule", "DeleteReceiptRuleSet", "DeleteTemplate", "DeleteVerifiedEmailAddress", "DescribeActiveReceiptRuleSet", "DescribeConfigurationSet", "DescribeReceiptRule", "DescribeReceiptRuleSet", "GetAccountSendingEnabled", "GetCustomVerificationEmailTemplate", "GetIdentityDkimAttributes", "GetIdentityMailFromDomainAttributes", "GetIdentityNotificationAttributes", "GetIdentityPolicies", "GetIdentityVerificationAttributes", "GetSendQuota", "GetSendStatistics", "GetTemplate", "ListConfigurationSets", "ListCustomVerificationEmailTemplates", "ListIdentities", "ListIdentityPolicies", "ListReceiptFilters", "ListReceiptRuleSets", "ListTemplates", "ListVerifiedEmailAddresses", "PutIdentityPolicy", "ReorderReceiptRuleSet", "SendBounce", "SendBulkTemplatedEmail", "SendCustomVerificationEmail", "SendEmail", "SendRawEmail", "SendTemplatedEmail", "SetActiveReceiptRuleSet", "SetIdentityDkimEnabled", "SetIdentityFeedbackForwardingEnabled", "SetIdentityHeadersInNotificationsEnabled", "SetIdentityMailFromDomain", "SetIdentityNotificationTopic", "SetReceiptRulePosition", "TestRenderTemplate", "UpdateAccountSendingEnabled", "UpdateConfigurationSetEventDestination", "UpdateConfigurationSetReputationMetricsEnabled", "UpdateConfigurationSetSendingEnabled", "UpdateConfigurationSetTrackingOptions", "UpdateCustomVerificationEmailTemplate", "UpdateReceiptRule", "UpdateTemplate", "VerifyDomainDkim", "VerifyDomainIdentity", "VerifyEmailAddress", "VerifyEmailIdentity"],
            "ARNFormat": "arn:aws:ses:<region>:<account_ID>:<arn_type>/<resource_id>",
            "ARNRegex": "^arn:aws:ses:.+:[0-9]+:.+",
            "conditionKeys": ["ses:FeedbackAddress", "ses:FromAddress", "ses:FromDisplayName", "ses:Recipients"],
            "HasResource": true
        },
        "AWS Cost Explorer Service": {
            "StringPrefix": "ce",
            "Actions": ["CreateCostCategoryDefinition", "DeleteCostCategoryDefinition", "DescribeCostCategoryDefinition", "GetCostAndUsage", "GetCostAndUsageWithResources", "GetCostForecast", "GetDimensionValues", "GetReservationCoverage", "GetReservationPurchaseRecommendation", "GetReservationUtilization", "GetRightsizingRecommendation", "GetSavingsPlansCoverage", "GetSavingsPlansPurchaseRecommendation", "GetSavingsPlansUtilization", "GetSavingsPlansUtilizationDetails", "GetTags", "GetUsageForecast", "ListCostCategoryDefinitions", "UpdateCostCategoryDefinition"],
            "ARNFormat": "arn:aws:ce::<account_ID>:ce",
            "ARNRegex": "^arn:aws:ce::.+:.+",
            "HasResource": false
        },
        "Amazon CloudWatch Synthetics": {
            "StringPrefix": "synthetics",
            "Actions": ["CreateCanary", "DeleteCanary", "DescribeCanaries", "DescribeCanariesLastRun", "GetCanaryRuns", "ListTagsForResource", "StartCanary", "StopCanary", "TagResource", "UntagResource", "UpdateCanary"],
            "ARNFormat": "arn:aws:synthetics:<region>:<account-id>:<resource-type>:<resource_name>",
            "ARNRegex": "^arn:aws:synthetics:.+",
            "HasResource": true
        },
        "Amazon Elastic Inference": {
            "StringPrefix": "elastic-inference",
            "Actions": ["Connect"],
            "ARNFormat": "arn:aws:elastic-inference:<region>:<account-id>:elastic-inference-accelerator/<identifier>",
            "ARNRegex": "^arn:${Partition}:elastic-inference:.+",
            "HasResource": true
        },
        "AWS DeepLens": {
            "StringPrefix": "deeplens",
            "Actions": ["AssociateServiceRoleToAccount", "BatchGetDevice", "BatchGetModel", "BatchGetProject", "CreateDeviceCertificates", "CreateModel", "CreateProject", "DeleteModel", "DeleteProject", "DeployProject", "DeregisterDevice", "GetAssociatedResources", "GetDeploymentStatus", "GetDevice", "GetModel", "GetProject", "ImportProjectFromTemplate", "ListDeployments", "ListDevices", "ListModels", "ListProjects", "RegisterDevice", "RemoveProject", "UpdateProject"],
            "ARNFormat": "arn:aws:deeplens:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:deeplens:.+:.+:.+",
            "HasResource": true
        },
        "Amazon RDS Data API": {
            "StringPrefix": "rds-data",
            "Actions": ["BatchExecuteStatement", "BeginTransaction", "CommitTransaction", "ExecuteSql", "ExecuteStatement", "RollbackTransaction"],
            "HasResource": false
        },
        "AWS SSO Directory": {
            "StringPrefix": "sso-directory",
            "Actions": ["AddMemberToGroup", "CompleteVirtualMfaDeviceRegistration", "CreateAlias", "CreateBearerToken", "CreateExternalIdPConfigurationForDirectory", "CreateGroup", "CreateProvisioningTenant", "CreateUser", "DeleteBearerToken", "DeleteExternalIdPConfigurationForDirectory", "DeleteGroup", "DeleteMfaDeviceForUser", "DeleteProvisioningTenant", "DeleteUser", "DescribeDirectory", "DescribeGroups", "DescribeUsers", "DisableExternalIdPConfigurationForDirectory", "DisableUser", "EnableExternalIdPConfigurationForDirectory", "EnableUser", "GetAWSSPConfigurationForDirectory", "ListBearerTokens", "ListExternalIdPConfigurationsForDirectory", "ListGroupsForUser", "ListMembersInGroup", "ListMfaDevicesForUser", "ListProvisioningTenants", "RemoveMemberFromGroup", "SearchGroups", "SearchUsers", "StartVirtualMfaDeviceRegistration", "UpdateExternalIdPConfigurationForDirectory", "UpdateGroup", "UpdatePassword", "UpdateUser", "VerifyEmail"],
            "ARNFormat": "arn:${Partition}:sso-directory:${Region}:${Account}:<relative-id>",
            "ARNRegex": "^arn:${Partition}:sso-directory:${Region}:.+",
            "HasResource": false
        },
        "Amazon AppFlow": {
            "StringPrefix": "appflow",
            "Actions": ["CreateConnectorProfile", "CreateFlow", "DeleteConnectorProfile", "DeleteFlow", "DescribeConnectorFields", "DescribeConnectorProfiles", "DescribeConnectors", "DescribeFlowExecution", "DescribeFlows", "ListConnectorFields", "ListTagsForResource", "RunFlow", "TagResource", "UntagResource", "UpdateFlow"],
            "ARNFormat": "arn:aws:appflow:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:appflow:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Trusted Advisor": {
            "StringPrefix": "trustedadvisor",
            "Actions": ["DescribeAccount", "DescribeAccountAccess", "DescribeCheckItems", "DescribeCheckRefreshStatuses", "DescribeCheckSummaries", "DescribeChecks", "DescribeNotificationPreferences", "ExcludeCheckItems", "IncludeCheckItems", "RefreshCheck", "SetAccountAccess", "UpdateNotificationPreferences"],
            "ARNFormat": "arn:aws:trustedadvisor:*:<account_ID>:checks/{category}/{checkId}",
            "ARNRegex": "arn:aws:trustedadvisor:*",
            "HasResource": true
        },
        "AWS Config": {
            "StringPrefix": "config",
            "Actions": ["BatchGetAggregateResourceConfig", "BatchGetResourceConfig", "DeleteAggregationAuthorization", "DeleteConfigRule", "DeleteConfigurationAggregator", "DeleteConfigurationRecorder", "DeleteConformancePack", "DeleteDeliveryChannel", "DeleteEvaluationResults", "DeleteOrganizationConfigRule", "DeleteOrganizationConformancePack", "DeletePendingAggregationRequest", "DeleteRemediationConfiguration", "DeleteRemediationExceptions", "DeleteRetentionConfiguration", "DeliverConfigSnapshot", "DescribeAggregateComplianceByConfigRules", "DescribeAggregationAuthorizations", "DescribeComplianceByConfigRule", "DescribeComplianceByResource", "DescribeConfigRuleEvaluationStatus", "DescribeConfigRules", "DescribeConfigurationAggregatorSourcesStatus", "DescribeConfigurationAggregators", "DescribeConfigurationRecorderStatus", "DescribeConfigurationRecorders", "DescribeConformancePackCompliance", "DescribeConformancePackStatus", "DescribeConformancePacks", "DescribeDeliveryChannelStatus", "DescribeDeliveryChannels", "DescribeOrganizationConfigRuleStatuses", "DescribeOrganizationConfigRules", "DescribeOrganizationConformancePackStatuses", "DescribeOrganizationConformancePacks", "DescribePendingAggregationRequests", "DescribeRemediationConfigurations", "DescribeRemediationExceptions", "DescribeRemediationExecutionStatus", "DescribeRetentionConfigurations", "GetAggregateComplianceDetailsByConfigRule", "GetAggregateConfigRuleComplianceSummary", "GetAggregateDiscoveredResourceCounts", "GetAggregateResourceConfig", "GetComplianceDetailsByConfigRule", "GetComplianceDetailsByResource", "GetComplianceSummaryByConfigRule", "GetComplianceSummaryByResourceType", "GetConformancePackComplianceDetails", "GetConformancePackComplianceSummary", "GetDiscoveredResourceCounts", "GetOrganizationConfigRuleDetailedStatus", "GetOrganizationConformancePackDetailedStatus", "GetResourceConfigHistory", "GetResources", "GetTagKeys", "ListAggregateDiscoveredResources", "ListDiscoveredResources", "ListTagsForResource", "PutAggregationAuthorization", "PutConfigRule", "PutConfigurationAggregator", "PutConfigurationRecorder", "PutConformancePack", "PutDeliveryChannel", "PutEvaluations", "PutOrganizationConfigRule", "PutOrganizationConformancePack", "PutRemediationConfigurations", "PutRemediationExceptions", "PutRetentionConfiguration", "SelectResourceConfig", "StartConfigRulesEvaluation", "StartConfigurationRecorder", "StartRemediationExecution", "StopConfigurationRecorder", "TagResource", "UntagResource"],
            "ARNFormat": "arn:<partition>:config:<region>:<account>:<resourceType>/<resourceId>",
            "ARNRegex": "arn:<partition>:config:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon RDS": {
            "StringPrefix": "rds",
            "Actions": ["AddRoleToDBCluster", "AddRoleToDBInstance", "AddSourceIdentifierToSubscription", "AddTagsToResource", "ApplyPendingMaintenanceAction", "AuthorizeDBSecurityGroupIngress", "BacktrackDBCluster", "CancelExportTask", "CopyDBClusterParameterGroup", "CopyDBClusterSnapshot", "CopyDBParameterGroup", "CopyDBSnapshot", "CopyOptionGroup", "CreateDBCluster", "CreateDBClusterEndpoint", "CreateDBClusterParameterGroup", "CreateDBClusterSnapshot", "CreateDBInstance", "CreateDBInstanceReadReplica", "CreateDBParameterGroup", "CreateDBProxy", "CreateDBSecurityGroup", "CreateDBSnapshot", "CreateDBSubnetGroup", "CreateEventSubscription", "CreateGlobalCluster", "CreateOptionGroup", "DeleteDBCluster", "DeleteDBClusterEndpoint", "DeleteDBClusterParameterGroup", "DeleteDBClusterSnapshot", "DeleteDBInstance", "DeleteDBInstanceAutomatedBackup", "DeleteDBParameterGroup", "DeleteDBProxy", "DeleteDBSecurityGroup", "DeleteDBSnapshot", "DeleteDBSubnetGroup", "DeleteEventSubscription", "DeleteGlobalCluster", "DeleteOptionGroup", "DeregisterDBProxyTargets", "DescribeAccountAttributes", "DescribeCertificates", "DescribeDBClusterBacktracks", "DescribeDBClusterEndpoints", "DescribeDBClusterParameterGroups", "DescribeDBClusterParameters", "DescribeDBClusterSnapshotAttributes", "DescribeDBClusterSnapshots", "DescribeDBClusters", "DescribeDBEngineVersions", "DescribeDBInstanceAutomatedBackups", "DescribeDBInstances", "DescribeDBLogFiles", "DescribeDBParameterGroups", "DescribeDBParameters", "DescribeDBProxies", "DescribeDBProxyTargetGroups", "DescribeDBProxyTargets", "DescribeDBSecurityGroups", "DescribeDBSnapshotAttributes", "DescribeDBSnapshots", "DescribeDBSubnetGroups", "DescribeEngineDefaultClusterParameters", "DescribeEngineDefaultParameters", "DescribeEventCategories", "DescribeEventSubscriptions", "DescribeEvents", "DescribeExportTasks", "DescribeGlobalClusters", "DescribeOptionGroupOptions", "DescribeOptionGroups", "DescribeOrderableDBInstanceOptions", "DescribePendingMaintenanceActions", "DescribeReservedDBInstances", "DescribeReservedDBInstancesOfferings", "DescribeSourceRegions", "DescribeValidDBInstanceModifications", "DownloadCompleteDBLogFile", "DownloadDBLogFilePortion", "FailoverDBCluster", "ListTagsForResource", "ModifyCurrentDBClusterCapacity", "ModifyDBCluster", "ModifyDBClusterEndpoint", "ModifyDBClusterParameterGroup", "ModifyDBClusterSnapshotAttribute", "ModifyDBInstance", "ModifyDBParameterGroup", "ModifyDBProxy", "ModifyDBProxyTargetGroup", "ModifyDBSnapshot", "ModifyDBSnapshotAttribute", "ModifyDBSubnetGroup", "ModifyEventSubscription", "ModifyGlobalCluster", "ModifyOptionGroup", "PromoteReadReplica", "PromoteReadReplicaDBCluster", "PurchaseReservedDBInstancesOffering", "RebootDBInstance", "RegisterDBProxyTargets", "RemoveFromGlobalCluster", "RemoveRoleFromDBCluster", "RemoveRoleFromDBInstance", "RemoveSourceIdentifierFromSubscription", "RemoveTagsFromResource", "ResetDBClusterParameterGroup", "ResetDBParameterGroup", "RestoreDBClusterFromS3", "RestoreDBClusterFromSnapshot", "RestoreDBClusterToPointInTime", "RestoreDBInstanceFromDBSnapshot", "RestoreDBInstanceFromS3", "RestoreDBInstanceToPointInTime", "RevokeDBSecurityGroupIngress", "StartActivityStream", "StartDBCluster", "StartDBInstance", "StartExportTask", "StopActivityStream", "StopDBCluster", "StopDBInstance"],
            "ARNFormat": "arn:aws:rds:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:rds:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "rds:DatabaseClass", "rds:DatabaseEngine", "rds:DatabaseName", "rds:EndpointType", "rds:MultiAz", "rds:Piops", "rds:StorageEncrypted", "rds:StorageSize", "rds:Vpc", "rds:cluster-pg-tag/${TagKey}", "rds:cluster-snapshot-tag/${TagKey}", "rds:cluster-tag/${TagKey}", "rds:db-tag/${TagKey}", "rds:es-tag/${TagKey}", "rds:og-tag/${TagKey}", "rds:pg-tag/${TagKey}", "rds:req-tag/${TagKey}", "rds:ri-tag/${TagKey}", "rds:secgrp-tag/${TagKey}", "rds:snapshot-tag/${TagKey}", "rds:subgrp-tag/${TagKey}"],
            "HasResource": true
        },
        "Amazon Simple Workflow Service": {
            "StringPrefix": "swf",
            "Actions": ["CancelTimer", "CancelWorkflowExecution", "CompleteWorkflowExecution", "ContinueAsNewWorkflowExecution", "CountClosedWorkflowExecutions", "CountOpenWorkflowExecutions", "CountPendingActivityTasks", "CountPendingDecisionTasks", "DeprecateActivityType", "DeprecateDomain", "DeprecateWorkflowType", "DescribeActivityType", "DescribeDomain", "DescribeWorkflowExecution", "DescribeWorkflowType", "FailWorkflowExecution", "GetWorkflowExecutionHistory", "ListActivityTypes", "ListClosedWorkflowExecutions", "ListDomains", "ListOpenWorkflowExecutions", "ListTagsForResource", "ListWorkflowTypes", "PollForActivityTask", "PollForDecisionTask", "RecordActivityTaskHeartbeat", "RecordMarker", "RegisterActivityType", "RegisterDomain", "RegisterWorkflowType", "RequestCancelActivityTask", "RequestCancelExternalWorkflowExecution", "RequestCancelWorkflowExecution", "RespondActivityTaskCanceled", "RespondActivityTaskCompleted", "RespondActivityTaskFailed", "RespondDecisionTaskCompleted", "ScheduleActivityTask", "SignalExternalWorkflowExecution", "SignalWorkflowExecution", "StartChildWorkflowExecution", "StartTimer", "StartWorkflowExecution", "TagResource", "TerminateWorkflowExecution", "UntagResource"],
            "ARNFormat": "arn:aws:swf:<region>:<account>:/<domain>/<domainName>",
            "ARNRegex": "^arn:aws:swf:.+",
            "conditionKeys": [" swf:workflowType.name", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "swf:activityType.name", "swf:activityType.version", "swf:defaultTaskList.name", "swf:name", "swf:tagFilter.tag", "swf:tagList.member.0", "swf:tagList.member.1", "swf:tagList.member.2", "swf:tagList.member.3", "swf:tagList.member.4", "swf:taskList.name", "swf:typeFilter.name", "swf:typeFilter.version", "swf:version", "swf:workflowType.name", "swf:workflowType.version"],
            "HasResource": true
        },
        "Amazon Macie": {
            "StringPrefix": "macie",
            "Actions": ["AssociateMemberAccount", "AssociateS3Resources", "DisassociateMemberAccount", "DisassociateS3Resources", "ListMemberAccounts", "ListS3Resources", "UpdateS3Resources"],
            "conditionKeys": ["aws:SourceArn"],
            "HasResource": false
        },
        "AWS AppSync": {
            "StringPrefix": "appsync",
            "Actions": ["CreateApiKey", "CreateDataSource", "CreateFunction", "CreateGraphqlApi", "CreateResolver", "CreateType", "DeleteApiKey", "DeleteDataSource", "DeleteFunction", "DeleteGraphqlApi", "DeleteResolver", "DeleteType", "GetDataSource", "GetFunction", "GetGraphqlApi", "GetIntrospectionSchema", "GetResolver", "GetSchemaCreationStatus", "GetType", "GraphQL", "ListApiKeys", "ListDataSources", "ListFunctions", "ListGraphqlApis", "ListResolvers", "ListResolversByFunction", "ListTagsForResource", "ListTypes", "StartSchemaCreation", "TagResource", "UntagResource", "UpdateApiKey", "UpdateDataSource", "UpdateFunction", "UpdateGraphqlApi", "UpdateResolver", "UpdateType"],
            "ARNFormat": "arn:aws:appsync:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:appsync:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Certificate Manager": {
            "StringPrefix": "acm",
            "Actions": ["AddTagsToCertificate", "DeleteCertificate", "DescribeCertificate", "ExportCertificate", "GetCertificate", "ImportCertificate", "ListCertificates", "ListTagsForCertificate", "RemoveTagsFromCertificate", "RenewCertificate", "RequestCertificate", "ResendValidationEmail", "UpdateCertificateOptions"],
            "ARNFormat": "arn:aws:acm:<region>:<account_ID>:<arn_type>/<resource_id>",
            "ARNRegex": "^arn:aws:acm:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS X-Ray": {
            "StringPrefix": "xray",
            "Actions": ["BatchGetTraces", "CreateGroup", "CreateSamplingRule", "DeleteGroup", "DeleteSamplingRule", "GetEncryptionConfig", "GetGroup", "GetGroups", "GetSamplingRules", "GetSamplingStatisticSummaries", "GetSamplingTargets", "GetServiceGraph", "GetTimeSeriesServiceStatistics", "GetTraceGraph", "GetTraceSummaries", "PutEncryptionConfig", "PutTelemetryRecords", "PutTraceSegments", "UpdateGroup", "UpdateSamplingRule"],
            "ARNFormat": "arn:${Partition}:xray:${Region}:${Account}:${ResourceType}/${ResourceId}",
            "ARNRegex": "^arn:${Partition}:xray:.+",
            "HasResource": true
        },
        "Amazon CloudFront": {
            "StringPrefix": "cloudfront",
            "Actions": ["CreateCloudFrontOriginAccessIdentity", "CreateDistribution", "CreateDistributionWithTags", "CreateFieldLevelEncryptionConfig", "CreateFieldLevelEncryptionProfile", "CreateInvalidation", "CreatePublicKey", "CreateStreamingDistribution", "CreateStreamingDistributionWithTags", "DeleteCloudFrontOriginAccessIdentity", "DeleteDistribution", "DeleteFieldLevelEncryptionConfig", "DeleteFieldLevelEncryptionProfile", "DeletePublicKey", "DeleteStreamingDistribution", "GetCloudFrontOriginAccessIdentity", "GetCloudFrontOriginAccessIdentityConfig", "GetDistribution", "GetDistributionConfig", "GetFieldLevelEncryption", "GetFieldLevelEncryptionConfig", "GetFieldLevelEncryptionProfile", "GetFieldLevelEncryptionProfileConfig", "GetInvalidation", "GetPublicKey", "GetPublicKeyConfig", "GetStreamingDistribution", "GetStreamingDistributionConfig", "ListCloudFrontOriginAccessIdentities", "ListDistributions", "ListDistributionsByLambdaFunction", "ListDistributionsByWebACLId", "ListFieldLevelEncryptionConfigs", "ListFieldLevelEncryptionProfiles", "ListInvalidations", "ListPublicKeys", "ListStreamingDistributions", "ListTagsForResource", "TagResource", "UntagResource", "UpdateCloudFrontOriginAccessIdentity", "UpdateDistribution", "UpdateFieldLevelEncryptionConfig", "UpdateFieldLevelEncryptionProfile", "UpdatePublicKey", "UpdateStreamingDistribution"],
            "ARNFormat": "arn:${Partition}:cloudfront::<accountID>:<resource_type>/<resource_id>",
            "ARNRegex": "^arn:${Partition}:cloudfront::[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Elastic Container Service for Kubernetes": {
            "StringPrefix": "eks",
            "Actions": ["CreateCluster", "CreateFargateProfile", "CreateNodegroup", "DeleteCluster", "DeleteFargateProfile", "DeleteNodegroup", "DescribeCluster", "DescribeFargateProfile", "DescribeNodegroup", "DescribeUpdate", "ListClusters", "ListFargateProfiles", "ListNodegroups", "ListTagsForResource", "ListUpdates", "TagResource", "UntagResource", "UpdateClusterConfig", "UpdateClusterVersion", "UpdateNodegroupConfig", "UpdateNodegroupVersion"],
            "ARNFormat": "arn:aws:eks:<region>:<account_ID>:<resource_type>/<relative_ID>",
            "ARNRegex": "^arn:aws:eks:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Firewall Manager": {
            "StringPrefix": "fms",
            "Actions": ["AssociateAdminAccount", "DeleteNotificationChannel", "DeletePolicy", "DisassociateAdminAccount", "GetAdminAccount", "GetComplianceDetail", "GetNotificationChannel", "GetPolicy", "GetProtectionStatus", "ListComplianceStatus", "ListMemberAccounts", "ListPolicies", "ListTagsForResource", "PutNotificationChannel", "PutPolicy", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:fms:<region>:<account_id>:<resource>/<resource_id>",
            "ARNRegex": "^arn:aws:fms:.+:[0-9]+:.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Kinesis": {
            "StringPrefix": "kinesis",
            "Actions": ["AddTagsToStream", "CreateStream", "DecreaseStreamRetentionPeriod", "DeleteStream", "DeregisterStreamConsumer", "DescribeLimits", "DescribeStream", "DescribeStreamConsumer", "DescribeStreamSummary", "DisableEnhancedMonitoring", "EnableEnhancedMonitoring", "GetRecords", "GetShardIterator", "IncreaseStreamRetentionPeriod", "ListShards", "ListStreamConsumers", "ListStreams", "ListTagsForStream", "MergeShards", "PutRecord", "PutRecords", "RegisterStreamConsumer", "RemoveTagsFromStream", "SplitShard", "SubscribeToShard", "UpdateShardCount"],
            "ARNFormat": "arn:aws:kinesis:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:kinesis:.+",
            "HasResource": true
        },
        "AWS Billing": {
            "StringPrefix": "aws-portal",
            "Actions": ["ModifyAccount", "ModifyBilling", "ModifyPaymentMethods", "ViewAccount", "ViewBilling", "ViewPaymentMethods", "ViewUsage"],
            "HasResource": false
        },
        "AWS Directory Service": {
            "StringPrefix": "ds",
            "Actions": ["AcceptSharedDirectory", "AddIpRoutes", "AddTagsToResource", "AuthorizeApplication", "CancelSchemaExtension", "CheckAlias", "ConnectDirectory", "CreateAlias", "CreateComputer", "CreateConditionalForwarder", "CreateDirectory", "CreateIdentityPoolDirectory", "CreateLogSubscription", "CreateMicrosoftAD", "CreateSnapshot", "CreateTrust", "DeleteConditionalForwarder", "DeleteDirectory", "DeleteLogSubscription", "DeleteSnapshot", "DeleteTrust", "DeregisterCertificate", "DeregisterEventTopic", "DescribeCertificate", "DescribeConditionalForwarders", "DescribeDirectories", "DescribeDomainControllers", "DescribeEventTopics", "DescribeLDAPSSettings", "DescribeSharedDirectories", "DescribeSnapshots", "DescribeTrusts", "DisableLDAPS", "DisableRadius", "DisableSso", "EnableLDAPS", "EnableRadius", "EnableSso", "GetAuthorizedApplicationDetails", "GetDirectoryLimits", "GetSnapshotLimits", "ListAuthorizedApplications", "ListCertificates", "ListIpRoutes", "ListLogSubscriptions", "ListSchemaExtensions", "ListTagsForResource", "RegisterCertificate", "RegisterEventTopic", "RejectSharedDirectory", "RemoveIpRoutes", "RemoveTagsFromResource", "ResetUserPassword", "RestoreFromSnapshot", "ShareDirectory", "StartSchemaExtension", "UnauthorizeApplication", "UnshareDirectory", "UpdateConditionalForwarder", "UpdateNumberOfDomainControllers", "UpdateRadius", "UpdateTrust", "VerifyTrust"],
            "ARNFormat": "arn:<partition>:ds:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:<partition>:ds:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS IoT SiteWise": {
            "StringPrefix": "iotsitewise",
            "Actions": ["AssociateAssets", "BatchAssociateProjectAssets", "BatchDisassociateProjectAssets", "BatchPutAssetPropertyValue", "CreateAccessPolicy", "CreateAsset", "CreateAssetModel", "CreateDashboard", "CreateGateway", "CreatePortal", "CreateProject", "DeleteAccessPolicy", "DeleteAsset", "DeleteAssetModel", "DeleteDashboard", "DeleteGateway", "DeletePortal", "DeleteProject", "DescribeAccessPolicy", "DescribeAsset", "DescribeAssetModel", "DescribeAssetProperty", "DescribeDashboard", "DescribeGateway", "DescribeGatewayCapabilityConfiguration", "DescribeLoggingOptions", "DescribePortal", "DescribeProject", "DisassociateAssets", "GetAssetPropertyAggregates", "GetAssetPropertyValue", "GetAssetPropertyValueHistory", "ListAccessPolicies", "ListAssetModels", "ListAssets", "ListAssociatedAssets", "ListDashboards", "ListGateways", "ListPortals", "ListProjectAssets", "ListProjects", "ListTagsForResource", "PutLoggingOptions", "TagResource", "UntagResource", "UpdateAccessPolicy", "UpdateAsset", "UpdateAssetModel", "UpdateAssetProperty", "UpdateDashboard", "UpdateGateway", "UpdateGatewayCapabilityConfiguration", "UpdatePortal", "UpdateProject"],
            "ARNFormat": "arn:aws:iotsitewise:<region>:<account_ID>:<type>/<name>",
            "ARNRegex": "^arn:${Partition}:iotsitewise:.+-\\d+:\\d{12}:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "iotsitewise:assetHierarchyPath", "iotsitewise:childAssetId", "iotsitewise:group", "iotsitewise:portal", "iotsitewise:project", "iotsitewise:propertyId", "iotsitewise:user"],
            "HasResource": true
        },
        "AWS CodeStar Notifications": {
            "StringPrefix": "codestar-notifications",
            "Actions": ["CreateNotificationRule", "DeleteNotificationRule", "DeleteTarget", "DescribeNotificationRule", "ListEventTypes", "ListNotificationRules", "ListTagsForResource", "ListTargets", "Subscribe", "TagResource", "Unsubscribe", "UntagResource", "UpdateNotificationRule"],
            "ARNFormat": "arn:aws:codestar-notifications:<region>:<account-id>:<resource-type>/<resource_id>",
            "ARNRegex": "^arn:aws:codestar-notifications:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "codestar-notifications:NotificationsForResource"],
            "HasResource": true
        },
        "Amazon Fraud Detector": {
            "StringPrefix": "frauddetector",
            "Actions": ["BatchCreateVariable", "BatchGetVariable", "CreateDetectorVersion", "CreateModelVersion", "CreateRule", "CreateVariable", "DeleteDetector", "DeleteDetectorVersion", "DeleteEvent", "DeleteRuleVersion", "DescribeDetector", "DescribeModelVersions", "GetDetectorVersion", "GetDetectors", "GetExternalModels", "GetModelVersion", "GetModels", "GetOutcomes", "GetPrediction", "GetRules", "GetVariables", "PutDetector", "PutExternalModel", "PutModel", "PutOutcome", "UpdateDetectorVersion", "UpdateDetectorVersionMetadata", "UpdateDetectorVersionStatus", "UpdateModelVersion", "UpdateRuleMetadata", "UpdateRuleVersion", "UpdateVariable"],
            "ARNFormat": "arn:aws:frauddetector:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:frauddetector:.+:.+:.+",
            "HasResource": false
        },
        "Amazon WorkLink": {
            "StringPrefix": "worklink",
            "Actions": ["AssociateDomain", "AssociateWebsiteAuthorizationProvider", "AssociateWebsiteCertificateAuthority", "CreateFleet", "DeleteFleet", "DescribeAuditStreamConfiguration", "DescribeCompanyNetworkConfiguration", "DescribeDevice", "DescribeDevicePolicyConfiguration", "DescribeDomain", "DescribeFleetMetadata", "DescribeIdentityProviderConfiguration", "DescribeWebsiteCertificateAuthority", "DisassociateDomain", "DisassociateWebsiteAuthorizationProvider", "DisassociateWebsiteCertificateAuthority", "ListDevices", "ListDomains", "ListFleets", "ListWebsiteAuthorizationProviders", "ListWebsiteCertificateAuthorities", "RestoreDomainAccess", "RevokeDomainAccess", "SignOutUser", "UpdateAuditStreamConfiguration", "UpdateCompanyNetworkConfiguration", "UpdateDevicePolicyConfiguration", "UpdateDomainMetadata", "UpdateFleetMetadata", "UpdateIdentityProviderConfiguration"],
            "ARNFormat": "arn:${Partition}:worklink::${account}:${resourceType}/${resourcePath}",
            "ARNRegex": "^arn:${Partition}:worklink:.+",
            "HasResource": true
        },
        "AWS CodeStar Connections": {
            "StringPrefix": "codestar-connections",
            "Actions": ["CreateConnection", "DeleteConnection", "GetConnection", "GetIndividualAccessToken", "GetInstallationUrl", "ListConnections", "ListInstallationTargets", "ListTagsForResource", "PassConnection", "StartOAuthHandshake", "TagResource", "UntagResource", "UpdateConnectionInstallation", "UseConnection"],
            "ARNFormat": "arn:aws:codestar-connections:<region>:<account-id>:<resource-type>/<resource_id>",
            "ARNRegex": "^arn:aws:codestar-connections:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "codestar-connections:BranchName", "codestar-connections:FullRepositoryId", "codestar-connections:InstallationId", "codestar-connections:OwnerId", "codestar-connections:PassedToService", "codestar-connections:ProviderAction", "codestar-connections:ProviderPermissionsRequired", "codestar-connections:ProviderType", "codestar-connections:ProviderTypeFilter", "codestar-connections:RepositoryName"],
            "HasResource": true
        },
        "Amazon WorkSpaces": {
            "StringPrefix": "workspaces",
            "Actions": ["AssociateIpGroups", "AuthorizeIpRules", "CreateIpGroup", "CreateTags", "CreateWorkspaces", "DeleteIpGroup", "DeleteTags", "DeleteWorkspaceImage", "DescribeAccount", "DescribeAccountModifications", "DescribeClientProperties", "DescribeIpGroups", "DescribeTags", "DescribeWorkspaceBundles", "DescribeWorkspaceDirectories", "DescribeWorkspaceImages", "DescribeWorkspaces", "DescribeWorkspacesConnectionStatus", "DisassociateIpGroups", "ImportWorkspaceImage", "ListAvailableManagementCidrRanges", "ModifyAccount", "ModifyClientProperties", "ModifyWorkspaceProperties", "ModifyWorkspaceState", "RebootWorkspaces", "RebuildWorkspaces", "RevokeIpRules", "StartWorkspaces", "StopWorkspaces", "TerminateWorkspaces", "UpdateRulesOfIpGroup"],
            "ARNFormat": "arn:aws:workspaces:*:*",
            "ARNRegex": "arn:aws:workspaces:*",
            "HasResource": true
        },
        "Amazon Chime": {
            "StringPrefix": "chime",
            "Actions": ["AcceptDelegate", "ActivateUsers", "AddDomain", "AddOrUpdateGroups", "AssociatePhoneNumberWithUser", "AssociatePhoneNumbersWithVoiceConnector", "AssociatePhoneNumbersWithVoiceConnectorGroup", "AssociateSigninDelegateGroupsWithAccount", "AuthorizeDirectory", "BatchCreateAttendee", "BatchCreateRoomMembership", "BatchDeletePhoneNumber", "BatchSuspendUser", "BatchUnsuspendUser", "BatchUpdatePhoneNumber", "BatchUpdateUser", "ConnectDirectory", "CreateAccount", "CreateApiKey", "CreateAttendee", "CreateBot", "CreateBotMembership", "CreateCDRBucket", "CreateMeeting", "CreatePhoneNumberOrder", "CreateProxySession", "CreateRoom", "CreateRoomMembership", "CreateUser", "CreateVoiceConnector", "CreateVoiceConnectorGroup", "DeleteAccount", "DeleteAccountOpenIdConfig", "DeleteApiKey", "DeleteAttendee", "DeleteCDRBucket", "DeleteDelegate", "DeleteDomain", "DeleteEventsConfiguration", "DeleteGroups", "DeleteMeeting", "DeletePhoneNumber", "DeleteProxySession", "DeleteRoom", "DeleteRoomMembership", "DeleteVoiceConnector", "DeleteVoiceConnectorGroup", "DeleteVoiceConnectorOrigination", "DeleteVoiceConnectorProxy", "DeleteVoiceConnectorStreamingConfiguration", "DeleteVoiceConnectorTermination", "DeleteVoiceConnectorTerminationCredentials", "DisassociatePhoneNumberFromUser", "DisassociatePhoneNumbersFromVoiceConnector", "DisassociatePhoneNumbersFromVoiceConnectorGroup", "DisassociateSigninDelegateGroupsFromAccount", "DisconnectDirectory", "GetAccount", "GetAccountResource", "GetAccountSettings", "GetAccountWithOpenIdConfig", "GetAttendee", "GetBot", "GetCDRBucket", "GetDomain", "GetEventsConfiguration", "GetGlobalSettings", "GetMeeting", "GetMeetingDetail", "GetPhoneNumber", "GetPhoneNumberOrder", "GetPhoneNumberSettings", "GetProxySession", "GetRoom", "GetTelephonyLimits", "GetUser", "GetUserActivityReportData", "GetUserByEmail", "GetUserSettings", "GetVoiceConnector", "GetVoiceConnectorGroup", "GetVoiceConnectorLoggingConfiguration", "GetVoiceConnectorOrigination", "GetVoiceConnectorProxy", "GetVoiceConnectorStreamingConfiguration", "GetVoiceConnectorTermination", "GetVoiceConnectorTerminationHealth", "InviteDelegate", "InviteUsers", "InviteUsersFromProvider", "ListAccountUsageReportData", "ListAccounts", "ListApiKeys", "ListAttendeeTags", "ListAttendees", "ListBots", "ListCDRBucket", "ListCallingRegions", "ListDelegates", "ListDirectories", "ListDomains", "ListGroups", "ListMeetingEvents", "ListMeetingTags", "ListMeetings", "ListMeetingsReportData", "ListPhoneNumberOrders", "ListPhoneNumbers", "ListProxySessions", "ListRoomMemberships", "ListRooms", "ListTagsForResource", "ListUsers", "ListVoiceConnectorGroups", "ListVoiceConnectorTerminationCredentials", "ListVoiceConnectors", "LogoutUser", "PutEventsConfiguration", "PutVoiceConnectorLoggingConfiguration", "PutVoiceConnectorOrigination", "PutVoiceConnectorProxy", "PutVoiceConnectorStreamingConfiguration", "PutVoiceConnectorTermination", "PutVoiceConnectorTerminationCredentials", "RegenerateSecurityToken", "RenameAccount", "RenewDelegate", "ResetAccountResource", "ResetPersonalPIN", "RestorePhoneNumber", "RetrieveDataExports", "SearchAvailablePhoneNumbers", "StartDataExport", "SubmitSupportRequest", "SuspendUsers", "TagAttendee", "TagMeeting", "TagResource", "UnauthorizeDirectory", "UntagAttendee", "UntagMeeting", "UntagResource", "UpdateAccount", "UpdateAccountOpenIdConfig", "UpdateAccountResource", "UpdateAccountSettings", "UpdateBot", "UpdateCDRSettings", "UpdateGlobalSettings", "UpdatePhoneNumber", "UpdatePhoneNumberSettings", "UpdateProxySession", "UpdateRoom", "UpdateRoomMembership", "UpdateSupportedLicenses", "UpdateUser", "UpdateUserLicenses", "UpdateUserSettings", "UpdateVoiceConnector", "UpdateVoiceConnectorGroup", "ValidateAccountResource"],
            "ARNFormat": "arn:aws:chime::<accountId>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:chime:.+",
            "HasResource": true
        },
        "Amazon ElastiCache": {
            "StringPrefix": "elasticache",
            "Actions": ["AddTagsToResource", "AuthorizeCacheSecurityGroupIngress", "CopySnapshot", "CreateCacheCluster", "CreateCacheParameterGroup", "CreateCacheSecurityGroup", "CreateCacheSubnetGroup", "CreateReplicationGroup", "CreateSnapshot", "DecreaseReplicaCount", "DeleteCacheCluster", "DeleteCacheParameterGroup", "DeleteCacheSecurityGroup", "DeleteCacheSubnetGroup", "DeleteReplicationGroup", "DeleteSnapshot", "DescribeCacheClusters", "DescribeCacheEngineVersions", "DescribeCacheParameterGroups", "DescribeCacheParameters", "DescribeCacheSecurityGroups", "DescribeCacheSubnetGroups", "DescribeEngineDefaultParameters", "DescribeEvents", "DescribeReplicationGroups", "DescribeReservedCacheNodes", "DescribeReservedCacheNodesOfferings", "DescribeSnapshots", "IncreaseReplicaCount", "ListAllowedNodeTypeModifications", "ListTagsForResource", "ModifyCacheCluster", "ModifyCacheParameterGroup", "ModifyCacheSubnetGroup", "ModifyReplicationGroup", "ModifyReplicationGroupShardConfiguration", "PurchaseReservedCacheNodesOffering", "RebootCacheCluster", "RemoveTagsFromResource", "ResetCacheParameterGroup", "RevokeCacheSecurityGroupIngress", "TestFailover"],
            "HasResource": false
        },
        "Amazon Kinesis Firehose": {
            "StringPrefix": "firehose",
            "Actions": ["CreateDeliveryStream", "DeleteDeliveryStream", "DescribeDeliveryStream", "ListDeliveryStreams", "ListTagsForDeliveryStream", "PutRecord", "PutRecordBatch", "StartDeliveryStreamEncryption", "StopDeliveryStreamEncryption", "TagDeliveryStream", "UntagDeliveryStream", "UpdateDestination"],
            "ARNFormat": "arn:aws:firehose:<region>:<account_ID>:deliverystream/<deliverystreamname>",
            "ARNRegex": "^arn:aws:firehose:.+:[0-9]+:deliverystream/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Mechanical Turk": {
            "StringPrefix": "mechanicalturk",
            "Actions": ["AcceptQualificationRequest", "ApproveAssignment", "AssociateQualificationWithWorker", "CreateAdditionalAssignmentsForHIT", "CreateHIT", "CreateHITType", "CreateHITWithHITType", "CreateQualificationType", "CreateWorkerBlock", "DeleteHIT", "DeleteQualificationType", "DeleteWorkerBlock", "DisassociateQualificationFromWorker", "GetAccountBalance", "GetAssignment", "GetFileUploadURL", "GetHIT", "GetQualificationScore", "GetQualificationType", "ListAssignmentsForHIT", "ListBonusPayments", "ListHITs", "ListHITsForQualificationType", "ListQualificationRequests", "ListQualificationTypes", "ListReviewPolicyResultsForHIT", "ListReviewableHITs", "ListWorkerBlocks", "ListWorkersWithQualificationType", "NotifyWorkers", "RejectAssignment", "RejectQualificationRequest", "SendBonus", "SendTestEventNotification", "UpdateExpirationForHIT", "UpdateHITReviewStatus", "UpdateHITTypeOfHIT", "UpdateNotificationSettings", "UpdateQualificationType"],
            "HasResource": false
        },
        "Amazon Storage Gateway": {
            "StringPrefix": "storagegateway",
            "Actions": ["ActivateGateway", "AddCache", "AddTagsToResource", "AddUploadBuffer", "AddWorkingStorage", "AttachVolume", "CancelArchival", "CancelRetrieval", "CreateCachediSCSIVolume", "CreateNFSFileShare", "CreateSMBFileShare", "CreateSnapshot", "CreateSnapshotFromVolumeRecoveryPoint", "CreateStorediSCSIVolume", "CreateTapeWithBarcode", "CreateTapes", "DeleteBandwidthRateLimit", "DeleteChapCredentials", "DeleteFileShare", "DeleteGateway", "DeleteSnapshotSchedule", "DeleteTape", "DeleteTapeArchive", "DeleteVolume", "DescribeBandwidthRateLimit", "DescribeCache", "DescribeCachediSCSIVolumes", "DescribeChapCredentials", "DescribeGatewayInformation", "DescribeMaintenanceStartTime", "DescribeNFSFileShares", "DescribeSMBFileShares", "DescribeSMBSettings", "DescribeSnapshotSchedule", "DescribeStorediSCSIVolumes", "DescribeTapeArchives", "DescribeTapeRecoveryPoints", "DescribeTapes", "DescribeUploadBuffer", "DescribeVTLDevices", "DescribeWorkingStorage", "DetachVolume", "DisableGateway", "JoinDomain", "ListFileShares", "ListGateways", "ListLocalDisks", "ListTagsForResource", "ListTapes", "ListVolumeInitiators", "ListVolumeRecoveryPoints", "ListVolumes", "NotifyWhenUploaded", "RefreshCache", "RemoveTagsFromResource", "ResetCache", "RetrieveTapeArchive", "RetrieveTapeRecoveryPoint", "SetLocalConsolePassword", "SetSMBGuestPassword", "ShutdownGateway", "StartGateway", "UpdateBandwidthRateLimit", "UpdateChapCredentials", "UpdateGatewayInformation", "UpdateGatewaySoftwareNow", "UpdateMaintenanceStartTime", "UpdateNFSFileShare", "UpdateSMBFileShare", "UpdateSnapshotSchedule", "UpdateVTLDeviceType"],
            "ARNFormat": "arn:aws:storagegateway:us-east-1:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:storagegateway:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Elastic MapReduce": {
            "StringPrefix": "elasticmapreduce",
            "Actions": ["AddInstanceFleet", "AddInstanceGroups", "AddJobFlowSteps", "AddTags", "CancelSteps", "CreateEditor", "CreateSecurityConfiguration", "DeleteEditor", "DeleteSecurityConfiguration", "DescribeCluster", "DescribeEditor", "DescribeJobFlows", "DescribeSecurityConfiguration", "DescribeStep", "GetBlockPublicAccessConfiguration", "ListBootstrapActions", "ListClusters", "ListEditors", "ListInstanceFleets", "ListInstanceGroups", "ListInstances", "ListSecurityConfigurations", "ListSteps", "ModifyCluster", "ModifyInstanceFleet", "ModifyInstanceGroups", "OpenEditorInConsole", "PutAutoScalingPolicy", "PutBlockPublicAccessConfiguration", "RemoveAutoScalingPolicy", "RemoveTags", "RunJobFlow", "SetTerminationProtection", "StartEditor", "StopEditor", "TerminateJobFlows", "ViewEventsFromAllClustersInConsole"],
            "ARNFormat": "arn:aws:elasticmapreduce:<region>:<account>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:elasticmapreduce:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "elasticmapreduce:RequestTag/${TagKey}", "elasticmapreduce:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "AWS Batch": {
            "StringPrefix": "batch",
            "Actions": ["CancelJob", "CreateComputeEnvironment", "CreateJobQueue", "DeleteComputeEnvironment", "DeleteJobQueue", "DeregisterJobDefinition", "DescribeComputeEnvironments", "DescribeJobDefinitions", "DescribeJobQueues", "DescribeJobs", "ListJobs", "RegisterJobDefinition", "SubmitJob", "TerminateJob", "UpdateComputeEnvironment", "UpdateJobQueue"],
            "ARNFormat": "arn:aws:batch:<region>:<account_ID>:<resource_type>/<relative_ID>",
            "ARNRegex": "^arn:aws:batch:.+",
            "conditionKeys": ["batch:Image", "batch:Privileged", "batch:User"],
            "HasResource": true
        },
        "AWS IoT Events": {
            "StringPrefix": "iotevents",
            "Actions": ["BatchPutMessage", "BatchUpdateDetector", "CreateDetectorModel", "CreateInput", "DeleteDetectorModel", "DeleteInput", "DescribeDetector", "DescribeDetectorModel", "DescribeInput", "DescribeLoggingOptions", "ListDetectorModelVersions", "ListDetectorModels", "ListDetectors", "ListInputs", "ListTagsForResource", "PutLoggingOptions", "TagResource", "UntagResource", "UpdateDetectorModel", "UpdateInput", "UpdateInputRouting"],
            "ARNFormat": "arn:aws:iotevents:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:iotevents:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS CloudTrail": {
            "StringPrefix": "cloudtrail",
            "Actions": ["AddTags", "CreateTrail", "DeleteTrail", "DescribeTrails", "GetEventSelectors", "GetInsightSelectors", "GetTrail", "GetTrailStatus", "ListPublicKeys", "ListTags", "ListTrails", "LookupEvents", "PutEventSelectors", "PutInsightSelectors", "RemoveTags", "StartLogging", "StopLogging", "UpdateTrail"],
            "ARNFormat": "arn:aws:cloudtrail:<region>:<account>:<resource>",
            "ARNRegex": "^arn:aws:cloudtrail:.+:[0-9]+:.+",
            "HasResource": true
        },
        "Amazon DynamoDB": {
            "StringPrefix": "dynamodb",
            "Actions": ["BatchGetItem", "BatchWriteItem", "ConditionCheckItem", "CreateBackup", "CreateGlobalTable", "CreateTable", "CreateTableReplica", "DeleteBackup", "DeleteItem", "DeleteTable", "DeleteTableReplica", "DescribeBackup", "DescribeContinuousBackups", "DescribeContributorInsights", "DescribeGlobalTable", "DescribeGlobalTableSettings", "DescribeLimits", "DescribeReservedCapacity", "DescribeReservedCapacityOfferings", "DescribeStream", "DescribeTable", "DescribeTableReplicaAutoScaling", "DescribeTimeToLive", "GetItem", "GetRecords", "GetShardIterator", "ListBackups", "ListContributorInsights", "ListGlobalTables", "ListStreams", "ListTables", "ListTagsOfResource", "PurchaseReservedCapacityOfferings", "PutItem", "Query", "RestoreTableFromBackup", "RestoreTableToPointInTime", "Scan", "TagResource", "UntagResource", "UpdateContinuousBackups", "UpdateContributorInsights", "UpdateGlobalTable", "UpdateGlobalTableSettings", "UpdateItem", "UpdateTable", "UpdateTableReplicaAutoScaling", "UpdateTimeToLive"],
            "ARNFormat": "arn:aws:dynamodb:<region>:<accountID>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:dynamodb:.+:.+",
            "conditionKeys": ["dynamodb:Attributes", "dynamodb:EnclosingOperation", "dynamodb:LeadingKeys", "dynamodb:ReturnConsumedCapacity", "dynamodb:ReturnValues", "dynamodb:Select"],
            "HasResource": true
        },
        "Amazon Elasticsearch Service": {
            "StringPrefix": "es",
            "Actions": ["AddTags", "CreateElasticsearchDomain", "CreateElasticsearchServiceRole", "DeleteElasticsearchDomain", "DeleteElasticsearchServiceRole", "DescribeElasticsearchDomain", "DescribeElasticsearchDomainConfig", "DescribeElasticsearchDomains", "DescribeElasticsearchInstanceTypeLimits", "DescribeReservedElasticsearchInstanceOfferings", "DescribeReservedElasticsearchInstances", "ESHttpDelete", "ESHttpGet", "ESHttpHead", "ESHttpPatch", "ESHttpPost", "ESHttpPut", "GetCompatibleElasticsearchVersions", "GetUpgradeHistory", "GetUpgradeStatus", "ListDomainNames", "ListElasticsearchInstanceTypeDetails", "ListElasticsearchInstanceTypes", "ListElasticsearchVersions", "ListTags", "PurchaseReservedElasticsearchInstanceOffering", "RemoveTags", "UpdateElasticsearchDomainConfig", "UpgradeElasticsearchDomain"],
            "ARNFormat": "arn:aws:es:<region>:<account_ID>:<resource>",
            "ARNRegex": "^arn:aws:es:.+",
            "HasResource": true
        },
        "AWS DeepRacer": {
            "StringPrefix": "deepracer",
            "Actions": ["CloneReinforcementLearningModel", "CreateAccountResources", "CreateLeaderboardSubmission", "CreateReinforcementLearningModel", "DeleteAccountResources", "DeleteModel", "GetAccountResources", "GetAlias", "GetEvaluation", "GetLatestUserSubmission", "GetLeaderboard", "GetModel", "GetRankedUserSubmission", "GetTrack", "GetTrainingJob", "ListEvaluations", "ListLeaderboardSubmissions", "ListLeaderboards", "ListModels", "ListTracks", "ListTrainingJobs", "SetAlias", "StartEvaluation", "StopEvaluation", "StopTrainingReinforcementLearningModel", "TestRewardFunction"],
            "ARNFormat": "arn:aws:deepracer:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:deepracer:.+",
            "HasResource": true
        },
        "AWS Budget Service": {
            "StringPrefix": "budgets",
            "Actions": ["ModifyBudget", "ViewBudget"],
            "ARNFormat": "arn:aws:budgets::<account_ID>:budget/<budgetname>",
            "ARNRegex": "^arn:aws:budgets::.+:.+",
            "HasResource": true
        },
        "Amazon EventBridge Schemas": {
            "StringPrefix": "schemas",
            "Actions": ["CreateDiscoverer", "CreateRegistry", "CreateSchema", "DeleteDiscoverer", "DeleteRegistry", "DeleteResourcePolicy", "DeleteSchema", "DeleteSchemaVersion", "DescribeCodeBinding", "DescribeDiscoverer", "DescribeRegistry", "DescribeSchema", "GetCodeBindingSource", "GetDiscoveredSchema", "GetResourcePolicy", "ListDiscoverers", "ListRegistries", "ListSchemaVersions", "ListSchemas", "ListTagsForResource", "PutCodeBinding", "PutResourcePolicy", "SearchSchemas", "StartDiscoverer", "StopDiscoverer", "TagResource", "UntagResource", "UpdateDiscoverer", "UpdateRegistry", "UpdateSchema"],
            "ARNFormat": "arn:aws:schemas:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:${Partition}:schemas:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Network Manager": {
            "StringPrefix": "networkmanager",
            "Actions": ["AssociateCustomerGateway", "AssociateLink", "CreateDevice", "CreateGlobalNetwork", "CreateLink", "CreateSite", "DeleteDevice", "DeleteGlobalNetwork", "DeleteLink", "DeleteSite", "DeregisterTransitGateway", "DescribeGlobalNetworks", "DisassociateCustomerGateway", "DisassociateLink", "GetCustomerGatewayAssociations", "GetDevices", "GetLinkAssociations", "GetLinks", "GetSites", "GetTransitGatewayRegistrations", "ListTagsForResource", "RegisterTransitGateway", "TagResource", "UntagResource", "UpdateDevice", "UpdateGlobalNetwork", "UpdateLink", "UpdateSite"],
            "ARNFormat": "arn:aws:networkmanager::<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:networkmanager::.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "networkmanager:cgwArn", "networkmanager:tgwArn"],
            "HasResource": true
        },
        "AWS Support": {
            "StringPrefix": "support",
            "Actions": ["AddAttachmentsToSet", "AddCommunicationToCase", "CreateCase", "DescribeAttachment", "DescribeCaseAttributes", "DescribeCases", "DescribeCommunications", "DescribeIssueTypes", "DescribeServices", "DescribeSeverityLevels", "DescribeSupportLevel", "DescribeTrustedAdvisorCheckRefreshStatuses", "DescribeTrustedAdvisorCheckResult", "DescribeTrustedAdvisorCheckSummaries", "DescribeTrustedAdvisorChecks", "InitiateCallForCase", "InitiateChatForCase", "PutCaseAttributes", "RateCaseCommunication", "RefreshTrustedAdvisorCheck", "ResolveCase", "SearchForCases"],
            "HasResource": false
        },
        "Amazon Cognito Identity": {
            "StringPrefix": "cognito-identity",
            "Actions": ["CreateIdentityPool", "DeleteIdentities", "DeleteIdentityPool", "DescribeIdentity", "DescribeIdentityPool", "GetCredentialsForIdentity", "GetId", "GetIdentityPoolRoles", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity", "ListIdentities", "ListIdentityPools", "ListTagsForResource", "LookupDeveloperIdentity", "MergeDeveloperIdentities", "SetIdentityPoolRoles", "TagResource", "UnlinkDeveloperIdentity", "UnlinkIdentity", "UntagResource", "UpdateIdentityPool"],
            "ARNFormat": "arn:aws:cognito-identity:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:cognito-identity:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Polly": {
            "StringPrefix": "polly",
            "Actions": ["DeleteLexicon", "DescribeVoices", "GetLexicon", "GetSpeechSynthesisTask", "ListLexicons", "ListSpeechSynthesisTasks", "PutLexicon", "StartSpeechSynthesisTask", "SynthesizeSpeech"],
            "ARNFormat": "arn:aws:polly:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:polly::.+",
            "HasResource": true
        },
        "AWS AppConfig": {
            "StringPrefix": "appconfig",
            "Actions": ["CreateApplication", "CreateConfigurationProfile", "CreateDeploymentStrategy", "CreateEnvironment", "DeleteApplication", "DeleteConfigurationProfile", "DeleteDeploymentStrategy", "DeleteEnvironment", "GetApplication", "GetConfiguration", "GetConfigurationProfile", "GetDeployment", "GetDeploymentStrategy", "GetEnvironment", "ListApplications", "ListConfigurationProfiles", "ListDeploymentStrategies", "ListDeployments", "ListEnvironments", "ListTagsForResource", "StartDeployment", "StopDeployment", "TagResource", "UntagResource", "UpdateApplication", "UpdateConfigurationProfile", "UpdateDeploymentStrategy", "UpdateEnvironment", "ValidateConfiguration"],
            "ARNFormat": "arn:aws:appconfig:<region>:<account-id>:<relative-id>",
            "ARNRegex": "^arn:aws:appconfig:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS License Manager": {
            "StringPrefix": "license-manager",
            "Actions": ["CreateLicenseConfiguration", "DeleteLicenseConfiguration", "GetLicenseConfiguration", "GetServiceSettings", "ListAssociationsForLicenseConfiguration", "ListLicenseConfigurations", "ListLicenseSpecificationsForResource", "ListResourceInventory", "ListTagsForResource", "ListUsageForLicenseConfiguration", "TagResource", "UntagResource", "UpdateLicenseConfiguration", "UpdateLicenseSpecificationsForResource", "UpdateServiceSettings"],
            "ARNFormat": "arn:aws:license-manager:<region>:<account-id>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:license-manager:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:TagKeys", "license-manager:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "Alexa for Business": {
            "StringPrefix": "a4b",
            "Actions": ["ApproveSkill", "AssociateContactWithAddressBook", "AssociateDeviceWithRoom", "AssociateSkillGroupWithRoom", "AssociateSkillWithSkillGroup", "AssociateSkillWithUsers", "CompleteRegistration", "CreateAddressBook", "CreateBusinessReportSchedule", "CreateConferenceProvider", "CreateContact", "CreateProfile", "CreateRoom", "CreateSkillGroup", "CreateUser", "DeleteAddressBook", "DeleteBusinessReportSchedule", "DeleteConferenceProvider", "DeleteContact", "DeleteDevice", "DeleteProfile", "DeleteRoom", "DeleteRoomSkillParameter", "DeleteSkillAuthorization", "DeleteSkillGroup", "DeleteUser", "DisassociateContactFromAddressBook", "DisassociateDeviceFromRoom", "DisassociateSkillFromSkillGroup", "DisassociateSkillFromUsers", "DisassociateSkillGroupFromRoom", "ForgetSmartHomeAppliances", "GetAddressBook", "GetConferencePreference", "GetConferenceProvider", "GetContact", "GetDevice", "GetNetworkProfile", "GetProfile", "GetRoom", "GetRoomSkillParameter", "GetSkillGroup", "ListBusinessReportSchedules", "ListConferenceProviders", "ListDeviceEvents", "ListSkills", "ListSkillsStoreCategories", "ListSkillsStoreSkillsByCategory", "ListSmartHomeAppliances", "ListTags", "PutConferencePreference", "PutDeviceSetupEvents", "PutRoomSkillParameter", "PutSkillAuthorization", "RegisterAVSDevice", "RegisterDevice", "RejectSkill", "ResolveRoom", "RevokeInvitation", "SearchAddressBooks", "SearchContacts", "SearchDevices", "SearchNetworkProfiles", "SearchProfiles", "SearchRooms", "SearchSkillGroups", "SearchUsers", "SendInvitation", "StartDeviceSync", "StartSmartHomeApplianceDiscovery", "TagResource", "UntagResource", "UpdateAddressBook", "UpdateBusinessReportSchedule", "UpdateConferenceProvider", "UpdateContact", "UpdateDevice", "UpdateProfile", "UpdateRoom", "UpdateSkillGroup"],
            "ARNFormat": "arn:aws:a4b:<region>:<account-id>:<resource-type>/<resource_id>",
            "ARNRegex": "^arn:aws:a4b:.+:.+:.+",
            "conditionKeys": ["a4b:amazonId", "a4b:filters_deviceType", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Certificate Manager Private Certificate Authority": {
            "StringPrefix": "acm-pca",
            "Actions": ["CreateCertificateAuthority", "CreateCertificateAuthorityAuditReport", "CreatePermission", "DeleteCertificateAuthority", "DeletePermission", "DescribeCertificateAuthority", "DescribeCertificateAuthorityAuditReport", "GetCertificate", "GetCertificateAuthorityCertificate", "GetCertificateAuthorityCsr", "ImportCertificateAuthorityCertificate", "IssueCertificate", "ListCertificateAuthorities", "ListPermissions", "ListTags", "RestoreCertificateAuthority", "RevokeCertificate", "TagCertificateAuthority", "UntagCertificateAuthority", "UpdateCertificateAuthority"],
            "ARNFormat": "arn:aws:acm-pca:<region>:<account_ID>:<arn_type>/<resource_id>",
            "ARNRegex": "^arn:aws:acm-pca:.+:[0-9]+:.+",
            "conditionKeys": ["acm-pca:TemplateArn", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Step Functions": {
            "StringPrefix": "states",
            "Actions": ["CreateActivity", "CreateStateMachine", "DeleteActivity", "DeleteStateMachine", "DescribeActivity", "DescribeExecution", "DescribeStateMachine", "DescribeStateMachineForExecution", "GetActivityTask", "GetExecutionHistory", "ListActivities", "ListExecutions", "ListStateMachines", "ListTagsForResource", "SendTaskFailure", "SendTaskHeartbeat", "SendTaskSuccess", "StartExecution", "StopExecution", "TagResource", "UntagResource", "UpdateStateMachine"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account>:<resourceType>:<resourceName>",
            "ARNRegex": "^arn:aws:states:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Message Delivery Service": {
            "StringPrefix": "ec2messages",
            "Actions": ["AcknowledgeMessage", "DeleteMessage", "FailMessage", "GetEndpoint", "GetMessages", "SendReply"],
            "HasResource": false
        },
        "AWS IoT Greengrass": {
            "StringPrefix": "greengrass",
            "Actions": ["AssociateRoleToGroup", "AssociateServiceRoleToAccount", "CreateConnectorDefinition", "CreateConnectorDefinitionVersion", "CreateCoreDefinition", "CreateCoreDefinitionVersion", "CreateDeployment", "CreateDeviceDefinition", "CreateDeviceDefinitionVersion", "CreateFunctionDefinition", "CreateFunctionDefinitionVersion", "CreateGroup", "CreateGroupCertificateAuthority", "CreateGroupVersion", "CreateLoggerDefinition", "CreateLoggerDefinitionVersion", "CreateResourceDefinition", "CreateResourceDefinitionVersion", "CreateSoftwareUpdateJob", "CreateSubscriptionDefinition", "CreateSubscriptionDefinitionVersion", "DeleteConnectorDefinition", "DeleteCoreDefinition", "DeleteDeviceDefinition", "DeleteFunctionDefinition", "DeleteGroup", "DeleteLoggerDefinition", "DeleteResourceDefinition", "DeleteSubscriptionDefinition", "DisassociateRoleFromGroup", "DisassociateServiceRoleFromAccount", "GetAssociatedRole", "GetBulkDeploymentStatus", "GetConnectivityInfo", "GetConnectorDefinition", "GetConnectorDefinitionVersion", "GetCoreDefinition", "GetCoreDefinitionVersion", "GetDeploymentStatus", "GetDeviceDefinition", "GetDeviceDefinitionVersion", "GetFunctionDefinition", "GetFunctionDefinitionVersion", "GetGroup", "GetGroupCertificateAuthority", "GetGroupCertificateConfiguration", "GetGroupVersion", "GetLoggerDefinition", "GetLoggerDefinitionVersion", "GetResourceDefinition", "GetResourceDefinitionVersion", "GetServiceRoleForAccount", "GetSubscriptionDefinition", "GetSubscriptionDefinitionVersion", "ListBulkDeploymentDetailedReports", "ListBulkDeployments", "ListConnectorDefinitionVersions", "ListConnectorDefinitions", "ListCoreDefinitionVersions", "ListCoreDefinitions", "ListDeployments", "ListDeviceDefinitionVersions", "ListDeviceDefinitions", "ListFunctionDefinitionVersions", "ListFunctionDefinitions", "ListGroupCertificateAuthorities", "ListGroupVersions", "ListGroups", "ListLoggerDefinitionVersions", "ListLoggerDefinitions", "ListResourceDefinitionVersions", "ListResourceDefinitions", "ListSubscriptionDefinitionVersions", "ListSubscriptionDefinitions", "ListTagsForResource", "ResetDeployments", "StartBulkDeployment", "StopBulkDeployment", "TagResource", "UntagResource", "UpdateConnectivityInfo", "UpdateConnectorDefinition", "UpdateCoreDefinition", "UpdateDeviceDefinition", "UpdateFunctionDefinition", "UpdateGroup", "UpdateGroupCertificateConfiguration", "UpdateLoggerDefinition", "UpdateResourceDefinition", "UpdateSubscriptionDefinition"],
            "ARNFormat": "arn:${Partition}:greengrass:${Region}:${Account}:/greengrass/${resourceType}/${resourcePath}",
            "ARNRegex": "^arn:${Partition}:greengrass:.+:[0-9]+:.+",
            "conditionKeys": ["aws:CurrentTime", "aws:EpochTime", "aws:MultiFactorAuthAge", "aws:MultiFactorAuthPresent", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:SecureTransport", "aws:TagKeys", "aws:UserAgent"],
            "HasResource": true
        },
        "Amazon Redshift": {
            "StringPrefix": "redshift",
            "Actions": ["AcceptReservedNodeExchange", "AuthorizeClusterSecurityGroupIngress", "AuthorizeSnapshotAccess", "BatchDeleteClusterSnapshots", "BatchModifyClusterSnapshots", "CancelQuery", "CancelQuerySession", "CancelResize", "CopyClusterSnapshot", "CreateCluster", "CreateClusterParameterGroup", "CreateClusterSecurityGroup", "CreateClusterSnapshot", "CreateClusterSubnetGroup", "CreateClusterUser", "CreateEventSubscription", "CreateHsmClientCertificate", "CreateHsmConfiguration", "CreateSavedQuery", "CreateScheduledAction", "CreateSnapshotCopyGrant", "CreateSnapshotSchedule", "CreateTags", "DeleteCluster", "DeleteClusterParameterGroup", "DeleteClusterSecurityGroup", "DeleteClusterSnapshot", "DeleteClusterSubnetGroup", "DeleteEventSubscription", "DeleteHsmClientCertificate", "DeleteHsmConfiguration", "DeleteSavedQueries", "DeleteScheduledAction", "DeleteSnapshotCopyGrant", "DeleteSnapshotSchedule", "DeleteTags", "DescribeAccountAttributes", "DescribeClusterDbRevisions", "DescribeClusterParameterGroups", "DescribeClusterParameters", "DescribeClusterSecurityGroups", "DescribeClusterSnapshots", "DescribeClusterSubnetGroups", "DescribeClusterTracks", "DescribeClusterVersions", "DescribeClusters", "DescribeDefaultClusterParameters", "DescribeEventCategories", "DescribeEventSubscriptions", "DescribeEvents", "DescribeHsmClientCertificates", "DescribeHsmConfigurations", "DescribeLoggingStatus", "DescribeNodeConfigurationOptions", "DescribeOrderableClusterOptions", "DescribeQuery", "DescribeReservedNodeOfferings", "DescribeReservedNodes", "DescribeResize", "DescribeSavedQueries", "DescribeScheduledActions", "DescribeSnapshotCopyGrants", "DescribeSnapshotSchedules", "DescribeStorage", "DescribeTable", "DescribeTableRestoreStatus", "DescribeTags", "DisableLogging", "DisableSnapshotCopy", "EnableLogging", "EnableSnapshotCopy", "ExecuteQuery", "FetchResults", "GetClusterCredentials", "GetReservedNodeExchangeOfferings", "JoinGroup", "ListDatabases", "ListSavedQueries", "ListSchemas", "ListTables", "ModifyCluster", "ModifyClusterDbRevision", "ModifyClusterIamRoles", "ModifyClusterMaintenance", "ModifyClusterParameterGroup", "ModifyClusterSnapshot", "ModifyClusterSnapshotSchedule", "ModifyClusterSubnetGroup", "ModifyEventSubscription", "ModifySavedQuery", "ModifyScheduledAction", "ModifySnapshotCopyRetentionPeriod", "ModifySnapshotSchedule", "PauseCluster", "PurchaseReservedNodeOffering", "RebootCluster", "ResetClusterParameterGroup", "ResizeCluster", "RestoreFromClusterSnapshot", "RestoreTableFromClusterSnapshot", "ResumeCluster", "RevokeClusterSecurityGroupIngress", "RevokeSnapshotAccess", "RotateEncryptionKey", "ViewQueriesFromConsole", "ViewQueriesInConsole"],
            "ARNFormat": "arn:aws:redshift:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:redshift:.+:.+:.+",
            "conditionKeys": ["redshift:DbName", "redshift:DbUser", "redshift:DurationSeconds"],
            "HasResource": true
        },
        "Amazon WorkDocs": {
            "StringPrefix": "workdocs",
            "Actions": ["AbortDocumentVersionUpload", "ActivateUser", "AddResourcePermissions", "AddUserToGroup", "CheckAlias", "CreateComment", "CreateCustomMetadata", "CreateFolder", "CreateInstance", "CreateLabels", "CreateNotificationSubscription", "CreateUser", "DeactivateUser", "DeleteComment", "DeleteCustomMetadata", "DeleteDocument", "DeleteFolder", "DeleteFolderContents", "DeleteInstance", "DeleteLabels", "DeleteNotificationSubscription", "DeleteUser", "DeregisterDirectory", "DescribeActivities", "DescribeAvailableDirectories", "DescribeComments", "DescribeDocumentVersions", "DescribeFolderContents", "DescribeGroups", "DescribeInstances", "DescribeNotificationSubscriptions", "DescribeResourcePermissions", "DescribeRootFolders", "DescribeUsers", "DownloadDocumentVersion", "GetCurrentUser", "GetDocument", "GetDocumentPath", "GetDocumentVersion", "GetFolder", "GetFolderPath", "GetResources", "InitiateDocumentVersionUpload", "RegisterDirectory", "RemoveAllResourcePermissions", "RemoveResourcePermission", "UpdateDocument", "UpdateDocumentVersion", "UpdateFolder", "UpdateInstanceAlias", "UpdateUser"],
            "HasResource": false
        },
        "AWS Marketplace Management Portal": {
            "StringPrefix": "aws-marketplace-management",
            "Actions": ["uploadFiles", "viewMarketing", "viewReports", "viewSettings", "viewSupport"],
            "HasResource": false
        },
        "Comprehend Medical": {
            "StringPrefix": "comprehendmedical",
            "Actions": ["DetectEntities", "DetectPHI"],
            "ARNFormat": "arn:${Partition}:comprehendmedical:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:comprehendmedical:.+:.+:.+",
            "HasResource": false
        },
        "AWS DeepComposer": {
            "StringPrefix": "deepcomposer",
            "Actions": ["AssociateCoupon", "CreateAudio", "CreateComposition", "CreateModel", "DeleteComposition", "DeleteModel", "GetComposition", "GetModel", "GetSampleModel", "ListCompositions", "ListModels", "ListSampleModels", "ListTrainingTopics", "UpdateComposition", "UpdateModel"],
            "ARNFormat": "arn:aws:deepcomposer:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:deepcomposer:.+:.+:.+",
            "HasResource": true
        },
        "Amazon Managed Blockchain": {
            "StringPrefix": "managedblockchain",
            "Actions": ["CreateMember", "CreateNetwork", "CreateNode", "CreateProposal", "DeleteMember", "DeleteNode", "GetMember", "GetNetwork", "GetNode", "GetProposal", "ListInvitations", "ListMembers", "ListNetworks", "ListNodes", "ListProposalVotes", "ListProposals", "RejectInvitation", "UpdateMember", "UpdateNode", "VoteOnProposal"],
            "ARNFormat": "arn:aws:managedblockchain:<region>:<accountId>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:managedblockchain:.+:[0-9]+:.+",
            "HasResource": true
        },
        "AWS WAF": {
            "StringPrefix": "waf",
            "Actions": ["CreateByteMatchSet", "CreateGeoMatchSet", "CreateIPSet", "CreateRateBasedRule", "CreateRegexMatchSet", "CreateRegexPatternSet", "CreateRule", "CreateRuleGroup", "CreateSizeConstraintSet", "CreateSqlInjectionMatchSet", "CreateWebACL", "CreateXssMatchSet", "DeleteByteMatchSet", "DeleteGeoMatchSet", "DeleteIPSet", "DeleteLoggingConfiguration", "DeletePermissionPolicy", "DeleteRateBasedRule", "DeleteRegexMatchSet", "DeleteRegexPatternSet", "DeleteRule", "DeleteRuleGroup", "DeleteSizeConstraintSet", "DeleteSqlInjectionMatchSet", "DeleteWebACL", "DeleteXssMatchSet", "GetByteMatchSet", "GetChangeToken", "GetChangeTokenStatus", "GetGeoMatchSet", "GetIPSet", "GetLoggingConfiguration", "GetPermissionPolicy", "GetRateBasedRule", "GetRateBasedRuleManagedKeys", "GetRegexMatchSet", "GetRegexPatternSet", "GetRule", "GetRuleGroup", "GetSampledRequests", "GetSizeConstraintSet", "GetSqlInjectionMatchSet", "GetWebACL", "GetXssMatchSet", "ListActivatedRulesInRuleGroup", "ListByteMatchSets", "ListGeoMatchSets", "ListIPSets", "ListLoggingConfigurations", "ListRateBasedRules", "ListRegexMatchSets", "ListRegexPatternSets", "ListRuleGroups", "ListRules", "ListSizeConstraintSets", "ListSqlInjectionMatchSets", "ListSubscribedRuleGroups", "ListTagsForResource", "ListWebACLs", "ListXssMatchSets", "PutLoggingConfiguration", "PutPermissionPolicy", "TagResource", "UntagResource", "UpdateByteMatchSet", "UpdateGeoMatchSet", "UpdateIPSet", "UpdateRateBasedRule", "UpdateRegexMatchSet", "UpdateRegexPatternSet", "UpdateRule", "UpdateRuleGroup", "UpdateSizeConstraintSet", "UpdateSqlInjectionMatchSet", "UpdateWebACL", "UpdateXssMatchSet"],
            "ARNFormat": "arn:aws:waf::<account_ID>:<resource>/<resource_id>",
            "ARNRegex": "^arn:aws:waf::[0-9]+:.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon AppStream 2.0": {
            "StringPrefix": "appstream",
            "Actions": ["AssociateFleet", "BatchAssociateUserStack", "BatchDisassociateUserStack", "CopyImage", "CreateDirectoryConfig", "CreateFleet", "CreateImageBuilder", "CreateImageBuilderStreamingURL", "CreateStack", "CreateStreamingURL", "CreateUsageReportSubscription", "CreateUser", "DeleteDirectoryConfig", "DeleteFleet", "DeleteImage", "DeleteImageBuilder", "DeleteImagePermissions", "DeleteStack", "DeleteUsageReportSubscription", "DeleteUser", "DescribeDirectoryConfigs", "DescribeFleets", "DescribeImageBuilders", "DescribeImagePermissions", "DescribeImages", "DescribeSessions", "DescribeStacks", "DescribeUsageReportSubscriptions", "DescribeUserStackAssociations", "DescribeUsers", "DisableUser", "DisassociateFleet", "EnableUser", "ExpireSession", "GetImageBuilders", "GetParametersForThemeAssetUpload", "ListAssociatedFleets", "ListAssociatedStacks", "ListTagsForResource", "StartFleet", "StartImageBuilder", "StopFleet", "StopImageBuilder", "Stream", "TagResource", "UntagResource", "UpdateDirectoryConfig", "UpdateFleet", "UpdateImagePermissions", "UpdateStack"],
            "ARNFormat": "arn:aws:appstream:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:appstream:.+",
            "conditionKeys": ["appstream:userId", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon QuickSight": {
            "StringPrefix": "quicksight",
            "Actions": ["CreateAdmin", "CreateDashboard", "CreateGroup", "CreateGroupMembership", "CreateIAMPolicyAssignment", "CreateReader", "CreateTemplate", "CreateTemplateAlias", "CreateUser", "DeleteDashboard", "DeleteGroup", "DeleteGroupMembership", "DeleteIAMPolicyAssignment", "DeleteTemplate", "DeleteTemplateAlias", "DeleteUser", "DeleteUserByPrincipalId", "DescribeDashboard", "DescribeDashboardPermissions", "DescribeGroup", "DescribeIAMPolicyAssignment", "DescribeTemplate", "DescribeTemplateAlias", "DescribeTemplatePermissions", "DescribeUser", "GetAuthCode", "GetDashboardEmbedUrl", "GetGroupMapping", "ListDashboardVersions", "ListDashboards", "ListGroupMemberships", "ListGroups", "ListIAMPolicyAssignments", "ListIAMPolicyAssignmentsForUser", "ListTagsForResource", "ListTemplateAliases", "ListTemplateVersions", "ListTemplates", "ListUserGroups", "ListUsers", "RegisterUser", "SearchDirectoryGroups", "SetGroupMapping", "Subscribe", "TagResource", "Unsubscribe", "UntagResource", "UpdateDashboard", "UpdateDashboardPermissions", "UpdateDashboardPublishedVersion", "UpdateGroup", "UpdateIAMPolicyAssignment", "UpdateTemplate", "UpdateTemplateAlias", "UpdateTemplatePermissions", "UpdateUser"],
            "ARNFormat": "arn:aws:quicksight:<region>:<accountId>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:quicksight:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "quicksight:IamArn", "quicksight:SessionName", "quicksight:UserName"],
            "HasResource": true
        },
        "AWS WAF V2": {
            "StringPrefix": "wafv2",
            "Actions": ["AssociateWebACL", "CheckCapacity", "CreateIPSet", "CreateRegexPatternSet", "CreateRuleGroup", "CreateWebACL", "DeleteIPSet", "DeleteLoggingConfiguration", "DeleteRegexPatternSet", "DeleteRuleGroup", "DeleteWebACL", "DescribeManagedRuleGroup", "DisassociateWebACL", "GetIPSet", "GetLoggingConfiguration", "GetRateBasedStatementManagedKeys", "GetRegexPatternSet", "GetRuleGroup", "GetSampledRequests", "GetWebACL", "GetWebACLForResource", "ListAvailableManagedRuleGroups", "ListIPSets", "ListLoggingConfigurations", "ListRegexPatternSets", "ListResourcesForWebACL", "ListRuleGroups", "ListTagsForResource", "ListWebACLs", "PutLoggingConfiguration", "TagResource", "UntagResource", "UpdateIPSet", "UpdateRegexPatternSet", "UpdateRuleGroup", "UpdateWebACL"],
            "ARNFormat": "arn:aws:wafv2:<region>:<account-id>:<scope>/<resource-type>/<resource-name>/<resource-id>",
            "ARNRegex": "^arn:aws:wafv2:.+:[0-9]+:.+/.+/.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon WorkSpaces Application Manager": {
            "StringPrefix": "wam",
            "Actions": ["AuthenticatePackager"],
            "HasResource": false
        },
        "Amazon Data Lifecycle Manager": {
            "StringPrefix": "dlm",
            "Actions": ["CreateLifecyclePolicy", "DeleteLifecyclePolicy", "GetLifecyclePolicies", "GetLifecyclePolicy", "ListTagsForResource", "TagResource", "UntagResource", "UpdateLifecyclePolicy"],
            "ARNFormat": "arn:${Partition}:dlm:<region>:<account-id>:policy/<resource_name>",
            "ARNRegex": "^arn:${Partition}:dlm:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Well-Architected Tool": {
            "StringPrefix": "wellarchitected",
            "Actions": ["CreateWorkload", "CreateWorkloadShare", "DeleteWorkload", "GetWorkload", "ListWorkloads"],
            "ARNFormat": "arn:aws:wellarchitected:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:${Partition}:wellarchitected:.+",
            "HasResource": true
        },
        "AWS Connector Service": {
            "StringPrefix": "awsconnector",
            "Actions": ["GetConnectorHealth", "RegisterConnector", "ValidateConnectorId"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:<serviceName>:.+:.+:.+",
            "HasResource": false
        },
        "Amazon Kendra": {
            "StringPrefix": "kendra",
            "Actions": ["BatchDeleteDocument", "BatchPutDocument", "CreateDataSource", "CreateFaq", "CreateIndex", "DeleteDataSource", "DeleteFaq", "DeleteIndex", "DescribeDataSource", "DescribeFaq", "DescribeIndex", "ListDataSourceSyncJobs", "ListDataSources", "ListFaqs", "ListIndices", "ListTagsForResource", "Query", "StartDataSourceSyncJob", "StopDataSourceSyncJob", "SubmitFeedback", "TagResource", "UntagResource", "UpdateDataSource", "UpdateIndex"],
            "ARNFormat": "arn:${Partition}:kendra:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:kendra:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Lightsail": {
            "StringPrefix": "lightsail",
            "Actions": ["AllocateStaticIp", "AttachDisk", "AttachInstancesToLoadBalancer", "AttachLoadBalancerTlsCertificate", "AttachStaticIp", "CloseInstancePublicPorts", "CopySnapshot", "CreateCloudFormationStack", "CreateDisk", "CreateDiskFromSnapshot", "CreateDiskSnapshot", "CreateDomain", "CreateDomainEntry", "CreateInstanceSnapshot", "CreateInstances", "CreateInstancesFromSnapshot", "CreateKeyPair", "CreateLoadBalancer", "CreateLoadBalancerTlsCertificate", "CreateRelationalDatabase", "CreateRelationalDatabaseFromSnapshot", "CreateRelationalDatabaseSnapshot", "DeleteDisk", "DeleteDiskSnapshot", "DeleteDomain", "DeleteDomainEntry", "DeleteInstance", "DeleteInstanceSnapshot", "DeleteKeyPair", "DeleteKnownHostKeys", "DeleteLoadBalancer", "DeleteLoadBalancerTlsCertificate", "DeleteRelationalDatabase", "DeleteRelationalDatabaseSnapshot", "DetachDisk", "DetachInstancesFromLoadBalancer", "DetachStaticIp", "DownloadDefaultKeyPair", "ExportSnapshot", "GetActiveNames", "GetBlueprints", "GetBundles", "GetCloudFormationStackRecords", "GetDisk", "GetDiskSnapshot", "GetDiskSnapshots", "GetDisks", "GetDomain", "GetDomains", "GetExportSnapshotRecords", "GetInstance", "GetInstanceAccessDetails", "GetInstanceMetricData", "GetInstancePortStates", "GetInstanceSnapshot", "GetInstanceSnapshots", "GetInstanceState", "GetInstances", "GetKeyPair", "GetKeyPairs", "GetLoadBalancer", "GetLoadBalancerMetricData", "GetLoadBalancerTlsCertificates", "GetLoadBalancers", "GetOperation", "GetOperations", "GetOperationsForResource", "GetRegions", "GetRelationalDatabase", "GetRelationalDatabaseBlueprints", "GetRelationalDatabaseBundles", "GetRelationalDatabaseEvents", "GetRelationalDatabaseLogEvents", "GetRelationalDatabaseLogStreams", "GetRelationalDatabaseMasterUserPassword", "GetRelationalDatabaseMetricData", "GetRelationalDatabaseParameters", "GetRelationalDatabaseSnapshot", "GetRelationalDatabaseSnapshots", "GetRelationalDatabases", "GetStaticIp", "GetStaticIps", "ImportKeyPair", "IsVpcPeered", "OpenInstancePublicPorts", "PeerVpc", "PutInstancePublicPorts", "RebootInstance", "RebootRelationalDatabase", "ReleaseStaticIp", "StartInstance", "StartRelationalDatabase", "StopInstance", "StopRelationalDatabase", "TagResource", "UnpeerVpc", "UntagResource", "UpdateDomainEntry", "UpdateLoadBalancerAttribute", "UpdateRelationalDatabase", "UpdateRelationalDatabaseParameters"],
            "ARNFormat": "arn:aws:lightsail:<regionName>:<userAccountId>:<resourceType>/<Id>",
            "ARNRegex": "arn:aws:lightsail:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Backup storage": {
            "StringPrefix": "backup-storage",
            "Actions": ["MountCapsule"],
            "ARNFormat": "arn:aws:backup-storage:<region>:<account-id>:<resource-type>:<resource_name>",
            "ARNRegex": "^^arn:aws:backup-storage:.+:.+:.+",
            "HasResource": false
        },
        "Amazon Cognito Sync": {
            "StringPrefix": "cognito-sync",
            "Actions": ["BulkPublish", "DeleteDataset", "DescribeDataset", "DescribeIdentityPoolUsage", "DescribeIdentityUsage", "GetBulkPublishDetails", "GetCognitoEvents", "GetIdentityPoolConfiguration", "ListDatasets", "ListIdentityPoolUsage", "ListRecords", "QueryRecords", "RegisterDevice", "SetCognitoEvents", "SetDatasetConfiguration", "SetIdentityPoolConfiguration", "SubscribeToDataset", "UnsubscribeFromDataset", "UpdateRecords"],
            "ARNFormat": "arn:aws:cognito-sync:<region>:<account>:<resourceType>/<resourcePath>:",
            "ARNRegex": "^arn:aws:cognito-sync:.+",
            "HasResource": true
        },
        "Amazon CloudSearch": {
            "StringPrefix": "cloudsearch",
            "Actions": ["AddTags", "BuildSuggesters", "CreateDomain", "DefineAnalysisScheme", "DefineExpression", "DefineIndexField", "DefineSuggester", "DeleteAnalysisScheme", "DeleteDomain", "DeleteExpression", "DeleteIndexField", "DeleteSuggester", "DescribeAnalysisSchemes", "DescribeAvailabilityOptions", "DescribeDomainEndpointOptions", "DescribeDomains", "DescribeExpressions", "DescribeIndexFields", "DescribeScalingParameters", "DescribeServiceAccessPolicies", "DescribeSuggesters", "IndexDocuments", "ListDomainNames", "ListTags", "RemoveTags", "UpdateAvailabilityOptions", "UpdateDomainEndpointOptions", "UpdateScalingParameters", "UpdateServiceAccessPolicies", "document", "search", "suggest"],
            "ARNFormat": "arn:aws:cloudsearch:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:cloudsearch:.+:.+:.+",
            "HasResource": true
        },
        "Amazon Elastic Transcoder": {
            "StringPrefix": "elastictranscoder",
            "Actions": ["CancelJob", "CreateJob", "CreatePipeline", "CreatePreset", "DeletePipeline", "DeletePreset", "ListJobsByPipeline", "ListJobsByStatus", "ListPipelines", "ListPresets", "ReadJob", "ReadPipeline", "ReadPreset", "TestRole", "UpdatePipeline", "UpdatePipelineNotifications", "UpdatePipelineStatus"],
            "ARNFormat": "arn:aws:elastictranscoder:<region>:<account>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:elastictranscoder:.+",
            "HasResource": true
        },
        "AWS Price List": {
            "StringPrefix": "pricing",
            "Actions": ["DescribeServices", "GetAttributeValues", "GetProducts"],
            "HasResource": false
        },
        "AWS Backup": {
            "StringPrefix": "backup",
            "Actions": ["CopyIntoBackupVault", "CreateBackupPlan", "CreateBackupSelection", "CreateBackupVault", "DeleteBackupPlan", "DeleteBackupSelection", "DeleteBackupVault", "DeleteBackupVaultAccessPolicy", "DeleteBackupVaultNotifications", "DeleteRecoveryPoint", "DescribeBackupJob", "DescribeBackupVault", "DescribeCopyJob", "DescribeProtectedResource", "DescribeRecoveryPoint", "DescribeRestoreJob", "ExportBackupPlanTemplate", "GetBackupPlan", "GetBackupPlanFromJSON", "GetBackupPlanFromTemplate", "GetBackupSelection", "GetBackupVaultAccessPolicy", "GetBackupVaultNotifications", "GetRecoveryPointRestoreMetadata", "GetSupportedResourceTypes", "ListBackupJobs", "ListBackupPlanTemplates", "ListBackupPlanVersions", "ListBackupPlans", "ListBackupSelections", "ListBackupVaults", "ListCopyJobs", "ListProtectedResources", "ListRecoveryPointsByBackupVault", "ListRecoveryPointsByResource", "ListRestoreJobs", "ListTags", "PutBackupVaultAccessPolicy", "PutBackupVaultNotifications", "StartBackupJob", "StartCopyJob", "StartRestoreJob", "StopBackupJob", "TagResource", "UntagResource", "UpdateBackupPlan", "UpdateRecoveryPointLifecycle"],
            "ARNFormat": "arn:<partition>:backup:<region>:<account-id>:<resource-type>:<resource_name>",
            "ARNRegex": "^arn:${Partition}:backup:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Mobile Analytics": {
            "StringPrefix": "mobileanalytics",
            "Actions": ["GetFinancialReports", "GetReports", "PutEvents"],
            "HasResource": false
        },
        "AWS IoT Device Tester": {
            "StringPrefix": "iot-device-tester",
            "Actions": ["CheckVersion", "DownloadTestSuite", "LatestIdt", "SendMetrics", "SupportedVersion"],
            "ARNFormat": "arn:aws:iot-device-tester:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:iot-device-tester:.+:.+:.+",
            "HasResource": false
        },
        "AWS Database Migration Service": {
            "StringPrefix": "dms",
            "Actions": ["AddTagsToResource", "ApplyPendingMaintenanceAction", "CreateEndpoint", "CreateEventSubscription", "CreateReplicationInstance", "CreateReplicationSubnetGroup", "CreateReplicationTask", "DeleteCertificate", "DeleteEndpoint", "DeleteEventSubscription", "DeleteReplicationInstance", "DeleteReplicationSubnetGroup", "DeleteReplicationTask", "DescribeAccountAttributes", "DescribeCertificates", "DescribeConnections", "DescribeEndpointTypes", "DescribeEndpoints", "DescribeEventCategories", "DescribeEventSubscriptions", "DescribeEvents", "DescribeOrderableReplicationInstances", "DescribeRefreshSchemasStatus", "DescribeReplicationInstanceTaskLogs", "DescribeReplicationInstances", "DescribeReplicationSubnetGroups", "DescribeReplicationTaskAssessmentResults", "DescribeReplicationTasks", "DescribeSchemas", "DescribeTableStatistics", "ImportCertificate", "ListTagsForResource", "ModifyEndpoint", "ModifyEventSubscription", "ModifyReplicationInstance", "ModifyReplicationSubnetGroup", "ModifyReplicationTask", "RebootReplicationInstance", "RefreshSchemas", "ReloadTables", "RemoveTagsFromResource", "StartReplicationTask", "StartReplicationTaskAssessment", "StopReplicationTask", "TestConnection"],
            "ARNFormat": "arn:aws:dms:<region>:<account>:<resource>",
            "ARNRegex": "arn:aws:dms:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "dms:cert-tag/${TagKey}", "dms:endpoint-tag/${TagKey}", "dms:es-tag/${TagKey}", "dms:rep-tag/${TagKey}", "dms:req-tag/${TagKey}", "dms:subgrp-tag/${TagKey}", "dms:task-tag/${TagKey}"],
            "HasResource": true
        },
        "Amazon Session Manager Message Gateway Service": {
            "StringPrefix": "ssmmessages",
            "Actions": ["CreateControlChannel", "CreateDataChannel", "OpenControlChannel", "OpenDataChannel"],
            "HasResource": false
        },
        "AWS Artifact": {
            "StringPrefix": "artifact",
            "Actions": ["AcceptAgreement", "DownloadAgreement", "Get", "TerminateAgreement"],
            "ARNFormat": "arn:aws:artifact::<resource>",
            "ARNRegex": "^arn:aws:artifact::.+",
            "HasResource": true
        },
        "Amazon Transcribe": {
            "StringPrefix": "transcribe",
            "Actions": ["CreateVocabulary", "CreateVocabularyFilter", "DeleteMedicalTranscriptionJob", "DeleteTranscriptionJob", "DeleteVocabulary", "DeleteVocabularyFilter", "GetMedicalTranscriptionJob", "GetTranscriptionJob", "GetVocabulary", "GetVocabularyFilter", "ListMedicalTranscriptionJobs", "ListTranscriptionJobs", "ListVocabularies", "ListVocabularyFilters", "StartMedicalStreamTranscription", "StartMedicalTranscriptionJob", "StartStreamTranscription", "StartTranscriptionJob", "UpdateVocabulary", "UpdateVocabularyFilter"],
            "ARNFormat": "arn:${Partition}:transcribe:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:transcribe:.+:.+:.+",
            "HasResource": false
        },
        "AWS IQ Permissions": {
            "StringPrefix": "iq-permission",
            "Actions": ["ApproveAccessGrant"],
            "ARNFormat": "arn:aws:iq-permission::<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:iq-permission::.+",
            "HasResource": false
        },
        "AWS Elemental MediaPackage VOD": {
            "StringPrefix": "mediapackage-vod",
            "Actions": ["CreateAsset", "CreatePackagingConfiguration", "CreatePackagingGroup", "DeleteAsset", "DeletePackagingConfiguration", "DeletePackagingGroup", "DescribeAsset", "DescribePackagingConfiguration", "DescribePackagingGroup", "ListAssets", "ListPackagingConfigurations", "ListPackagingGroups"],
            "ARNFormat": "arn:aws:mediapackage-vod:<Region>:<Account>:<ResourceType>/<ResourceName>",
            "ARNRegex": "^arn:aws:mediapackage-vod:.+:.+:.+",
            "HasResource": true
        },
        "AWS Device Farm": {
            "StringPrefix": "devicefarm",
            "Actions": ["CreateDevicePool", "CreateInstanceProfile", "CreateNetworkProfile", "CreateProject", "CreateRemoteAccessSession", "CreateTestGridProject", "CreateTestGridUrl", "CreateUpload", "CreateVPCEConfiguration", "DeleteDevicePool", "DeleteInstanceProfile", "DeleteNetworkProfile", "DeleteProject", "DeleteRemoteAccessSession", "DeleteRun", "DeleteTestGridProject", "DeleteUpload", "DeleteVPCEConfiguration", "GetAccountSettings", "GetDevice", "GetDeviceInstance", "GetDevicePool", "GetDevicePoolCompatibility", "GetInstanceProfile", "GetJob", "GetNetworkProfile", "GetOfferingStatus", "GetProject", "GetRemoteAccessSession", "GetRun", "GetSuite", "GetTest", "GetTestGridProject", "GetTestGridSession", "GetUpload", "GetVPCEConfiguration", "InstallToRemoteAccessSession", "ListArtifacts", "ListDeviceInstances", "ListDevicePools", "ListDevices", "ListInstanceProfiles", "ListJobs", "ListNetworkProfiles", "ListOfferingPromotions", "ListOfferingTransactions", "ListOfferings", "ListProjects", "ListRemoteAccessSessions", "ListRuns", "ListSamples", "ListSuites", "ListTagsForResource", "ListTestGridProjects", "ListTestGridSessionActions", "ListTestGridSessionArtifacts", "ListTestGridSessions", "ListTests", "ListUniqueProblems", "ListUploads", "ListVPCEConfigurations", "PurchaseOffering", "RenewOffering", "ScheduleRun", "StopJob", "StopRemoteAccessSession", "StopRun", "TagResource", "UntagResource", "UpdateDeviceInstance", "UpdateDevicePool", "UpdateInstanceProfile", "UpdateNetworkProfile", "UpdateProject", "UpdateTestGridProject", "UpdateUpload", "UpdateVPCEConfiguration"],
            "ARNFormat": "arn:aws:devicefarm:<region>:<account-id>:<resource-type>:<resource-id>",
            "ARNRegex": "^arn:aws:devicefarm:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Ground Station": {
            "StringPrefix": "groundstation",
            "Actions": ["CancelContact", "CreateConfig", "CreateDataflowEndpointGroup", "CreateMissionProfile", "DeleteConfig", "DeleteDataflowEndpointGroup", "DeleteMissionProfile", "DescribeContact", "GetConfig", "GetDataflowEndpointGroup", "GetMinuteUsage", "GetMissionProfile", "GetSatellite", "ListConfigs", "ListContacts", "ListDataflowEndpointGroups", "ListGroundStations", "ListMissionProfiles", "ListSatellites", "ListTagsForResource", "ReserveContact", "TagResource", "UntagResource", "UpdateConfig", "UpdateMissionProfile"],
            "ARNFormat": "arn:aws:groundstation:<region>:<accountID>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:groundstation:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "groundstation:configId", "groundstation:configType", "groundstation:contactId", "groundstation:dataflowEndpointGroupId", "groundstation:groundStationId", "groundstation:missionProfileId", "groundstation:satelliteId"],
            "HasResource": true
        },
        "AWS Code Signing for Amazon FreeRTOS": {
            "StringPrefix": "signer",
            "Actions": ["CancelSigningProfile", "DescribeSigningJob", "GetSigningPlatform", "GetSigningProfile", "ListSigningJobs", "ListSigningPlatforms", "ListSigningProfiles", "ListTagsForResource", "PutSigningProfile", "StartSigningJob", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:signer:<region>::<signer_resource_path>",
            "ARNRegex": "^arn:aws:signer:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Purchase Orders Console": {
            "StringPrefix": "purchase-orders",
            "Actions": ["ModifyPurchaseOrders", "ViewPurchaseOrders"],
            "ARNFormat": "arn:aws:purchase-orders:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:purchase-orders:.+:.+:.+",
            "HasResource": false
        },
        "AWS Resource Groups": {
            "StringPrefix": "resource-groups",
            "Actions": ["CreateGroup", "DeleteGroup", "GetGroup", "GetGroupQuery", "GetTags", "ListGroupResources", "ListGroups", "SearchResources", "Tag", "Untag", "UpdateGroup", "UpdateGroupQuery"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:resource-groups:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS IQ": {
            "StringPrefix": "iq",
            "Actions": ["CreateProject"],
            "ARNFormat": "arn:aws:iq::<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:iq::.+",
            "HasResource": false
        },
        "Manage Amazon API Gateway": {
            "StringPrefix": "apigateway",
            "Actions": ["DELETE", "GET", "PATCH", "POST", "PUT", "SetWebACL", "UpdateRestApiPolicy"],
            "ARNFormat": "arn:aws:apigateway:<region>::<api_gateway_resource_path>",
            "ARNRegex": "^arn:aws:apigateway:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS App Mesh": {
            "StringPrefix": "appmesh",
            "Actions": ["CreateMesh", "CreateRoute", "CreateVirtualNode", "CreateVirtualRouter", "CreateVirtualService", "DeleteMesh", "DeleteRoute", "DeleteVirtualNode", "DeleteVirtualRouter", "DeleteVirtualService", "DescribeMesh", "DescribeRoute", "DescribeVirtualNode", "DescribeVirtualRouter", "DescribeVirtualService", "ListMeshes", "ListRoutes", "ListTagsForResource", "ListVirtualNodes", "ListVirtualRouters", "ListVirtualServices", "StreamAggregatedResources", "TagResource", "UntagResource", "UpdateMesh", "UpdateRoute", "UpdateVirtualNode", "UpdateVirtualRouter", "UpdateVirtualService"],
            "ARNFormat": "arn:aws:appmesh:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:appmesh:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Database Query Metadata Service": {
            "StringPrefix": "dbqms",
            "Actions": ["CreateFavoriteQuery", "CreateQueryHistory", "DeleteFavoriteQueries", "DeleteQueryHistory", "DescribeFavoriteQueries", "DescribeQueryHistory", "GetQueryString", "UpdateFavoriteQuery", "UpdateQueryHistory"],
            "ARNFormat": "arn:${Partition}:dbqms::",
            "ARNRegex": "^arn:${Partition}:dbqms::.+",
            "HasResource": false
        },
        "Amazon Managed Streaming for Kafka": {
            "StringPrefix": "kafka",
            "Actions": ["CreateCluster", "CreateConfiguration", "DeleteCluster", "DescribeCluster", "DescribeClusterOperation", "DescribeConfiguration", "DescribeConfigurationRevision", "GetBootstrapBrokers", "ListClusterOperations", "ListClusters", "ListConfigurations", "ListNodes", "ListTagsForResource", "TagResource", "UntagResource", "UpdateBrokerCount", "UpdateBrokerStorage", "UpdateClusterConfiguration", "UpdateMonitoring"],
            "ARNFormat": "arn:aws:kafka:<region>:<account>:<resourceType>/<resourceName>/<UUID>",
            "ARNRegex": "^arn:aws:kafka:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon CodeGuru Reviewer": {
            "StringPrefix": "codeguru-reviewer",
            "Actions": ["AssociateRepository", "CreateConnectionToken", "DescribeRepositoryAssociation", "DisassociateRepository", "GetMetricsData", "ListRepositoryAssociations", "ListThirdPartyRepositories"],
            "ARNFormat": "arn:aws:codeguru-reviewer:<region>:<account-id>:<resource-type>:<resource_name>",
            "ARNRegex": "^arn:aws:codeguru-reviewer:.+:.+:.+",
            "conditionKeys": ["aws:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "Amazon Pinpoint SMS and Voice Service": {
            "StringPrefix": "sms-voice",
            "Actions": ["CreateConfigurationSet", "CreateConfigurationSetEventDestination", "DeleteConfigurationSet", "DeleteConfigurationSetEventDestination", "GetConfigurationSetEventDestinations", "ListConfigurationSets", "SendVoiceMessage", "UpdateConfigurationSetEventDestination"],
            "ARNFormat": "arn:aws:sms-voice:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:sms-voice:.+:.+:.+",
            "HasResource": false
        },
        "Amazon CloudWatch": {
            "StringPrefix": "cloudwatch",
            "Actions": ["DeleteAlarms", "DeleteAnomalyDetector", "DeleteDashboards", "DeleteInsightRules", "DescribeAlarmHistory", "DescribeAlarms", "DescribeAlarmsForMetric", "DescribeAnomalyDetectors", "DescribeInsightRules", "DisableAlarmActions", "DisableInsightRules", "EnableAlarmActions", "EnableInsightRules", "GetDashboard", "GetInsightRuleReport", "GetMetricData", "GetMetricStatistics", "GetMetricWidgetImage", "ListDashboards", "ListMetrics", "ListTagsForResource", "PutAnomalyDetector", "PutDashboard", "PutInsightRule", "PutMetricAlarm", "PutMetricData", "SetAlarmState", "TagResource", "UntagResource"],
            "ARNFormat": "arn:${Partition}:cloudwatch:${Region}:${Account}:${ResourceType}/${ResourcePath}",
            "ARNRegex": "^arn:${Partition}:cloudwatch:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "cloudwatch:namespace"],
            "HasResource": true
        },
        "Amazon EC2 Auto Scaling": {
            "StringPrefix": "autoscaling",
            "Actions": ["AttachInstances", "AttachLoadBalancerTargetGroups", "AttachLoadBalancers", "BatchDeleteScheduledAction", "BatchPutScheduledUpdateGroupAction", "CompleteLifecycleAction", "CreateAutoScalingGroup", "CreateLaunchConfiguration", "CreateOrUpdateTags", "DeleteAutoScalingGroup", "DeleteLaunchConfiguration", "DeleteLifecycleHook", "DeleteNotificationConfiguration", "DeletePolicy", "DeleteScheduledAction", "DeleteTags", "DescribeAccountLimits", "DescribeAdjustmentTypes", "DescribeAutoScalingGroups", "DescribeAutoScalingInstances", "DescribeAutoScalingNotificationTypes", "DescribeLaunchConfigurations", "DescribeLifecycleHookTypes", "DescribeLifecycleHooks", "DescribeLoadBalancerTargetGroups", "DescribeLoadBalancers", "DescribeMetricCollectionTypes", "DescribeNotificationConfigurations", "DescribePolicies", "DescribeScalingActivities", "DescribeScalingProcessTypes", "DescribeScheduledActions", "DescribeTags", "DescribeTerminationPolicyTypes", "DetachInstances", "DetachLoadBalancerTargetGroups", "DetachLoadBalancers", "DisableMetricsCollection", "EnableMetricsCollection", "EnterStandby", "ExecutePolicy", "ExitStandby", "PutLifecycleHook", "PutNotificationConfiguration", "PutScalingPolicy", "PutScheduledUpdateGroupAction", "RecordLifecycleActionHeartbeat", "ResumeProcesses", "SetDesiredCapacity", "SetInstanceHealth", "SetInstanceProtection", "SuspendProcesses", "TerminateInstanceInAutoScalingGroup", "UpdateAutoScalingGroup"],
            "ARNFormat": "arn:${Partition}:autoscaling:<region>:<account>:<relative-id>",
            "ARNRegex": "^arn:${Partition}:autoscaling:.+:.+:.+",
            "conditionKeys": ["autoscaling:ImageId", "autoscaling:InstanceType", "autoscaling:InstanceTypes", "autoscaling:LaunchConfigurationName", "autoscaling:LaunchTemplateVersionSpecified", "autoscaling:LoadBalancerNames", "autoscaling:MaxSize", "autoscaling:MinSize", "autoscaling:ResourceTag/${TagKey}", "autoscaling:SpotPrice", "autoscaling:TargetGroupARNs", "autoscaling:VPCZoneIdentifiers", "aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Snowball": {
            "StringPrefix": "snowball",
            "Actions": ["CancelCluster", "CancelJob", "CreateAddress", "CreateCluster", "CreateJob", "DescribeAddress", "DescribeAddresses", "DescribeCluster", "DescribeJob", "GetJobManifest", "GetJobUnlockCode", "GetSnowballUsage", "ListClusterJobs", "ListClusters", "ListJobs", "UpdateCluster", "UpdateJob"],
            "HasResource": false
        },
        "AWS Shield": {
            "StringPrefix": "shield",
            "Actions": ["AssociateDRTLogBucket", "AssociateDRTRole", "CreateProtection", "CreateSubscription", "DeleteProtection", "DeleteSubscription", "DescribeAttack", "DescribeDRTAccess", "DescribeEmergencyContactSettings", "DescribeProtection", "DescribeSubscription", "DisassociateDRTLogBucket", "DisassociateDRTRole", "GetSubscriptionState", "ListAttacks", "ListProtections", "UpdateEmergencyContactSettings", "UpdateSubscription"],
            "ARNFormat": "arn:aws:shield::<account_ID>:<resource>/<resource_id>",
            "ARNRegex": "^arn:aws:shield::[0-9]+:.+/.+",
            "HasResource": true
        },
        "AWS Secrets Manager": {
            "StringPrefix": "secretsmanager",
            "Actions": ["CancelRotateSecret", "CreateSecret", "DeleteResourcePolicy", "DeleteSecret", "DescribeSecret", "GetRandomPassword", "GetResourcePolicy", "GetSecretValue", "ListSecretVersionIds", "ListSecrets", "PutResourcePolicy", "PutSecretValue", "RestoreSecret", "RotateSecret", "TagResource", "UntagResource", "UpdateSecret", "UpdateSecretVersionStage"],
            "ARNFormat": "arn:${Partition}:secretsmanager:${Region}:${Account}:secret:${SecretId}",
            "ARNRegex": "^arn:${Partition}:secretsmanager:.+",
            "conditionKeys": ["aws:RequestTag/tag-key", "aws:TagKeys", "secretsmanager:Description", "secretsmanager:ForceDeleteWithoutRecovery", "secretsmanager:KmsKeyId", "secretsmanager:Name", "secretsmanager:RecoveryWindowInDays", "secretsmanager:ResourceTag/tag-key", "secretsmanager:RotationLambdaARN", "secretsmanager:SecretId", "secretsmanager:VersionId", "secretsmanager:VersionStage", "secretsmanager:resource/AllowRotationLambdaArn"],
            "HasResource": true
        },
        "Application Auto Scaling": {
            "StringPrefix": "application-autoscaling",
            "Actions": ["DeleteScalingPolicy", "DeleteScheduledAction", "DeregisterScalableTarget", "DescribeScalableTargets", "DescribeScalingActivities", "DescribeScalingPolicies", "DescribeScheduledActions", "PutScalingPolicy", "PutScheduledAction", "RegisterScalableTarget"],
            "HasResource": false
        },
        "Amazon FSx": {
            "StringPrefix": "fsx",
            "Actions": ["CancelDataRepositoryTask", "CreateBackup", "CreateDataRepositoryTask", "CreateFileSystem", "CreateFileSystemFromBackup", "DeleteBackup", "DeleteFileSystem", "DescribeBackups", "DescribeDataRepositoryTasks", "DescribeFileSystems", "ListTagsForResource", "TagResource", "UntagResource", "UpdateFileSystem"],
            "ARNFormat": "arn:${Partition}:fsx:${Region}:${Account}:${ResourceType}/${ResourcePath}",
            "ARNRegex": "^arn:${Partition}:fsx:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Amplify": {
            "StringPrefix": "amplify",
            "Actions": ["CreateApp", "CreateBackendEnvironment", "CreateBranch", "CreateDeployment", "CreateDomainAssociation", "CreateWebHook", "DeleteApp", "DeleteBackendEnvironment", "DeleteBranch", "DeleteDomainAssociation", "DeleteJob", "DeleteWebHook", "GenerateAccessLogs", "GetApp", "GetArtifactUrl", "GetBackendEnvironment", "GetBranch", "GetDomainAssociation", "GetJob", "GetWebHook", "ListApps", "ListArtifacts", "ListBackendEnvironments", "ListBranches", "ListDomainAssociations", "ListJobs", "ListWebHooks", "StartDeployment", "StartJob", "StopJob", "TagResource", "UntagResource", "UpdateApp", "UpdateBranch", "UpdateDomainAssociation", "UpdateWebHook"],
            "ARNFormat": "arn:aws:amplify:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:amplify:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS App Mesh Preview": {
            "StringPrefix": "appmesh-preview",
            "Actions": ["CreateMesh", "CreateRoute", "CreateVirtualNode", "CreateVirtualRouter", "CreateVirtualService", "DeleteMesh", "DeleteRoute", "DeleteVirtualNode", "DeleteVirtualRouter", "DeleteVirtualService", "DescribeMesh", "DescribeRoute", "DescribeVirtualNode", "DescribeVirtualRouter", "DescribeVirtualService", "ListMeshes", "ListRoutes", "ListVirtualNodes", "ListVirtualRouters", "ListVirtualServices", "StreamAggregatedResources", "UpdateMesh", "UpdateRoute", "UpdateVirtualNode", "UpdateVirtualRouter", "UpdateVirtualService"],
            "ARNFormat": "arn:aws:appmesh-preview:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:appmesh-preview:.+:.+:.+",
            "HasResource": true
        },
        "Amazon Kinesis Video Streams": {
            "StringPrefix": "kinesisvideo",
            "Actions": ["ConnectAsMaster", "ConnectAsViewer", "CreateSignalingChannel", "CreateStream", "DeleteSignalingChannel", "DeleteStream", "DescribeSignalingChannel", "DescribeStream", "GetClip", "GetDASHStreamingSessionURL", "GetDataEndpoint", "GetHLSStreamingSessionURL", "GetIceServerConfig", "GetMedia", "GetMediaForFragmentList", "GetSignalingChannelEndpoint", "ListFragments", "ListSignalingChannels", "ListStreams", "ListTagsForResource", "ListTagsForStream", "PutMedia", "SendAlexaOfferToMaster", "TagResource", "TagStream", "UntagResource", "UntagStream", "UpdateDataRetention", "UpdateSignalingChannel", "UpdateStream"],
            "ARNFormat": "arn:aws:kinesisvideo:<region>:<account_ID>:<resourceType>/<resourceName>/<creationTime>",
            "ARNRegex": "^arn:aws:kinesisvideo:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon API Gateway": {
            "StringPrefix": "execute-api",
            "Actions": ["InvalidateCache", "Invoke", "ManageConnections"],
            "ARNFormat": "arn:aws:execute-api:<region>:<account_id>:<api_id>/<stage>/<method>/<api_specific_resource_path>",
            "ARNRegex": "^arn:aws:execute-api:.+",
            "HasResource": true
        },
        "AWS Elemental MediaLive": {
            "StringPrefix": "medialive",
            "Actions": ["BatchUpdateSchedule", "CreateChannel", "CreateInput", "CreateInputSecurityGroup", "CreateMultiplex", "CreateTags", "DeleteChannel", "DeleteInput", "DeleteInputSecurityGroup", "DeleteMultiplex", "DeleteReservation", "DeleteTags", "DescribeChannel", "DescribeInput", "DescribeInputSecurityGroup", "DescribeMultiplex", "DescribeOffering", "DescribeReservation", "DescribeSchedule", "ListChannels", "ListInputSecurityGroups", "ListInputs", "ListMultiplexes", "ListOfferings", "ListReservations", "ListTagsForResource", "PurchaseOffering", "StartChannel", "StartMultiplex", "StopChannel", "StopMultiplex", "UpdateChannel", "UpdateChannelClass", "UpdateInput", "UpdateInputSecurityGroup", "UpdateMultiplex", "UpdateReservation"],
            "ARNFormat": "arn:${Partition}:medialive:${Region}:${Account}:${ResourceType}:${ResourcePath}",
            "ARNRegex": "^arn:${Partition}:medialive:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Key Management Service": {
            "StringPrefix": "kms",
            "Actions": ["CancelKeyDeletion", "ConnectCustomKeyStore", "CreateAlias", "CreateCustomKeyStore", "CreateGrant", "CreateKey", "Decrypt", "DeleteAlias", "DeleteCustomKeyStore", "DeleteImportedKeyMaterial", "DescribeCustomKeyStores", "DescribeKey", "DisableKey", "DisableKeyRotation", "DisconnectCustomKeyStore", "EnableKey", "EnableKeyRotation", "Encrypt", "GenerateDataKey", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "GetKeyPolicy", "GetKeyRotationStatus", "GetParametersForImport", "GetPublicKey", "ImportKeyMaterial", "ListAliases", "ListGrants", "ListKeyPolicies", "ListKeys", "ListResourceTags", "ListRetirableGrants", "PutKeyPolicy", "ReEncryptFrom", "ReEncryptTo", "RetireGrant", "RevokeGrant", "ScheduleKeyDeletion", "Sign", "TagResource", "UntagResource", "UpdateAlias", "UpdateCustomKeyStore", "UpdateKeyDescription", "Verify"],
            "ARNFormat": "arn:aws:kms:<region>:<account_id>:<resource_type>/<id>",
            "ARNRegex": "^arn:aws:kms:.+",
            "conditionKeys": ["kms:BypassPolicyLockoutSafetyCheck", "kms:CallerAccount", "kms:CustomerMasterKeySpec", "kms:CustomerMasterKeyUsage", "kms:DataKeyPairSpec", "kms:EncryptionAlgorithm", "kms:EncryptionContextKeys", "kms:ExpirationModel", "kms:GrantConstraintType", "kms:GrantIsForAWSResource", "kms:GrantOperations", "kms:GranteePrincipal", "kms:KeyOrigin", "kms:MessageType", "kms:ReEncryptOnSameKey", "kms:RetiringPrincipal", "kms:SigningAlgorithm", "kms:ValidTo", "kms:ViaService", "kms:WrappingAlgorithm", "kms:WrappingKeySpec"],
            "HasResource": true
        },
        "AWS CloudHSM": {
            "StringPrefix": "cloudhsm",
            "Actions": ["AddTagsToResource", "CopyBackupToRegion", "CreateCluster", "CreateHapg", "CreateHsm", "CreateLunaClient", "DeleteBackup", "DeleteCluster", "DeleteHapg", "DeleteHsm", "DeleteLunaClient", "DescribeBackups", "DescribeClusters", "DescribeHapg", "DescribeHsm", "DescribeLunaClient", "GetConfig", "InitializeCluster", "ListAvailableZones", "ListHapgs", "ListHsms", "ListLunaClients", "ListTags", "ListTagsForResource", "ModifyHapg", "ModifyHsm", "ModifyLunaClient", "RemoveTagsFromResource", "RestoreBackup", "TagResource", "UntagResource"],
            "ARNFormat": "arn:<partition>:cloudhsm:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:<partition>:cloudhsm:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon CodeGuru": {
            "StringPrefix": "codeguru",
            "Actions": ["GetCodeGuruFreeTrialSummary"],
            "ARNFormat": "arn:aws:codeguru:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:codeguru:.+:.+:.+",
            "HasResource": false
        },
        "Amazon EC2": {
            "StringPrefix": "ec2",
            "Actions": ["AcceptReservedInstancesExchangeQuote", "AcceptTransitGatewayPeeringAttachment", "AcceptTransitGatewayVpcAttachment", "AcceptVpcEndpointConnections", "AcceptVpcPeeringConnection", "AdvertiseByoipCidr", "AllocateAddress", "AllocateHosts", "ApplySecurityGroupsToClientVpnTargetNetwork", "AssignIpv6Addresses", "AssignPrivateIpAddresses", "AssociateAddress", "AssociateClientVpnTargetNetwork", "AssociateDhcpOptions", "AssociateIamInstanceProfile", "AssociateRouteTable", "AssociateSubnetCidrBlock", "AssociateTransitGatewayMulticastDomain", "AssociateTransitGatewayRouteTable", "AssociateVpcCidrBlock", "AttachClassicLinkVpc", "AttachInternetGateway", "AttachNetworkInterface", "AttachVolume", "AttachVpnGateway", "AuthorizeClientVpnIngress", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "BundleInstance", "CancelBundleTask", "CancelCapacityReservation", "CancelConversionTask", "CancelExportTask", "CancelImportTask", "CancelReservedInstancesListing", "CancelSpotFleetRequests", "CancelSpotInstanceRequests", "ConfirmProductInstance", "CopyFpgaImage", "CopyImage", "CopySnapshot", "CreateCapacityReservation", "CreateClientVpnEndpoint", "CreateClientVpnRoute", "CreateCustomerGateway", "CreateDefaultSubnet", "CreateDefaultVpc", "CreateDhcpOptions", "CreateEgressOnlyInternetGateway", "CreateFleet", "CreateFlowLogs", "CreateFpgaImage", "CreateImage", "CreateInstanceExportTask", "CreateInternetGateway", "CreateKeyPair", "CreateLaunchTemplate", "CreateLaunchTemplateVersion", "CreateLocalGatewayRoute", "CreateLocalGatewayRouteTableVpcAssociation", "CreateNatGateway", "CreateNetworkAcl", "CreateNetworkAclEntry", "CreateNetworkInterface", "CreateNetworkInterfacePermission", "CreatePlacementGroup", "CreateReservedInstancesListing", "CreateRoute", "CreateRouteTable", "CreateSecurityGroup", "CreateSnapshot", "CreateSnapshots", "CreateSpotDatafeedSubscription", "CreateSubnet", "CreateTags", "CreateTrafficMirrorFilter", "CreateTrafficMirrorFilterRule", "CreateTrafficMirrorSession", "CreateTrafficMirrorTarget", "CreateTransitGateway", "CreateTransitGatewayMulticastDomain", "CreateTransitGatewayPeeringAttachment", "CreateTransitGatewayRoute", "CreateTransitGatewayRouteTable", "CreateTransitGatewayVpcAttachment", "CreateVolume", "CreateVpc", "CreateVpcEndpoint", "CreateVpcEndpointConnectionNotification", "CreateVpcEndpointServiceConfiguration", "CreateVpcPeeringConnection", "CreateVpnConnection", "CreateVpnConnectionRoute", "CreateVpnGateway", "DeleteClientVpnEndpoint", "DeleteClientVpnRoute", "DeleteCustomerGateway", "DeleteDhcpOptions", "DeleteEgressOnlyInternetGateway", "DeleteFleets", "DeleteFlowLogs", "DeleteFpgaImage", "DeleteInternetGateway", "DeleteKeyPair", "DeleteLaunchTemplate", "DeleteLaunchTemplateVersions", "DeleteLocalGatewayRoute", "DeleteLocalGatewayRouteTableVpcAssociation", "DeleteNatGateway", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "DeleteNetworkInterface", "DeleteNetworkInterfacePermission", "DeletePlacementGroup", "DeleteRoute", "DeleteRouteTable", "DeleteSecurityGroup", "DeleteSnapshot", "DeleteSpotDatafeedSubscription", "DeleteSubnet", "DeleteTags", "DeleteTrafficMirrorFilter", "DeleteTrafficMirrorFilterRule", "DeleteTrafficMirrorSession", "DeleteTrafficMirrorTarget", "DeleteTransitGateway", "DeleteTransitGatewayMulticastDomain", "DeleteTransitGatewayPeeringAttachment", "DeleteTransitGatewayRoute", "DeleteTransitGatewayRouteTable", "DeleteTransitGatewayVpcAttachment", "DeleteVolume", "DeleteVpc", "DeleteVpcEndpointConnectionNotifications", "DeleteVpcEndpointServiceConfigurations", "DeleteVpcEndpoints", "DeleteVpcPeeringConnection", "DeleteVpnConnection", "DeleteVpnConnectionRoute", "DeleteVpnGateway", "DeprovisionByoipCidr", "DeregisterImage", "DeregisterTransitGatewayMulticastGroupMembers", "DeregisterTransitGatewayMulticastGroupSources", "DescribeAccountAttributes", "DescribeAddresses", "DescribeAggregateIdFormat", "DescribeAvailabilityZones", "DescribeBundleTasks", "DescribeByoipCidrs", "DescribeCapacityReservations", "DescribeClassicLinkInstances", "DescribeClientVpnAuthorizationRules", "DescribeClientVpnConnections", "DescribeClientVpnEndpoints", "DescribeClientVpnRoutes", "DescribeClientVpnTargetNetworks", "DescribeConversionTasks", "DescribeCustomerGateways", "DescribeDhcpOptions", "DescribeEgressOnlyInternetGateways", "DescribeElasticGpus", "DescribeExportImageTasks", "DescribeExportTasks", "DescribeFastSnapshotRestores", "DescribeFleetHistory", "DescribeFleetInstances", "DescribeFleets", "DescribeFlowLogs", "DescribeFpgaImageAttribute", "DescribeFpgaImages", "DescribeHostReservationOfferings", "DescribeHostReservations", "DescribeHosts", "DescribeIamInstanceProfileAssociations", "DescribeIdFormat", "DescribeIdentityIdFormat", "DescribeImageAttribute", "DescribeImages", "DescribeImportImageTasks", "DescribeImportSnapshotTasks", "DescribeInstanceAttribute", "DescribeInstanceCreditSpecifications", "DescribeInstanceStatus", "DescribeInstanceTypes", "DescribeInstances", "DescribeInternetGateways", "DescribeKeyPairs", "DescribeLaunchTemplateVersions", "DescribeLaunchTemplates", "DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations", "DescribeLocalGatewayRouteTableVpcAssociations", "DescribeLocalGatewayRouteTables", "DescribeLocalGatewayVirtualInterfaceGroups", "DescribeLocalGatewayVirtualInterfaces", "DescribeLocalGateways", "DescribeMovingAddresses", "DescribeNatGateways", "DescribeNetworkAcls", "DescribeNetworkInterfaceAttribute", "DescribeNetworkInterfacePermissions", "DescribeNetworkInterfaces", "DescribePlacementGroups", "DescribePrefixLists", "DescribePrincipalIdFormat", "DescribePublicIpv4Pools", "DescribeRegions", "DescribeReservedInstances", "DescribeReservedInstancesListings", "DescribeReservedInstancesModifications", "DescribeReservedInstancesOfferings", "DescribeRouteTables", "DescribeScheduledInstanceAvailability", "DescribeScheduledInstances", "DescribeSecurityGroupReferences", "DescribeSecurityGroups", "DescribeSnapshotAttribute", "DescribeSnapshots", "DescribeSpotDatafeedSubscription", "DescribeSpotFleetInstances", "DescribeSpotFleetRequestHistory", "DescribeSpotFleetRequests", "DescribeSpotInstanceRequests", "DescribeSpotPriceHistory", "DescribeStaleSecurityGroups", "DescribeSubnets", "DescribeTags", "DescribeTrafficMirrorFilters", "DescribeTrafficMirrorSessions", "DescribeTrafficMirrorTargets", "DescribeTransitGatewayAttachments", "DescribeTransitGatewayMulticastDomains", "DescribeTransitGatewayPeeringAttachments", "DescribeTransitGatewayRouteTables", "DescribeTransitGatewayVpcAttachments", "DescribeTransitGateways", "DescribeVolumeAttribute", "DescribeVolumeStatus", "DescribeVolumes", "DescribeVolumesModifications", "DescribeVpcAttribute", "DescribeVpcClassicLink", "DescribeVpcClassicLinkDnsSupport", "DescribeVpcEndpointConnectionNotifications", "DescribeVpcEndpointConnections", "DescribeVpcEndpointServiceConfigurations", "DescribeVpcEndpointServicePermissions", "DescribeVpcEndpointServices", "DescribeVpcEndpoints", "DescribeVpcPeeringConnections", "DescribeVpcs", "DescribeVpnConnections", "DescribeVpnGateways", "DetachClassicLinkVpc", "DetachInternetGateway", "DetachNetworkInterface", "DetachVolume", "DetachVpnGateway", "DisableEbsEncryptionByDefault", "DisableFastSnapshotRestores", "DisableTransitGatewayRouteTablePropagation", "DisableVgwRoutePropagation", "DisableVpcClassicLink", "DisableVpcClassicLinkDnsSupport", "DisassociateAddress", "DisassociateClientVpnTargetNetwork", "DisassociateIamInstanceProfile", "DisassociateRouteTable", "DisassociateSubnetCidrBlock", "DisassociateTransitGatewayMulticastDomain", "DisassociateTransitGatewayRouteTable", "DisassociateVpcCidrBlock", "EnableEbsEncryptionByDefault", "EnableFastSnapshotRestores", "EnableTransitGatewayRouteTablePropagation", "EnableVgwRoutePropagation", "EnableVolumeIO", "EnableVpcClassicLink", "EnableVpcClassicLinkDnsSupport", "ExportClientVpnClientCertificateRevocationList", "ExportClientVpnClientConfiguration", "ExportImage", "ExportTransitGatewayRoutes", "GetCapacityReservationUsage", "GetConsoleOutput", "GetConsoleScreenshot", "GetDefaultCreditSpecification", "GetEbsDefaultKmsKeyId", "GetEbsEncryptionByDefault", "GetHostReservationPurchasePreview", "GetLaunchTemplateData", "GetPasswordData", "GetReservedInstancesExchangeQuote", "GetTransitGatewayAttachmentPropagations", "GetTransitGatewayMulticastDomainAssociations", "GetTransitGatewayRouteTableAssociations", "GetTransitGatewayRouteTablePropagations", "ImportClientVpnClientCertificateRevocationList", "ImportImage", "ImportInstance", "ImportKeyPair", "ImportSnapshot", "ImportVolume", "ModifyCapacityReservation", "ModifyClientVpnEndpoint", "ModifyDefaultCreditSpecification", "ModifyEbsDefaultKmsKeyId", "ModifyFleet", "ModifyFpgaImageAttribute", "ModifyHosts", "ModifyIdFormat", "ModifyIdentityIdFormat", "ModifyImageAttribute", "ModifyInstanceAttribute", "ModifyInstanceCapacityReservationAttributes", "ModifyInstanceCreditSpecification", "ModifyInstanceEventStartTime", "ModifyInstanceMetadataOptions", "ModifyInstancePlacement", "ModifyLaunchTemplate", "ModifyNetworkInterfaceAttribute", "ModifyReservedInstances", "ModifySnapshotAttribute", "ModifySpotFleetRequest", "ModifySubnetAttribute", "ModifyTrafficMirrorFilterNetworkServices", "ModifyTrafficMirrorFilterRule", "ModifyTrafficMirrorSession", "ModifyTransitGatewayVpcAttachment", "ModifyVolume", "ModifyVolumeAttribute", "ModifyVpcAttribute", "ModifyVpcEndpoint", "ModifyVpcEndpointConnectionNotification", "ModifyVpcEndpointServiceConfiguration", "ModifyVpcEndpointServicePermissions", "ModifyVpcPeeringConnectionOptions", "ModifyVpcTenancy", "ModifyVpnConnection", "ModifyVpnTunnelCertificate", "ModifyVpnTunnelOptions", "MonitorInstances", "MoveAddressToVpc", "ProvisionByoipCidr", "PurchaseHostReservation", "PurchaseReservedInstancesOffering", "PurchaseScheduledInstances", "RebootInstances", "RegisterImage", "RegisterTransitGatewayMulticastGroupMembers", "RegisterTransitGatewayMulticastGroupSources", "RejectTransitGatewayPeeringAttachment", "RejectTransitGatewayVpcAttachment", "RejectVpcEndpointConnections", "RejectVpcPeeringConnection", "ReleaseAddress", "ReleaseHosts", "ReplaceIamInstanceProfileAssociation", "ReplaceNetworkAclAssociation", "ReplaceNetworkAclEntry", "ReplaceRoute", "ReplaceRouteTableAssociation", "ReplaceTransitGatewayRoute", "ReportInstanceStatus", "RequestSpotFleet", "RequestSpotInstances", "ResetEbsDefaultKmsKeyId", "ResetFpgaImageAttribute", "ResetImageAttribute", "ResetInstanceAttribute", "ResetNetworkInterfaceAttribute", "ResetSnapshotAttribute", "RestoreAddressToClassic", "RevokeClientVpnIngress", "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RunInstances", "RunScheduledInstances", "SearchLocalGatewayRoutes", "SearchTransitGatewayMulticastGroups", "SearchTransitGatewayRoutes", "SendDiagnosticInterrupt", "StartInstances", "StartVpcEndpointServicePrivateDnsVerification", "StopInstances", "TerminateClientVpnConnections", "TerminateInstances", "UnassignIpv6Addresses", "UnassignPrivateIpAddresses", "UnmonitorInstances", "UpdateSecurityGroupRuleDescriptionsEgress", "UpdateSecurityGroupRuleDescriptionsIngress", "WithdrawByoipCidr"],
            "ARNFormat": "arn:aws:ec2:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:ec2:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:TagKeys", "ec2:AccepterVpc", "ec2:AssociatePublicIpAddress", "ec2:AuthenticationType", "ec2:AuthorizedService", "ec2:AuthorizedUser", "ec2:AutoPlacement", "ec2:AvailabilityZone", "ec2:CreateAction", "ec2:DPDTimeoutSeconds", "ec2:EbsOptimized", "ec2:ElasticGpuType", "ec2:Encrypted", "ec2:GatewayType", "ec2:HostRecovery", "ec2:IKEVersions", "ec2:ImageType", "ec2:InsideTunnelCidr", "ec2:InstanceMarketType", "ec2:InstanceProfile", "ec2:InstanceType", "ec2:IsLaunchTemplateResource", "ec2:LaunchTemplate", "ec2:MetadataHttpEndpoint", "ec2:MetadataHttpPutResponseHopLimit", "ec2:MetadataHttpTokens", "ec2:Owner", "ec2:ParentSnapshot", "ec2:ParentVolume", "ec2:Permission", "ec2:Phase1DHGroupNumbers", "ec2:Phase1EncryptionAlgorithms", "ec2:Phase1IntegrityAlgorithms", "ec2:Phase1LifetimeSeconds", "ec2:Phase2DHGroupNumbers", "ec2:Phase2EncryptionAlgorithms", "ec2:Phase2IntegrityAlgorithms", "ec2:Phase2LifetimeSeconds", "ec2:PlacementGroup", "ec2:PlacementGroupStrategy", "ec2:PresharedKeys", "ec2:ProductCode", "ec2:Public", "ec2:Quantity", "ec2:Region", "ec2:RekeyFuzzPercentage", "ec2:RekeyMarginTimeSeconds", "ec2:RequesterVpc", "ec2:ReservedInstancesOfferingType", "ec2:ResourceTag/", "ec2:ResourceTag/${TagKey}", "ec2:RoleDelivery", "ec2:RootDeviceType", "ec2:RoutingType", "ec2:SnapshotTime", "ec2:SourceInstanceARN", "ec2:Subnet", "ec2:Tenancy", "ec2:VolumeIops", "ec2:VolumeSize", "ec2:VolumeType", "ec2:Vpc", "ec2:VpceServiceName", "ec2:VpceServiceOwner", "ec2:VpceServicePrivateDnsName"],
            "HasResource": true
        },
        "AWS Import Export Disk Service": {
            "StringPrefix": "importexport",
            "Actions": ["CancelJob", "CreateJob", "GetShippingLabel", "GetStatus", "ListJobs", "UpdateJob"],
            "HasResource": false
        },
        "Data Pipeline": {
            "StringPrefix": "datapipeline",
            "Actions": ["ActivatePipeline", "AddTags", "CreatePipeline", "DeactivatePipeline", "DeletePipeline", "DescribeObjects", "DescribePipelines", "EvaluateExpression", "GetAccountLimits", "GetPipelineDefinition", "ListPipelines", "PollForTask", "PutAccountLimits", "PutPipelineDefinition", "QueryObjects", "RemoveTags", "ReportTaskProgress", "ReportTaskRunnerHeartbeat", "SetStatus", "SetTaskStatus", "ValidatePipelineDefinition"],
            "conditionKeys": ["datapipeline:PipelineCreator", "datapipeline:Tag", "datapipeline:workerGroup"],
            "HasResource": false
        },
        "AWS Server Migration Service": {
            "StringPrefix": "sms",
            "Actions": ["CreateApp", "CreateReplicationJob", "DeleteApp", "DeleteAppLaunchConfiguration", "DeleteAppReplicationConfiguration", "DeleteReplicationJob", "DeleteServerCatalog", "DisassociateConnector", "GenerateChangeSet", "GenerateTemplate", "GetApp", "GetAppLaunchConfiguration", "GetAppReplicationConfiguration", "GetConnectors", "GetMessages", "GetReplicationJobs", "GetReplicationRuns", "GetServers", "ImportServerCatalog", "LaunchApp", "ListApps", "PutAppLaunchConfiguration", "PutAppReplicationConfiguration", "SendMessage", "StartAppReplication", "StartOnDemandReplicationRun", "StopAppReplication", "TerminateApp", "UpdateApp", "UpdateReplicationJob"],
            "ARNFormat": "arn:aws:<serviceName>:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:<serviceName>:.+:.+:.+",
            "HasResource": false
        },
        "AWS CloudFormation": {
            "StringPrefix": "cloudformation",
            "Actions": ["CancelUpdateStack", "ContinueUpdateRollback", "CreateChangeSet", "CreateStack", "CreateStackInstances", "CreateStackSet", "CreateUploadBucket", "DeleteChangeSet", "DeleteStack", "DeleteStackInstances", "DeleteStackSet", "DeregisterType", "DescribeAccountLimits", "DescribeChangeSet", "DescribeStackDriftDetectionStatus", "DescribeStackEvents", "DescribeStackInstance", "DescribeStackResource", "DescribeStackResourceDrifts", "DescribeStackResources", "DescribeStackSet", "DescribeStackSetOperation", "DescribeStacks", "DescribeType", "DescribeTypeRegistration", "DetectStackDrift", "DetectStackResourceDrift", "DetectStackSetDrift", "EstimateTemplateCost", "ExecuteChangeSet", "GetStackPolicy", "GetTemplate", "GetTemplateSummary", "ListChangeSets", "ListExports", "ListImports", "ListStackInstances", "ListStackResources", "ListStackSetOperationResults", "ListStackSetOperations", "ListStackSets", "ListStacks", "ListTypeRegistrations", "ListTypeVersions", "ListTypes", "RegisterType", "SetStackPolicy", "SetTypeDefaultVersion", "SignalResource", "StopStackSetOperation", "TagResource", "UntagResource", "UpdateStack", "UpdateStackInstances", "UpdateStackSet", "UpdateTerminationProtection", "ValidateTemplate"],
            "ARNFormat": "arn:aws:cloudformation:<region>:<account>:<relative-id>",
            "ARNRegex": "^arn:aws:cloudformation:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "cloudformation:ChangeSetName", "cloudformation:ImportResourceTypes", "cloudformation:ResourceTypes", "cloudformation:RoleArn", "cloudformation:StackPolicyUrl", "cloudformation:TemplateUrl"],
            "HasResource": true
        },
        "Amazon WorkMail Message Flow": {
            "StringPrefix": "workmailmessageflow",
            "Actions": ["GetRawMessageContent"],
            "ARNFormat": "arn:${Partition}:workmailmessageflow:${Region}:${Account}:message/${OrganizationId}/${Context}/${MessageId}",
            "ARNRegex": "^arn:${Partition}:workmailmessageflow:.+:.+:.+",
            "HasResource": true
        },
        "AWS Chatbot": {
            "StringPrefix": "chatbot",
            "Actions": ["CreateChimeWebhookConfiguration", "CreateSlackChannelConfiguration", "DeleteChimeWebhookConfiguration", "DeleteSlackChannelConfiguration", "DescribeChimeWebhookConfigurations", "DescribeSlackChannelConfigurations", "DescribeSlackChannels", "DescribeSlackWorkspaces", "GetSlackOauthParameters", "RedeemSlackOauthCode", "UpdateChimeWebhookConfiguration", "UpdateSlackChannelConfiguration"],
            "ARNFormat": "arn:${Partition}:chatbot::<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:${Partition}:chatbot:.+",
            "HasResource": true
        },
        "AWS Health APIs and Notifications": {
            "StringPrefix": "health",
            "Actions": ["DescribeAffectedAccountsForOrganization", "DescribeAffectedEntities", "DescribeAffectedEntitiesForOrganization", "DescribeEntityAggregates", "DescribeEventAggregates", "DescribeEventDetails", "DescribeEventDetailsForOrganization", "DescribeEventTypes", "DescribeEvents", "DescribeEventsForOrganization", "DescribeHealthServiceStatusForOrganization", "DisableHealthServiceAccessForOrganization", "EnableHealthServiceAccessForOrganization"],
            "ARNFormat": "arn:aws:health::<namespace>:<relative-id>",
            "ARNRegex": "^arn:aws:health:[^:]*:[^:]*:.+",
            "conditionKeys": ["health:eventTypeCode", "health:service"],
            "HasResource": true
        },
        "AWS Outposts": {
            "StringPrefix": "outposts",
            "Actions": ["CreateOutpost", "GetOutpost", "GetOutpostInstanceTypes", "ListOutposts", "ListSites"],
            "ARNFormat": "arn:aws:outposts:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:outposts:.+:.+:.+",
            "HasResource": true
        },
        "Amazon GameLift": {
            "StringPrefix": "gamelift",
            "Actions": ["AcceptMatch", "CreateAlias", "CreateBuild", "CreateFleet", "CreateGameSession", "CreateGameSessionQueue", "CreateMatchmakingConfiguration", "CreateMatchmakingRuleSet", "CreatePlayerSession", "CreatePlayerSessions", "CreateScript", "CreateVpcPeeringAuthorization", "CreateVpcPeeringConnection", "DeleteAlias", "DeleteBuild", "DeleteFleet", "DeleteGameSessionQueue", "DeleteMatchmakingConfiguration", "DeleteMatchmakingRuleSet", "DeleteScalingPolicy", "DeleteScript", "DeleteVpcPeeringAuthorization", "DeleteVpcPeeringConnection", "DescribeAlias", "DescribeBuild", "DescribeEC2InstanceLimits", "DescribeFleetAttributes", "DescribeFleetCapacity", "DescribeFleetEvents", "DescribeFleetPortSettings", "DescribeFleetUtilization", "DescribeGameSessionDetails", "DescribeGameSessionPlacement", "DescribeGameSessionQueues", "DescribeGameSessions", "DescribeInstances", "DescribeMatchmaking", "DescribeMatchmakingConfigurations", "DescribeMatchmakingRuleSets", "DescribePlayerSessions", "DescribeRuntimeConfiguration", "DescribeScalingPolicies", "DescribeScript", "DescribeVpcPeeringAuthorizations", "DescribeVpcPeeringConnections", "GetGameSessionLogUrl", "GetInstanceAccess", "ListAliases", "ListBuilds", "ListFleets", "ListScripts", "ListTagsForResource", "PutScalingPolicy", "RequestUploadCredentials", "ResolveAlias", "SearchGameSessions", "StartFleetActions", "StartGameSessionPlacement", "StartMatchBackfill", "StartMatchmaking", "StopFleetActions", "StopGameSessionPlacement", "StopMatchmaking", "TagResource", "UntagResource", "UpdateAlias", "UpdateBuild", "UpdateFleetAttributes", "UpdateFleetCapacity", "UpdateFleetPortSettings", "UpdateGameSession", "UpdateGameSessionQueue", "UpdateMatchmakingConfiguration", "UpdateRuntimeConfiguration", "UpdateScript", "ValidateMatchmakingRuleSet"],
            "ARNFormat": "arn:aws:gamelift:<region>:<accountId>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:aws:gamelift:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS OpsWorks Configuration Management": {
            "StringPrefix": "opsworks-cm",
            "Actions": ["AssociateNode", "CreateBackup", "CreateServer", "DeleteBackup", "DeleteServer", "DescribeAccountAttributes", "DescribeBackups", "DescribeEvents", "DescribeNodeAssociationStatus", "DescribeServers", "DisassociateNode", "RestoreServer", "StartMaintenance", "UpdateServer", "UpdateServerEngineAttributes"],
            "ARNFormat": "arn:aws:opsworks-cm:<region>:<account>:<resourceType>/<id>",
            "ARNRegex": "^arn:aws:opsworks-cm:.+:[0-9]+:.+",
            "HasResource": false
        },
        "Amazon EC2 Instance Connect": {
            "StringPrefix": "ec2-instance-connect",
            "Actions": ["SendSSHPublicKey"],
            "ARNFormat": "arn:aws:ec2:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:ec2:.+",
            "conditionKeys": ["ec2:osuser"],
            "HasResource": true
        },
        "Amazon RDS IAM Authentication": {
            "StringPrefix": "rds-db",
            "Actions": ["connect"],
            "ARNFormat": "arn:aws:rds-db:<region>:<account-id>:dbuser:<dbi-resource-id>/<db-user-name>",
            "ARNRegex": "^arn:aws:rds-db:.+",
            "HasResource": true
        },
        "Application Discovery": {
            "StringPrefix": "discovery",
            "Actions": ["AssociateConfigurationItemsToApplication", "BatchDeleteImportData", "CreateApplication", "CreateTags", "DeleteApplications", "DeleteTags", "DescribeAgents", "DescribeConfigurations", "DescribeContinuousExports", "DescribeExportConfigurations", "DescribeExportTasks", "DescribeImportTasks", "DescribeTags", "DisassociateConfigurationItemsFromApplication", "ExportConfigurations", "GetDiscoverySummary", "ListConfigurations", "ListServerNeighbors", "StartContinuousExport", "StartDataCollectionByAgentIds", "StartExportTask", "StartImportTask", "StopContinuousExport", "StopDataCollectionByAgentIds", "UpdateApplication"],
            "HasResource": false
        },
        "Amazon Elastic Block Store": {
            "StringPrefix": "ebs",
            "Actions": ["GetSnapshotBlock", "ListChangedBlocks", "ListSnapshotBlocks"],
            "ARNFormat": "arn:aws:ebs:<region>:<account>:<resourceType>/<resourcePath>",
            "ARNRegex": "^arn:aws:ebs:.+",
            "conditionKeys": ["aws:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "AWS CodeCommit": {
            "StringPrefix": "codecommit",
            "Actions": ["AssociateApprovalRuleTemplateWithRepository", "BatchAssociateApprovalRuleTemplateWithRepositories", "BatchDescribeMergeConflicts", "BatchDisassociateApprovalRuleTemplateFromRepositories", "BatchGetCommits", "BatchGetPullRequests", "BatchGetRepositories", "CancelUploadArchive", "CreateApprovalRuleTemplate", "CreateBranch", "CreateCommit", "CreatePullRequest", "CreatePullRequestApprovalRule", "CreateRepository", "CreateUnreferencedMergeCommit", "DeleteApprovalRuleTemplate", "DeleteBranch", "DeleteCommentContent", "DeleteFile", "DeletePullRequestApprovalRule", "DeleteRepository", "DescribeMergeConflicts", "DescribePullRequestEvents", "DisassociateApprovalRuleTemplateFromRepository", "EvaluatePullRequestApprovalRules", "GetApprovalRuleTemplate", "GetBlob", "GetBranch", "GetComment", "GetCommentsForComparedCommit", "GetCommentsForPullRequest", "GetCommit", "GetCommitHistory", "GetCommitsFromMergeBase", "GetDifferences", "GetFile", "GetFolder", "GetMergeCommit", "GetMergeConflicts", "GetMergeOptions", "GetObjectIdentifier", "GetPullRequest", "GetPullRequestApprovalStates", "GetPullRequestOverrideState", "GetReferences", "GetRepository", "GetRepositoryTriggers", "GetTree", "GetUploadArchiveStatus", "GitPull", "GitPush", "ListApprovalRuleTemplates", "ListAssociatedApprovalRuleTemplatesForRepository", "ListBranches", "ListPullRequests", "ListRepositories", "ListRepositoriesForApprovalRuleTemplate", "ListTagsForResource", "MergeBranchesByFastForward", "MergeBranchesBySquash", "MergeBranchesByThreeWay", "MergePullRequestByFastForward", "MergePullRequestBySquash", "MergePullRequestByThreeWay", "OverridePullRequestApprovalRules", "PostCommentForComparedCommit", "PostCommentForPullRequest", "PostCommentReply", "PutFile", "PutRepositoryTriggers", "TagResource", "TestRepositoryTriggers", "UntagResource", "UpdateApprovalRuleTemplateContent", "UpdateApprovalRuleTemplateDescription", "UpdateApprovalRuleTemplateName", "UpdateComment", "UpdateDefaultBranch", "UpdatePullRequestApprovalRuleContent", "UpdatePullRequestApprovalState", "UpdatePullRequestDescription", "UpdatePullRequestStatus", "UpdatePullRequestTitle", "UpdateRepositoryDescription", "UpdateRepositoryName", "UploadArchive"],
            "ARNFormat": "arn:aws:codecommit:<region>:<account_ID>:<repository_name>",
            "ARNRegex": "^arn:aws:codecommit:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "codecommit:References"],
            "HasResource": true
        },
        "Amazon CodeGuru Profiler": {
            "StringPrefix": "codeguru-profiler",
            "Actions": ["ConfigureAgent", "CreateProfilingGroup", "DeleteProfilingGroup", "DescribeProfilingGroup", "GetFindingsReport", "GetFindingsReportAccountSummary", "GetPolicy", "GetProfile", "GetRecommendations", "ListFindingsReports", "ListProfileTimes", "ListProfilingGroups", "PostAgentProfile", "PutPermission", "RemovePermission", "UpdateProfilingGroup"],
            "ARNFormat": "arn:aws:codeguru-profiler:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:codeguru-profiler:.+:.+:.+",
            "HasResource": true
        },
        "Amazon SNS": {
            "StringPrefix": "sns",
            "Actions": ["AddPermission", "CheckIfPhoneNumberIsOptedOut", "ConfirmSubscription", "CreatePlatformApplication", "CreatePlatformEndpoint", "CreateTopic", "DeleteEndpoint", "DeletePlatformApplication", "DeleteTopic", "GetEndpointAttributes", "GetPlatformApplicationAttributes", "GetSMSAttributes", "GetSubscriptionAttributes", "GetTopicAttributes", "ListEndpointsByPlatformApplication", "ListPhoneNumbersOptedOut", "ListPlatformApplications", "ListSubscriptions", "ListSubscriptionsByTopic", "ListTagsForResource", "ListTopics", "OptInPhoneNumber", "Publish", "RemovePermission", "SetEndpointAttributes", "SetPlatformApplicationAttributes", "SetSMSAttributes", "SetSubscriptionAttributes", "SetTopicAttributes", "Subscribe", "TagResource", "Unsubscribe", "UntagResource"],
            "ARNFormat": "arn:aws:sns:<region>:<account_ID>:<topic_name>",
            "ARNRegex": "^arn:aws:sns:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:TagKeys", "sns:Endpoint", "sns:Protocol"],
            "HasResource": true
        },
        "Amazon Cognito User Pools": {
            "StringPrefix": "cognito-idp",
            "Actions": ["AddCustomAttributes", "AdminAddUserToGroup", "AdminConfirmSignUp", "AdminCreateUser", "AdminDeleteUser", "AdminDeleteUserAttributes", "AdminDisableProviderForUser", "AdminDisableUser", "AdminEnableUser", "AdminForgetDevice", "AdminGetDevice", "AdminGetUser", "AdminInitiateAuth", "AdminLinkProviderForUser", "AdminListDevices", "AdminListGroupsForUser", "AdminListUserAuthEvents", "AdminRemoveUserFromGroup", "AdminResetUserPassword", "AdminRespondToAuthChallenge", "AdminSetUserMFAPreference", "AdminSetUserPassword", "AdminSetUserSettings", "AdminUpdateAuthEventFeedback", "AdminUpdateDeviceStatus", "AdminUpdateUserAttributes", "AdminUserGlobalSignOut", "AssociateSoftwareToken", "ChangePassword", "ConfirmDevice", "ConfirmForgotPassword", "ConfirmSignUp", "CreateGroup", "CreateIdentityProvider", "CreateResourceServer", "CreateUserImportJob", "CreateUserPool", "CreateUserPoolClient", "CreateUserPoolDomain", "DeleteGroup", "DeleteIdentityProvider", "DeleteResourceServer", "DeleteUser", "DeleteUserAttributes", "DeleteUserPool", "DeleteUserPoolClient", "DeleteUserPoolDomain", "DescribeIdentityProvider", "DescribeResourceServer", "DescribeRiskConfiguration", "DescribeUserImportJob", "DescribeUserPool", "DescribeUserPoolClient", "DescribeUserPoolDomain", "ForgetDevice", "ForgotPassword", "GetCSVHeader", "GetDevice", "GetGroup", "GetIdentityProviderByIdentifier", "GetSigningCertificate", "GetUICustomization", "GetUser", "GetUserAttributeVerificationCode", "GetUserPoolMfaConfig", "GlobalSignOut", "InitiateAuth", "ListDevices", "ListGroups", "ListIdentityProviders", "ListResourceServers", "ListTagsForResource", "ListUserImportJobs", "ListUserPoolClients", "ListUserPools", "ListUsers", "ListUsersInGroup", "ResendConfirmationCode", "RespondToAuthChallenge", "SetRiskConfiguration", "SetUICustomization", "SetUserMFAPreference", "SetUserPoolMfaConfig", "SetUserSettings", "SignUp", "StartUserImportJob", "StopUserImportJob", "TagResource", "UntagResource", "UpdateAuthEventFeedback", "UpdateDeviceStatus", "UpdateGroup", "UpdateIdentityProvider", "UpdateResourceServer", "UpdateUserAttributes", "UpdateUserPool", "UpdateUserPoolClient", "UpdateUserPoolDomain", "VerifySoftwareToken", "VerifyUserAttribute"],
            "ARNFormat": "arn:aws:cognito-idp:<region>:<account>:<resourceType>/<resourcePath>:",
            "ARNRegex": "^arn:aws:cognito-idp:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Elastic Beanstalk": {
            "StringPrefix": "elasticbeanstalk",
            "Actions": ["AbortEnvironmentUpdate", "AddTags", "ApplyEnvironmentManagedAction", "CheckDNSAvailability", "ComposeEnvironments", "CreateApplication", "CreateApplicationVersion", "CreateConfigurationTemplate", "CreateEnvironment", "CreatePlatformVersion", "CreateStorageLocation", "DeleteApplication", "DeleteApplicationVersion", "DeleteConfigurationTemplate", "DeleteEnvironmentConfiguration", "DeletePlatformVersion", "DescribeAccountAttributes", "DescribeApplicationVersions", "DescribeApplications", "DescribeConfigurationOptions", "DescribeConfigurationSettings", "DescribeEnvironmentHealth", "DescribeEnvironmentManagedActionHistory", "DescribeEnvironmentManagedActions", "DescribeEnvironmentResources", "DescribeEnvironments", "DescribeEvents", "DescribeInstancesHealth", "DescribePlatformVersion", "ListAvailableSolutionStacks", "ListPlatformBranches", "ListPlatformVersions", "ListTagsForResource", "RebuildEnvironment", "RemoveTags", "RequestEnvironmentInfo", "RestartAppServer", "RetrieveEnvironmentInfo", "SwapEnvironmentCNAMEs", "TerminateEnvironment", "UpdateApplication", "UpdateApplicationResourceLifecycle", "UpdateApplicationVersion", "UpdateConfigurationTemplate", "UpdateEnvironment", "ValidateConfigurationSettings"],
            "ARNFormat": "arn:aws:elasticbeanstalk:<region>:<account_ID>:<resource_type>/<path_to_resource>",
            "ARNRegex": "^arn:aws:elasticbeanstalk:.+:.*:.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "elasticbeanstalk:FromApplication", "elasticbeanstalk:FromApplicationVersion", "elasticbeanstalk:FromConfigurationTemplate", "elasticbeanstalk:FromEnvironment", "elasticbeanstalk:FromPlatform", "elasticbeanstalk:FromSolutionStack", "elasticbeanstalk:InApplication"],
            "HasResource": true
        },
        "CloudWatch Application Insights": {
            "StringPrefix": "applicationinsights",
            "Actions": ["CreateApplication", "CreateComponent", "DeleteApplication", "DeleteComponent", "DescribeApplication", "DescribeComponent", "DescribeComponentConfiguration", "DescribeComponentConfigurationRecommendation", "DescribeObservation", "DescribeProblem", "DescribeProblemObservations", "ListApplications", "ListComponents", "ListProblems", "UpdateApplication", "UpdateComponent", "UpdateComponentConfiguration"],
            "HasResource": false
        },
        "Elastic Load Balancing V2": {
            "StringPrefix": "elasticloadbalancing",
            "Actions": ["AddListenerCertificates", "AddTags", "CreateListener", "CreateLoadBalancer", "CreateRule", "CreateTargetGroup", "DeleteListener", "DeleteLoadBalancer", "DeleteRule", "DeleteTargetGroup", "DeregisterTargets", "DescribeAccountLimits", "DescribeListenerCertificates", "DescribeListeners", "DescribeLoadBalancerAttributes", "DescribeLoadBalancers", "DescribeRules", "DescribeSSLPolicies", "DescribeTags", "DescribeTargetGroupAttributes", "DescribeTargetGroups", "DescribeTargetHealth", "ModifyListener", "ModifyLoadBalancerAttributes", "ModifyRule", "ModifyTargetGroup", "ModifyTargetGroupAttributes", "RegisterTargets", "RemoveListenerCertificates", "RemoveTags", "SetIpAddressType", "SetRulePriorities", "SetSecurityGroups", "SetSubnets", "SetWebAcl"],
            "ARNFormat": "arn:aws:elasticloadbalancing:<region>:<account>:<resourceType>/<resourceid>",
            "ARNRegex": "^arn:aws:elasticloadbalancing:.+",
            "conditionKeys": ["aws:RequestTag/tag-key", "aws:TagKeys", "elasticloadbalancing:ResourceTag/tag-key"],
            "HasResource": true
        },
        "Elastic Load Balancing": {
            "StringPrefix": "elasticloadbalancing",
            "Actions": ["AddTags", "ApplySecurityGroupsToLoadBalancer", "AttachLoadBalancerToSubnets", "ConfigureHealthCheck", "CreateAppCookieStickinessPolicy", "CreateLBCookieStickinessPolicy", "CreateLoadBalancer", "CreateLoadBalancerListeners", "CreateLoadBalancerPolicy", "DeleteLoadBalancer", "DeleteLoadBalancerListeners", "DeleteLoadBalancerPolicy", "DeregisterInstancesFromLoadBalancer", "DescribeInstanceHealth", "DescribeLoadBalancerAttributes", "DescribeLoadBalancerPolicies", "DescribeLoadBalancerPolicyTypes", "DescribeLoadBalancers", "DescribeTags", "DetachLoadBalancerFromSubnets", "DisableAvailabilityZonesForLoadBalancer", "EnableAvailabilityZonesForLoadBalancer", "ModifyLoadBalancerAttributes", "RegisterInstancesWithLoadBalancer", "RemoveTags", "SetLoadBalancerListenerSSLCertificate", "SetLoadBalancerPoliciesForBackendServer", "SetLoadBalancerPoliciesOfListener"],
            "ARNFormat": "arn:aws:elasticloadbalancing:<region>:<account>:<resourceType>/<resourceid>",
            "ARNRegex": "^arn:aws:elasticloadbalancing:.+",
            "conditionKeys": ["aws:RequestTag/tag-key", "aws:TagKeys", "elasticloadbalancing:ResourceTag/", "elasticloadbalancing:ResourceTag/tag-key"],
            "HasResource": true
        },
        "Amazon Translate": {
            "StringPrefix": "translate",
            "Actions": ["DeleteTerminology", "DescribeTextTranslationJob", "GetTerminology", "ImportTerminology", "ListTerminologies", "ListTextTranslationJobs", "StartTextTranslationJob", "StopTextTranslationJob", "TranslateText"],
            "ARNFormat": "arn:${Partition}:translate:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:translate:.+:.+:.+",
            "HasResource": false
        },
        "AWS WAF Regional": {
            "StringPrefix": "waf-regional",
            "Actions": ["AssociateWebACL", "CreateByteMatchSet", "CreateGeoMatchSet", "CreateIPSet", "CreateRateBasedRule", "CreateRegexMatchSet", "CreateRegexPatternSet", "CreateRule", "CreateRuleGroup", "CreateSizeConstraintSet", "CreateSqlInjectionMatchSet", "CreateWebACL", "CreateXssMatchSet", "DeleteByteMatchSet", "DeleteGeoMatchSet", "DeleteIPSet", "DeleteLoggingConfiguration", "DeletePermissionPolicy", "DeleteRateBasedRule", "DeleteRegexMatchSet", "DeleteRegexPatternSet", "DeleteRule", "DeleteRuleGroup", "DeleteSizeConstraintSet", "DeleteSqlInjectionMatchSet", "DeleteWebACL", "DeleteXssMatchSet", "DisassociateWebACL", "GetByteMatchSet", "GetChangeToken", "GetChangeTokenStatus", "GetGeoMatchSet", "GetIPSet", "GetLoggingConfiguration", "GetPermissionPolicy", "GetRateBasedRule", "GetRateBasedRuleManagedKeys", "GetRegexMatchSet", "GetRegexPatternSet", "GetRule", "GetRuleGroup", "GetSampledRequests", "GetSizeConstraintSet", "GetSqlInjectionMatchSet", "GetWebACL", "GetWebACLForResource", "GetXssMatchSet", "ListActivatedRulesInRuleGroup", "ListByteMatchSets", "ListGeoMatchSets", "ListIPSets", "ListLoggingConfigurations", "ListRateBasedRules", "ListRegexMatchSets", "ListRegexPatternSets", "ListResourcesForWebACL", "ListRuleGroups", "ListRules", "ListSizeConstraintSets", "ListSqlInjectionMatchSets", "ListSubscribedRuleGroups", "ListTagsForResource", "ListWebACLs", "ListXssMatchSets", "PutLoggingConfiguration", "PutPermissionPolicy", "TagResource", "UntagResource", "UpdateByteMatchSet", "UpdateGeoMatchSet", "UpdateIPSet", "UpdateRateBasedRule", "UpdateRegexMatchSet", "UpdateRegexPatternSet", "UpdateRule", "UpdateRuleGroup", "UpdateSizeConstraintSet", "UpdateSqlInjectionMatchSet", "UpdateWebACL", "UpdateXssMatchSet"],
            "ARNFormat": "arn:aws:waf-regional:<region>:<account_ID>:<resource>/<resource_id>",
            "ARNRegex": "^arn:aws:waf-regional:.+:[0-9]+:.+/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Elastic Container Service": {
            "StringPrefix": "ecs",
            "Actions": ["CreateCluster", "CreateService", "CreateTaskSet", "DeleteAccountSetting", "DeleteAttributes", "DeleteCluster", "DeleteService", "DeleteTaskSet", "DeregisterContainerInstance", "DeregisterTaskDefinition", "DescribeClusters", "DescribeContainerInstances", "DescribeServices", "DescribeTaskDefinition", "DescribeTaskSets", "DescribeTasks", "DiscoverPollEndpoint", "ListAccountSettings", "ListAttributes", "ListClusters", "ListContainerInstances", "ListServices", "ListTagsForResource", "ListTaskDefinitionFamilies", "ListTaskDefinitions", "ListTasks", "Poll", "PutAccountSetting", "PutAccountSettingDefault", "PutAttributes", "RegisterContainerInstance", "RegisterTaskDefinition", "RunTask", "StartTask", "StartTelemetrySession", "StopTask", "SubmitAttachmentStateChanges", "SubmitContainerStateChange", "SubmitTaskStateChange", "TagResource", "UntagResource", "UpdateContainerAgent", "UpdateContainerInstancesState", "UpdateService", "UpdateServicePrimaryTaskSet", "UpdateTaskSet"],
            "ARNFormat": "arn:aws:ecs:<region>:<account_ID>:<resource_type>/<relative_ID>",
            "ARNRegex": "^arn:aws:ecs:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "ecs:ResourceTag/${TagKey}", "ecs:cluster", "ecs:container-instances", "ecs:service", "ecs:task-definition"],
            "HasResource": true
        },
        "Amazon Elastic Container Registry": {
            "StringPrefix": "ecr",
            "Actions": ["BatchCheckLayerAvailability", "BatchDeleteImage", "BatchGetImage", "CompleteLayerUpload", "CreateRepository", "DeleteLifecyclePolicy", "DeleteRepository", "DeleteRepositoryPolicy", "DescribeImageScanFindings", "DescribeImages", "DescribeRepositories", "GetAuthorizationToken", "GetDownloadUrlForLayer", "GetLifecyclePolicy", "GetLifecyclePolicyPreview", "GetRepositoryPolicy", "InitiateLayerUpload", "ListImages", "ListTagsForResource", "PutImage", "PutImageScanningConfiguration", "PutImageTagMutability", "PutLifecyclePolicy", "SetRepositoryPolicy", "StartImageScan", "StartLifecyclePolicyPreview", "TagResource", "UntagResource", "UploadLayerPart"],
            "ARNFormat": "arn:aws:ecr:<region>:<account_ID>:repository/<repository_name>",
            "ARNRegex": "^arn:aws:ecr:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "ecr:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "Amazon DynamoDB Accelerator (DAX)": {
            "StringPrefix": "dax",
            "Actions": ["BatchGetItem", "BatchWriteItem", "ConditionCheckItem", "CreateCluster", "CreateParameterGroup", "CreateSubnetGroup", "DecreaseReplicationFactor", "DeleteCluster", "DeleteItem", "DeleteParameterGroup", "DeleteSubnetGroup", "DescribeClusters", "DescribeDefaultParameters", "DescribeEvents", "DescribeParameterGroups", "DescribeParameters", "DescribeSubnetGroups", "GetItem", "IncreaseReplicationFactor", "ListTags", "PutItem", "Query", "RebootNode", "Scan", "TagResource", "UntagResource", "UpdateCluster", "UpdateItem", "UpdateParameterGroup", "UpdateSubnetGroup"],
            "ARNFormat": "arn:aws:dax:<region>:<accountId>:cache/<clustername>",
            "ARNRegex": "^arn:aws:dax:.+:[0-9]+:cache/[a-zA-Z0-9_.-]+",
            "conditionKeys": ["dax:EnclosingOperation"],
            "HasResource": true
        },
        "Amazon Resource Group Tagging API": {
            "StringPrefix": "tag",
            "Actions": ["DescribeReportCreation", "GetComplianceSummary", "GetResources", "GetTagKeys", "GetTagValues", "StartReportCreation", "TagResources", "UntagResources"],
            "HasResource": false
        },
        "Amazon CloudWatch Logs": {
            "StringPrefix": "logs",
            "Actions": ["AssociateKmsKey", "CancelExportTask", "CreateExportTask", "CreateLogDelivery", "CreateLogGroup", "CreateLogStream", "DeleteDestination", "DeleteLogDelivery", "DeleteLogGroup", "DeleteLogStream", "DeleteMetricFilter", "DeleteResourcePolicy", "DeleteRetentionPolicy", "DeleteSubscriptionFilter", "DescribeDestinations", "DescribeExportTasks", "DescribeLogGroups", "DescribeLogStreams", "DescribeMetricFilters", "DescribeQueries", "DescribeResourcePolicies", "DescribeSubscriptionFilters", "DisassociateKmsKey", "FilterLogEvents", "GetLogDelivery", "GetLogEvents", "GetLogGroupFields", "GetLogRecord", "GetQueryResults", "ListLogDeliveries", "ListTagsLogGroup", "PutDestination", "PutDestinationPolicy", "PutLogEvents", "PutMetricFilter", "PutResourcePolicy", "PutRetentionPolicy", "PutSubscriptionFilter", "StartQuery", "StopQuery", "TagLogGroup", "TestMetricFilter", "UntagLogGroup", "UpdateLogDelivery"],
            "ARNFormat": "arn:aws:logs:.+:.+:.+",
            "ARNRegex": "^arn:aws:logs:.+",
            "HasResource": true
        },
        "AWS Service Catalog": {
            "StringPrefix": "servicecatalog",
            "Actions": ["AcceptPortfolioShare", "AssociateBudgetWithResource", "AssociatePrincipalWithPortfolio", "AssociateProductWithPortfolio", "AssociateServiceActionWithProvisioningArtifact", "AssociateTagOptionWithResource", "BatchAssociateServiceActionWithProvisioningArtifact", "BatchDisassociateServiceActionFromProvisioningArtifact", "CopyProduct", "CreateConstraint", "CreatePortfolio", "CreatePortfolioShare", "CreateProduct", "CreateProvisionedProductPlan", "CreateProvisioningArtifact", "CreateServiceAction", "CreateTagOption", "DeleteConstraint", "DeletePortfolio", "DeletePortfolioShare", "DeleteProduct", "DeleteProvisionedProductPlan", "DeleteProvisioningArtifact", "DeleteServiceAction", "DeleteTagOption", "DescribeConstraint", "DescribeCopyProductStatus", "DescribePortfolio", "DescribePortfolioShareStatus", "DescribeProduct", "DescribeProductAsAdmin", "DescribeProductView", "DescribeProvisionedProduct", "DescribeProvisionedProductPlan", "DescribeProvisioningArtifact", "DescribeProvisioningParameters", "DescribeRecord", "DescribeServiceAction", "DescribeServiceActionExecutionParameters", "DescribeTagOption", "DisableAWSOrganizationsAccess", "DisassociateBudgetFromResource", "DisassociatePrincipalFromPortfolio", "DisassociateProductFromPortfolio", "DisassociateServiceActionFromProvisioningArtifact", "DisassociateTagOptionFromResource", "EnableAWSOrganizationsAccess", "ExecuteProvisionedProductPlan", "ExecuteProvisionedProductServiceAction", "GetAWSOrganizationsAccessStatus", "ListAcceptedPortfolioShares", "ListBudgetsForResource", "ListConstraintsForPortfolio", "ListLaunchPaths", "ListOrganizationPortfolioAccess", "ListPortfolioAccess", "ListPortfolios", "ListPortfoliosForProduct", "ListPrincipalsForPortfolio", "ListProvisionedProductPlans", "ListProvisioningArtifacts", "ListProvisioningArtifactsForServiceAction", "ListRecordHistory", "ListResourcesForTagOption", "ListServiceActions", "ListServiceActionsForProvisioningArtifact", "ListStackInstancesForProvisionedProduct", "ListTagOptions", "ProvisionProduct", "RejectPortfolioShare", "ScanProvisionedProducts", "SearchProducts", "SearchProductsAsAdmin", "SearchProvisionedProducts", "TerminateProvisionedProduct", "UpdateConstraint", "UpdatePortfolio", "UpdateProduct", "UpdateProvisionedProduct", "UpdateProvisionedProductProperties", "UpdateProvisioningArtifact", "UpdateServiceAction", "UpdateTagOption"],
            "ARNFormat": "arn:aws:(catalog|servicecatalog):<region>:<account>:<resourceType>/<id>",
            "ARNRegex": "^arn:aws:(catalog|servicecatalog):.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "servicecatalog:accountLevel", "servicecatalog:roleLevel", "servicecatalog:userLevel"],
            "HasResource": true
        },
        "Amazon MQ": {
            "StringPrefix": "mq",
            "Actions": ["CreateBroker", "CreateConfiguration", "CreateTags", "CreateUser", "DeleteBroker", "DeleteTags", "DeleteUser", "DescribeBroker", "DescribeBrokerEngineTypes", "DescribeBrokerInstanceOptions", "DescribeConfiguration", "DescribeConfigurationRevision", "DescribeUser", "ListBrokers", "ListConfigurationRevisions", "ListConfigurations", "ListTags", "ListUsers", "RebootBroker", "UpdateBroker", "UpdateConfiguration", "UpdateUser"],
            "ARNFormat": "arn:${Partition}:mq:<region>:<account>:.+",
            "ARNRegex": "^arn:${Partition}:mq:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Personalize": {
            "StringPrefix": "personalize",
            "Actions": ["CreateCampaign", "CreateDataset", "CreateDatasetGroup", "CreateDatasetImportJob", "CreateEventTracker", "CreateSchema", "CreateSolution", "CreateSolutionVersion", "DeleteCampaign", "DeleteDataset", "DeleteDatasetGroup", "DeleteEventTracker", "DeleteSchema", "DeleteSolution", "DescribeAlgorithm", "DescribeCampaign", "DescribeDataset", "DescribeDatasetGroup", "DescribeDatasetImportJob", "DescribeEventTracker", "DescribeFeatureTransformation", "DescribeRecipe", "DescribeSchema", "DescribeSolution", "DescribeSolutionVersion", "GetPersonalizedRanking", "GetRecommendations", "GetSolutionMetrics", "ListCampaigns", "ListDatasetGroups", "ListDatasetImportJobs", "ListDatasets", "ListEventTrackers", "ListRecipes", "ListSchemas", "ListSolutionVersions", "ListSolutions", "PutEvents", "UpdateCampaign"],
            "ARNFormat": "arn:aws:personalize:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:personalize:.+:.+:.+",
            "HasResource": true
        },
        "AWS Cloud9": {
            "StringPrefix": "cloud9",
            "Actions": ["CreateEnvironmentEC2", "CreateEnvironmentMembership", "DeleteEnvironment", "DeleteEnvironmentMembership", "DescribeEnvironmentMemberships", "DescribeEnvironmentStatus", "DescribeEnvironments", "GetUserSettings", "ListEnvironments", "ListTagsForResource", "TagResource", "UntagResource", "UpdateEnvironment", "UpdateEnvironmentMembership", "UpdateUserSettings"],
            "ARNFormat": "arn:aws:cloud9:<region>:<account-id>:<resource_type>:<resource_id>",
            "ARNRegex": "^arn:aws:cloud9:.+:[0-9]+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "cloud9:EnvironmentId", "cloud9:EnvironmentName", "cloud9:InstanceType", "cloud9:Permissions", "cloud9:SubnetId", "cloud9:UserArn"],
            "HasResource": true
        },
        "Amazon Detective": {
            "StringPrefix": "detective",
            "Actions": ["AcceptInvitation", "CreateGraph", "CreateMembers", "DeleteGraph", "DeleteMembers", "DisassociateMembership", "GetFreeTrialEligibility", "GetGraphIngestState", "GetMembers", "GetPricingInformation", "GetUsageInformation", "ListGraphs", "ListInvitations", "ListMembers", "RejectInvitation", "SearchGraph", "StartMonitoringMember"],
            "ARNFormat": "arn:aws:detective:${Region}:${AccountId}:graph:${GraphId}",
            "ARNRegex": "^arn:aws:detective:.+",
            "HasResource": true
        },
        "AWS Transfer for SFTP": {
            "StringPrefix": "transfer",
            "Actions": ["CreateServer", "CreateUser", "DeleteServer", "DeleteSshPublicKey", "DeleteUser", "DescribeServer", "DescribeUser", "ImportSshPublicKey", "ListServers", "ListTagsForResource", "ListUsers", "StartServer", "StopServer", "TagResource", "TestIdentityProvider", "UntagResource", "UpdateServer", "UpdateUser"],
            "ARNFormat": "arn:aws:transfer:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:transfer:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "IAM Access Analyzer": {
            "StringPrefix": "access-analyzer",
            "Actions": ["CreateAnalyzer", "CreateArchiveRule", "DeleteAnalyzer", "DeleteArchiveRule", "GetAnalyzedResource", "GetAnalyzer", "GetArchiveRule", "GetFinding", "ListAnalyzedResources", "ListAnalyzers", "ListArchiveRules", "ListFindings", "ListTagsForResource", "StartResourceScan", "TagResource", "UntagResource", "UpdateArchiveRule", "UpdateFindings"],
            "ARNFormat": "arn:${Partition}:access-analyzer::analyzer/${analyzerName}",
            "ARNRegex": "^arn:${Partition}:access-analyzer::.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Textract": {
            "StringPrefix": "textract",
            "Actions": ["AnalyzeDocument", "DetectDocumentText", "GetDocumentAnalysis", "GetDocumentTextDetection", "StartDocumentAnalysis", "StartDocumentTextDetection"],
            "ARNFormat": "arn:aws:textract:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:textract::.+",
            "HasResource": false
        },
        "Application Discovery Arsenal": {
            "StringPrefix": "arsenal",
            "Actions": ["RegisterOnPremisesAgent"],
            "HasResource": false
        },
        "Amazon GroundTruth Labeling": {
            "StringPrefix": "groundtruthlabeling",
            "Actions": ["DescribeConsoleJob", "ListDatasetObjects", "RunFilterOrSampleDatasetJob", "RunGenerateManifestByCrawlingJob"],
            "ARNFormat": "arn:${Partition}:groundtruthlabeling:${region}:${account}:${resourceType}/${resourcePath}",
            "ARNRegex": "^arn:${Partition}:groundtruthlabeling:.+",
            "HasResource": false
        },
        "AWS Elemental MediaStore": {
            "StringPrefix": "mediastore",
            "Actions": ["CreateContainer", "DeleteContainer", "DeleteContainerPolicy", "DeleteCorsPolicy", "DeleteLifecyclePolicy", "DeleteMetricPolicy", "DeleteObject", "DescribeContainer", "DescribeObject", "GetContainerPolicy", "GetCorsPolicy", "GetLifecyclePolicy", "GetMetricPolicy", "GetObject", "ListContainers", "ListItems", "ListTagsForResource", "PutContainerPolicy", "PutCorsPolicy", "PutLifecyclePolicy", "PutMetricPolicy", "PutObject", "StartAccessLogging", "StopAccessLogging", "TagResource", "UntagResource"],
            "ARNFormat": "arn:aws:mediastore:<Region>:<Account>:<Resource>",
            "ARNRegex": "^arn:aws:mediastore:.+:.+",
            "HasResource": true
        },
        "AWS IoT 1-Click": {
            "StringPrefix": "iot1click",
            "Actions": ["AssociateDeviceWithPlacement", "ClaimDevicesByClaimCode", "CreatePlacement", "CreateProject", "DeletePlacement", "DeleteProject", "DescribeDevice", "DescribePlacement", "DescribeProject", "DisassociateDeviceFromPlacement", "FinalizeDeviceClaim", "GetDeviceMethods", "GetDevicesInPlacement", "InitiateDeviceClaim", "InvokeDeviceMethod", "ListDeviceEvents", "ListDevices", "ListPlacements", "ListProjects", "ListTagsForResource", "TagResource", "UnclaimDevice", "UntagResource", "UpdateDeviceState", "UpdatePlacement", "UpdateProject"],
            "ARNFormat": "arn:aws:iot1click:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:iot1click:.+:[0-9]+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS CodePipeline": {
            "StringPrefix": "codepipeline",
            "Actions": ["AcknowledgeJob", "AcknowledgeThirdPartyJob", "CreateCustomActionType", "CreatePipeline", "DeleteCustomActionType", "DeletePipeline", "DeleteWebhook", "DeregisterWebhookWithThirdParty", "DisableStageTransition", "EnableStageTransition", "GetJobDetails", "GetPipeline", "GetPipelineExecution", "GetPipelineState", "GetThirdPartyJobDetails", "ListActionExecutions", "ListActionTypes", "ListPipelineExecutions", "ListPipelines", "ListTagsForResource", "ListWebhooks", "PollForJobs", "PollForThirdPartyJobs", "PutActionRevision", "PutApprovalResult", "PutJobFailureResult", "PutJobSuccessResult", "PutThirdPartyJobFailureResult", "PutThirdPartyJobSuccessResult", "PutWebhook", "RegisterWebhookWithThirdParty", "RetryStageExecution", "StartPipelineExecution", "StopPipelineExecution", "TagResource", "UntagResource", "UpdatePipeline"],
            "ARNFormat": "arn:aws:codepipeline:<region>:<account_ID>:<path_to_pipeline_resource>",
            "ARNRegex": "arn:aws:codepipeline:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Security Hub": {
            "StringPrefix": "securityhub",
            "Actions": ["AcceptInvitation", "BatchDisableStandards", "BatchEnableStandards", "BatchImportFindings", "BatchUpdateFindings", "CreateActionTarget", "CreateInsight", "CreateMembers", "DeclineInvitations", "DeleteActionTarget", "DeleteInsight", "DeleteInvitations", "DeleteMembers", "DescribeActionTargets", "DescribeHub", "DescribeProducts", "DescribeStandards", "DescribeStandardsControls", "DisableImportFindingsForProduct", "DisableSecurityHub", "DisassociateFromMasterAccount", "DisassociateMembers", "EnableImportFindingsForProduct", "EnableSecurityHub", "GetEnabledStandards", "GetFindings", "GetInsightResults", "GetInsights", "GetInvitationsCount", "GetMasterAccount", "GetMembers", "InviteMembers", "ListEnabledProductsForImport", "ListInvitations", "ListMembers", "ListTagsForResource", "TagResource", "UntagResource", "UpdateActionTarget", "UpdateFindings", "UpdateInsight", "UpdateStandardsControl"],
            "ARNFormat": "arn:${Partition}:securityhub:<region>:<account_ID>:.+",
            "ARNRegex": "^arn:${Partition}:securityhub:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "securityhub:TargetAccount"],
            "HasResource": true
        },
        "Amazon EC2 Image Builder": {
            "StringPrefix": "imagebuilder",
            "Actions": ["CancelImageCreation", "CreateComponent", "CreateDistributionConfiguration", "CreateImage", "CreateImagePipeline", "CreateImageRecipe", "CreateInfrastructureConfiguration", "DeleteComponent", "DeleteDistributionConfiguration", "DeleteImage", "DeleteImagePipeline", "DeleteImageRecipe", "DeleteInfrastructureConfiguration", "GetComponent", "GetComponentPolicy", "GetDistributionConfiguration", "GetImage", "GetImagePipeline", "GetImagePolicy", "GetImageRecipe", "GetImageRecipePolicy", "GetInfrastructureConfiguration", "ListComponentBuildVersions", "ListComponents", "ListDistributionConfigurations", "ListImageBuildVersions", "ListImagePipelines", "ListImageRecipes", "ListImages", "ListInfrastructureConfigurations", "ListTagsForResource", "PutComponentPolicy", "PutImagePolicy", "PutImageRecipePolicy", "StartImagePipelineExecution", "TagResource", "UntagResource", "UpdateDistributionConfiguration", "UpdateImagePipeline", "UpdateInfrastructureConfiguration"],
            "ARNFormat": "arn:aws:imagebuilder:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:imagebuilder:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon SQS": {
            "StringPrefix": "sqs",
            "Actions": ["AddPermission", "ChangeMessageVisibility", "ChangeMessageVisibilityBatch", "CreateQueue", "DeleteMessage", "DeleteMessageBatch", "DeleteQueue", "GetQueueAttributes", "GetQueueUrl", "ListDeadLetterSourceQueues", "ListQueueTags", "ListQueues", "PurgeQueue", "ReceiveMessage", "RemovePermission", "SendMessage", "SendMessageBatch", "SetQueueAttributes", "TagQueue", "UntagQueue"],
            "ARNFormat": "arn:aws:sqs:<region>:<account_ID>:<queue_name>",
            "ARNRegex": "^arn:aws:sqs:.+",
            "HasResource": true
        },
        "AWS Cloud Map": {
            "StringPrefix": "servicediscovery",
            "Actions": ["CreateHttpNamespace", "CreatePrivateDnsNamespace", "CreatePublicDnsNamespace", "CreateService", "DeleteNamespace", "DeleteService", "DeregisterInstance", "DiscoverInstances", "GetInstance", "GetInstancesHealthStatus", "GetNamespace", "GetOperation", "GetService", "ListInstances", "ListNamespaces", "ListOperations", "ListServices", "RegisterInstance", "UpdateInstanceCustomHealthStatus", "UpdateService"],
            "ARNFormat": "arn:aws:servicediscovery:<region>:<account-id>:<resource-type>/<resource_name>",
            "ARNRegex": "^arn:aws:servicediscovery:.+",
            "conditionKeys": ["servicediscovery:NamespaceArn", "servicediscovery:NamespaceName", "servicediscovery:ServiceArn", "servicediscovery:ServiceName"],
            "HasResource": true
        },
        "Compute Optimizer": {
            "StringPrefix": "compute-optimizer",
            "Actions": ["GetAutoScalingGroupRecommendations", "GetEC2InstanceRecommendations", "GetEC2RecommendationProjectedMetrics", "GetEnrollmentStatus", "GetRecommendationSummaries", "UpdateEnrollmentStatus"],
            "HasResource": false
        },
        "Amazon Glacier": {
            "StringPrefix": "glacier",
            "Actions": ["AbortMultipartUpload", "AbortVaultLock", "AddTagsToVault", "CompleteMultipartUpload", "CompleteVaultLock", "CreateVault", "DeleteArchive", "DeleteVault", "DeleteVaultAccessPolicy", "DeleteVaultNotifications", "DescribeJob", "DescribeVault", "GetDataRetrievalPolicy", "GetJobOutput", "GetVaultAccessPolicy", "GetVaultLock", "GetVaultNotifications", "InitiateJob", "InitiateMultipartUpload", "InitiateVaultLock", "ListJobs", "ListMultipartUploads", "ListParts", "ListProvisionedCapacity", "ListTagsForVault", "ListVaults", "PurchaseProvisionedCapacity", "RemoveTagsFromVault", "SetDataRetrievalPolicy", "SetVaultAccessPolicy", "SetVaultNotifications", "UploadArchive", "UploadMultipartPart"],
            "ARNFormat": "arn:aws:glacier:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:glacier:.+:.+:.+",
            "conditionKeys": ["glacier:ArchiveAgeInDays", "glacier:ResourceTag/"],
            "HasResource": true
        },
        "Amazon Rekognition": {
            "StringPrefix": "rekognition",
            "Actions": ["CompareFaces", "CreateCollection", "CreateProject", "CreateProjectVersion", "CreateStreamProcessor", "DeleteCollection", "DeleteFaces", "DeleteProject", "DeleteProjectVersion", "DeleteStreamProcessor", "DescribeCollection", "DescribeProjectVersions", "DescribeProjects", "DescribeStreamProcessor", "DetectCustomLabels", "DetectFaces", "DetectLabels", "DetectModerationLabels", "DetectText", "GetCelebrityInfo", "GetCelebrityRecognition", "GetContentModeration", "GetFaceDetection", "GetFaceSearch", "GetLabelDetection", "GetPersonTracking", "GetTextDetection", "IndexFaces", "ListCollections", "ListFaces", "ListStreamProcessors", "RecognizeCelebrities", "SearchFaces", "SearchFacesByImage", "StartCelebrityRecognition", "StartContentModeration", "StartFaceDetection", "StartFaceSearch", "StartLabelDetection", "StartPersonTracking", "StartProjectVersion", "StartStreamProcessor", "StartTextDetection", "StopProjectVersion", "StopStreamProcessor"],
            "ARNFormat": "arn:aws:rekognition:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:rekognition::.+",
            "HasResource": true
        },
        "Launch Wizard": {
            "StringPrefix": "launchwizard",
            "Actions": ["DeleteApp", "DescribeProvisionedApp", "DescribeProvisioningEvents", "GetInfrastructureSuggestion", "GetIpAddress", "GetResourceCostEstimate", "ListProvisionedApps", "StartProvisioning"],
            "ARNRegex": "^arn:aws:launchwizard:.+:.+:.+",
            "HasResource": false
        },
        "AWS Elemental MediaConvert": {
            "StringPrefix": "mediaconvert",
            "Actions": ["AssociateCertificate", "CancelJob", "CreateJob", "CreateJobTemplate", "CreatePreset", "CreateQueue", "DeleteJobTemplate", "DeletePreset", "DeleteQueue", "DescribeEndpoints", "DisassociateCertificate", "GetJob", "GetJobTemplate", "GetPreset", "GetQueue", "ListJobTemplates", "ListJobs", "ListPresets", "ListQueues", "ListTagsForResource", "TagResource", "UntagResource", "UpdateJobTemplate", "UpdatePreset", "UpdateQueue"],
            "ARNFormat": "arn:${Partition}:mediaconvert:<region>:<account>:<resourceType>/<resourceId>",
            "ARNRegex": "^arn:${Partition}:mediaconvert:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Service Quotas": {
            "StringPrefix": "servicequotas",
            "Actions": ["AssociateServiceQuotaTemplate", "DeleteServiceQuotaIncreaseRequestFromTemplate", "DisassociateServiceQuotaTemplate", "GetAWSDefaultServiceQuota", "GetAssociationForServiceQuotaTemplate", "GetRequestedServiceQuotaChange", "GetServiceQuota", "GetServiceQuotaIncreaseRequestFromTemplate", "ListAWSDefaultServiceQuotas", "ListRequestedServiceQuotaChangeHistory", "ListRequestedServiceQuotaChangeHistoryByQuota", "ListServiceQuotaIncreaseRequestsInTemplate", "ListServiceQuotas", "ListServices", "PutServiceQuotaIncreaseRequestIntoTemplate", "RequestServiceQuotaIncrease"],
            "ARNFormat": "arn:aws:servicequotas:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:aws:servicequotas:.+",
            "conditionKeys": ["servicequotas:service"],
            "HasResource": true
        },
        "Amazon Inspector": {
            "StringPrefix": "inspector",
            "Actions": ["AddAttributesToFindings", "CreateAssessmentTarget", "CreateAssessmentTemplate", "CreateResourceGroup", "DeleteAssessmentRun", "DeleteAssessmentTarget", "DeleteAssessmentTemplate", "DescribeAssessmentRuns", "DescribeAssessmentTargets", "DescribeAssessmentTemplates", "DescribeCrossAccountAccessRole", "DescribeFindings", "DescribeResourceGroups", "DescribeRulesPackages", "GetTelemetryMetadata", "ListAssessmentRunAgents", "ListAssessmentRuns", "ListAssessmentTargets", "ListAssessmentTemplates", "ListEventSubscriptions", "ListFindings", "ListRulesPackages", "ListTagsForResource", "PreviewAgents", "RegisterCrossAccountAccessRole", "RemoveAttributesFromFindings", "SetTagsForResource", "StartAssessmentRun", "StopAssessmentRun", "SubscribeToEvent", "UnsubscribeFromEvent", "UpdateAssessmentTarget"],
            "HasResource": false
        },
        "AWS RoboMaker": {
            "StringPrefix": "robomaker",
            "Actions": ["BatchDescribeSimulationJob", "CancelDeploymentJob", "CancelSimulationJob", "CancelSimulationJobBatch", "CreateDeploymentJob", "CreateFleet", "CreateRobot", "CreateRobotApplication", "CreateRobotApplicationVersion", "CreateSimulationApplication", "CreateSimulationApplicationVersion", "CreateSimulationJob", "DeleteFleet", "DeleteRobot", "DeleteRobotApplication", "DeleteSimulationApplication", "DeregisterRobot", "DescribeDeploymentJob", "DescribeFleet", "DescribeRobot", "DescribeRobotApplication", "DescribeSimulationApplication", "DescribeSimulationJob", "DescribeSimulationJobBatch", "ListDeploymentJobs", "ListFleets", "ListRobotApplications", "ListRobots", "ListSimulationApplications", "ListSimulationJobBatches", "ListSimulationJobs", "ListTagsForResource", "RegisterRobot", "RestartSimulationJob", "StartSimulationJobBatch", "SyncDeploymentJob", "TagResource", "UntagResource", "UpdateRobotApplication", "UpdateSimulationApplication"],
            "ARNFormat": "arn:${Partition}:robomaker:${Region}:${AccountId}:${ResourceType}/${ResourceName}",
            "ARNRegex": "^arn:${Partition}:robomaker:.+:.+:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon QLDB": {
            "StringPrefix": "qldb",
            "Actions": ["CreateLedger", "DeleteLedger", "DescribeJournalS3Export", "DescribeLedger", "ExecuteStatement", "ExportJournalToS3", "GetBlock", "GetDigest", "GetRevision", "InsertSampleData", "ListJournalS3Exports", "ListJournalS3ExportsForLedger", "ListLedgers", "ListTagsForResource", "SendCommand", "ShowCatalog", "TagResource", "UntagResource", "UpdateLedger"],
            "ARNFormat": "arn:${Partition}:qldb:${region}:${account}:${resourceType}/${resourcePath}",
            "ARNRegex": "^arn:${Partition}:qldb:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS CodeStar": {
            "StringPrefix": "codestar",
            "Actions": ["AssociateTeamMember", "CreateProject", "CreateUserProfile", "DeleteExtendedAccess", "DeleteProject", "DeleteUserProfile", "DescribeProject", "DescribeUserProfile", "DisassociateTeamMember", "GetExtendedAccess", "ListProjects", "ListResources", "ListTagsForProject", "ListTeamMembers", "ListUserProfiles", "PutExtendedAccess", "TagProject", "UntagProject", "UpdateProject", "UpdateTeamMember", "UpdateUserProfile"],
            "ARNFormat": "arn:aws:codestar:<region>:<account_ID>:<resource_type>/<resource_id>",
            "ARNRegex": "^arn:aws:codestar:.+:[0-9]+:project/.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys", "iam:ResourceTag/${TagKey}"],
            "HasResource": true
        },
        "AWS Direct Connect": {
            "StringPrefix": "directconnect",
            "Actions": ["AcceptDirectConnectGatewayAssociationProposal", "AllocateConnectionOnInterconnect", "AllocateHostedConnection", "AllocatePrivateVirtualInterface", "AllocatePublicVirtualInterface", "AllocateTransitVirtualInterface", "AssociateConnectionWithLag", "AssociateHostedConnection", "AssociateVirtualInterface", "ConfirmConnection", "ConfirmPrivateVirtualInterface", "ConfirmPublicVirtualInterface", "ConfirmTransitVirtualInterface", "CreateBGPPeer", "CreateConnection", "CreateDirectConnectGateway", "CreateDirectConnectGatewayAssociation", "CreateDirectConnectGatewayAssociationProposal", "CreateInterconnect", "CreateLag", "CreatePrivateVirtualInterface", "CreatePublicVirtualInterface", "CreateTransitVirtualInterface", "DeleteBGPPeer", "DeleteConnection", "DeleteDirectConnectGateway", "DeleteDirectConnectGatewayAssociation", "DeleteDirectConnectGatewayAssociationProposal", "DeleteInterconnect", "DeleteLag", "DeleteVirtualInterface", "DescribeConnectionLoa", "DescribeConnections", "DescribeConnectionsOnInterconnect", "DescribeDirectConnectGatewayAssociationProposals", "DescribeDirectConnectGatewayAssociations", "DescribeDirectConnectGatewayAttachments", "DescribeDirectConnectGateways", "DescribeHostedConnections", "DescribeInterconnectLoa", "DescribeInterconnects", "DescribeLags", "DescribeLoa", "DescribeLocations", "DescribeTags", "DescribeVirtualGateways", "DescribeVirtualInterfaces", "DisassociateConnectionFromLag", "TagResource", "UntagResource", "UpdateDirectConnectGatewayAssociation", "UpdateLag", "UpdateVirtualInterfaceAttributes"],
            "ARNFormat": "arn:${Partition}:directconnect:${Region}:${Account}:${ResourceType}/${ResourceId}",
            "ARNRegex": "^arn:${Partition}:directconnect:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Neptune": {
            "StringPrefix": "neptune-db",
            "Actions": ["connect"],
            "ARNFormat": "arn:aws:neptune-db:<region>:<accountID>:<relative-id>",
            "ARNRegex": "^arn:aws:neptune-db:.+",
            "HasResource": true
        },
        "DataSync": {
            "StringPrefix": "datasync",
            "Actions": ["CancelTaskExecution", "CreateAgent", "CreateLocationEfs", "CreateLocationNfs", "CreateLocationS3", "CreateLocationSmb", "CreateTask", "DeleteAgent", "DeleteLocation", "DeleteTask", "DescribeAgent", "DescribeLocationEfs", "DescribeLocationNfs", "DescribeLocationS3", "DescribeLocationSmb", "DescribeTask", "DescribeTaskExecution", "ListAgents", "ListLocations", "ListTagsForResource", "ListTaskExecutions", "ListTasks", "StartTaskExecution", "TagResource", "UntagResource", "UpdateAgent", "UpdateTask"],
            "ARNFormat": "arn:${Partition}:datasync:<region>:<account>:<resourceType>/<resourceName>",
            "ARNRegex": "^arn:${Partition}:datasync:.+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Organizations": {
            "StringPrefix": "organizations",
            "Actions": ["AcceptHandshake", "AttachPolicy", "CancelHandshake", "CreateAccount", "CreateGovCloudAccount", "CreateOrganization", "CreateOrganizationalUnit", "CreatePolicy", "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit", "DeletePolicy", "DescribeAccount", "DescribeCreateAccountStatus", "DescribeEffectivePolicy", "DescribeHandshake", "DescribeOrganization", "DescribeOrganizationalUnit", "DescribePolicy", "DetachPolicy", "DisableAWSServiceAccess", "DisablePolicyType", "EnableAWSServiceAccess", "EnableAllFeatures", "EnablePolicyType", "InviteAccountToOrganization", "LeaveOrganization", "ListAWSServiceAccessForOrganization", "ListAccounts", "ListAccountsForParent", "ListChildren", "ListCreateAccountStatus", "ListHandshakesForAccount", "ListHandshakesForOrganization", "ListOrganizationalUnitsForParent", "ListParents", "ListPolicies", "ListPoliciesForTarget", "ListRoots", "ListTagsForResource", "ListTargetsForPolicy", "MoveAccount", "RemoveAccountFromOrganization", "TagResource", "UntagResource", "UpdateOrganizationalUnit", "UpdatePolicy"],
            "ARNFormat": "arn:${Partition}:organizations::<masterAccountId>:<resource>/o-<organizationId>(/<resourceType>/<resourceId>)?",
            "ARNRegex": "^arn:${Partition}:organizations::.+:.+",
            "conditionKeys": ["organizations:PolicyType", "organizations:ServicePrincipal"],
            "HasResource": true
        },
        "AWS Performance Insights": {
            "StringPrefix": "pi",
            "Actions": ["DescribeDimensionKeys", "GetResourceMetrics"],
            "ARNFormat": "arn:aws:pi:<region>:<account>:<resource-type>/<relative-id>",
            "ARNRegex": "^arn:aws:pi:.+",
            "HasResource": true
        },
        "Amazon Kinesis Analytics V2": {
            "StringPrefix": "kinesisanalytics",
            "Actions": ["AddApplicationCloudWatchLoggingOption", "AddApplicationInput", "AddApplicationInputProcessingConfiguration", "AddApplicationOutput", "AddApplicationReferenceDataSource", "AddApplicationVpcConfiguration", "CreateApplication", "CreateApplicationSnapshot", "DeleteApplication", "DeleteApplicationCloudWatchLoggingOption", "DeleteApplicationInputProcessingConfiguration", "DeleteApplicationOutput", "DeleteApplicationReferenceDataSource", "DeleteApplicationSnapshot", "DeleteApplicationVpcConfiguration", "DescribeApplication", "DescribeApplicationSnapshot", "DiscoverInputSchema", "ListApplicationSnapshots", "ListApplications", "ListTagsForResource", "StartApplication", "StopApplication", "TagResource", "UntagResource", "UpdateApplication"],
            "ARNFormat": "arn:aws:kinesisanalytics:<region>:<account_ID>:application/<applicationname>",
            "ARNRegex": "^arn:aws:kinesisanalytics:.+:[0-9]+:application/[a-zA-Z0-9_.-]+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "Amazon Kinesis Analytics": {
            "StringPrefix": "kinesisanalytics",
            "Actions": ["AddApplicationInput", "AddApplicationOutput", "AddApplicationReferenceDataSource", "CreateApplication", "DeleteApplication", "DeleteApplicationOutput", "DeleteApplicationReferenceDataSource", "DescribeApplication", "DiscoverInputSchema", "GetApplicationState", "ListApplications", "ListTagsForResource", "StartApplication", "StopApplication", "TagResource", "UntagResource", "UpdateApplication"],
            "ARNFormat": "arn:aws:kinesisanalytics:<region>:<account_ID>:application/<applicationname>",
            "ARNRegex": "^arn:aws:kinesisanalytics:.+:[0-9]+:application/[a-zA-Z0-9_.-]+",
            "conditionKeys": ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"],
            "HasResource": true
        },
        "AWS Accounts": {
            "StringPrefix": "account",
            "Actions": ["DisableRegion", "EnableRegion", "ListRegions"],
            "conditionKeys": ["account:TargetRegion"],
            "HasResource": false
        }
    },
    "policyTypes": {
        "SQSPolicy": {"Name": "SQS Queue Policy", "AssociatedService": ["Amazon SQS"]},
        "S3Policy": {"Name": "S3 Bucket Policy", "AssociatedService": ["Amazon S3"]},
        "VPCPolicy": {
            "Name": "VPC Endpoint Policy",
            "AssociatedService": ["Amazon S3", "Amazon DynamoDB For VPC Policies"]
        },
        "IAMPolicy": {"Name": "IAM Policy", "AssociatedService": ["*"]},
        "SNSPolicy": {"Name": "SNS Topic Policy", "AssociatedService": ["Amazon SNS"]}
    },
    "VPCPolicyServiceActionMap": {"Amazon DynamoDB For VPC Policies": ["DescribeContinuousBackups", "DescribeBackup", "DescribeReservedCapacity", "PurchaseReservedCapacityOfferings", "ListBackups", "DeleteItem", "Query", "DeleteBackup", "DescribeTable", "CreateTable", "BatchGetItem", "BatchWriteItem", "DeleteTable", "RestoreTableFromBackup", "GetItem", "DescribeLimits", "UpdateTable", "UpdateItem", "DescribeReservedCapacityOfferings", "ListTables", "Scan", "PutItem", "CreateBackup"]}
}
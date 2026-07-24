extension microsoftGraphV1_0

// Entra ID Elite (Topology 2)
// One deployment manages N companies (FormerCompanies rows from the
// portal grid). Group tenants are derived full-mesh by the engine, never
// entered here. Ships production-first (FormerApplyChanges=true); set it
// false for a plan-only trial that reads and previews without writing.

@description('Object with a "rows" array from the portal grid: one row per company (companyId, tenantIds CSV, apiKey, actorEmail). Secure so API keys never appear in deployment history. Serialized into FORMER_COMPANY_MAP for the engine.')
@secure()
param FormerCompanies object

@description('Target environment. platform is production; preprod is the staging platform.')
@allowed(['platform', 'preprod'])
param Environment string = 'platform'

@description('Existing multi-tenant App Registration client ID. Leave empty to create a new App Registration automatically.')
param EntraIdClientId string = ''

@description('Create a new App Registration + FIC automatically (requires Application Administrator).')
param CreateAppRegistration bool = empty(EntraIdClientId)

@description('Also grant admin consent for the Graph application permissions automatically. Requires Global Administrator or Privileged Role Administrator — Application Administrator cannot consent to Microsoft Graph app roles.')
param GrantAdminConsent bool = false

@description('Skip adding a Federated Identity Credential to an existing App Registration (set true only if you add it manually).')
param SkipFicCreation bool = false

@description('Write to the platform former-employee lists. false = plan-only trial: the sync reads, plans and audits but never mutates.')
param FormerApplyChanges bool = true

@description('real talks to the live API; mock keeps everything in local table storage (trial).')
@allowed(['real', 'mock'])
param FormerClientMode string = 'real'

@description('Former sync interval in minutes. Values over 60 must be whole hours (NCRONTAB step fields).')
@allowed([5, 10, 15, 30, 60, 120, 240, 360, 720, 1440])
param FormerSyncIntervalMinutes int = 60

@description('Run the first former sync right after deployment.')
param RunOnStartup bool = true

@description('Include soft-deleted Entra users in the former set (V2).')
param IncludeDeletedUsers bool = true

@description('standart sends disabled Members to the former list; strict only logs them as review-needed.')
@allowed(['standart', 'strict'])
param RulesetMode string = 'standart'

@description('Absolute cap on adds per run per company.')
param FormerMaxAdds int = 500

@description('Absolute cap on removals per run per company.')
param FormerMaxRemovals int = 100

@description('Removals may not exceed this percentage of the remote list.')
param FormerMaxRemovalPercent int = 50

@description('URL of the FunctionApp deployment package (zip). Leave empty to deploy infrastructure only and publish code separately.')
param PackageUri string = 'https://github.com/orcunsami/entra-id-elite/releases/download/v1.0.0/FunctionApp.zip'

var location = resourceGroup().location
var suffix = uniqueString(resourceGroup().id)
var functionAppName = 'former-elite-${suffix}'
var storageAccountName = toLower('elitesa${suffix}')
var managedIdentityName = 'Elite-Former-MI'
var hostingPlanName = 'Elite-Former-Plan'
var workspaceName = 'Elite-Former-LAW-${suffix}'
var dcrName = 'Elite-Former-DCR'
var socradarBaseUrl = Environment == 'preprod' ? 'https://preprod.socradar.com' : 'https://platform.socradar.com'
// NCRONTAB minute field is 0-59: intervals >= 60 must move to the hour field
// (the base entra-id template's proven pattern) or they silently fire hourly.
var formerSchedule = FormerSyncIntervalMinutes < 60
  ? '0 */${FormerSyncIntervalMinutes} * * * *'
  : '0 0 */${FormerSyncIntervalMinutes / 60} * * *'

// ============================================================================
// Storage (state: EntraIDState checkpoint/guard, FormerManual, FormerOwnership)
// ============================================================================

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource stateTables 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = [for t in ['EntraIDState', 'FormerManual', 'FormerOwnership']: {
  parent: tableService
  name: t
}]

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
}

// ============================================================================
// Microsoft Graph: App Registration + SP + FIC (least-privilege for former
// sync: User.Read.All for active/disabled Members, Directory.Read.All for
// /directory/deletedItems). Existing-app path adds the FIC via CLI script.
// ============================================================================

var graphUniqueAppName = 'entra-former-${suffix}'
var eliteGraphRoleIds = [
  'df021288-bdef-4463-88db-98f22de89214' // User.Read.All
  '7ab1d382-f21e-4acd-a863-ba3e13f7da61' // Directory.Read.All
]

resource appReg 'Microsoft.Graph/applications@v1.0' = if (CreateAppRegistration) {
  uniqueName: graphUniqueAppName
  displayName: 'Entra ID Elite'
  signInAudience: 'AzureADMultipleOrgs'
  requiredResourceAccess: [
    {
      resourceAppId: '00000003-0000-0000-c000-000000000000'
      resourceAccess: [for roleId in eliteGraphRoleIds: { id: roleId, type: 'Role' }]
    }
  ]
}

resource appSp 'Microsoft.Graph/servicePrincipals@v1.0' = if (CreateAppRegistration) {
  appId: appReg.appId
}

resource fic 'Microsoft.Graph/applications/federatedIdentityCredentials@v1.0' = if (CreateAppRegistration) {
  name: '${appReg.uniqueName}/former-elite-uami'
  audiences: ['api://AzureADTokenExchange']
  issuer: 'https://login.microsoftonline.com/${tenant().tenantId}/v2.0'
  subject: managedIdentity.properties.principalId
}

resource graphSpRef 'Microsoft.Graph/servicePrincipals@v1.0' existing = if (CreateAppRegistration && GrantAdminConsent) {
  appId: '00000003-0000-0000-c000-000000000000'
}

resource adminConsentGrants 'Microsoft.Graph/appRoleAssignedTo@v1.0' = [for roleId in eliteGraphRoleIds: if (CreateAppRegistration && GrantAdminConsent) {
  appRoleId: roleId
  principalId: appSp.id
  resourceId: graphSpRef.id
}]

var resolvedAppClientId = CreateAppRegistration ? appReg.appId : EntraIdClientId

resource addFicToExistingApp 'Microsoft.Resources/deploymentScripts@2020-10-01' = if (!CreateAppRegistration && !SkipFicCreation) {
  name: 'addFic-${suffix}'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${managedIdentity.id}': {} }
  }
  properties: {
    azCliVersion: '2.50.0'
    retentionInterval: 'PT1H'
    timeout: 'PT5M'
    environmentVariables: [
      { name: 'APP_ID', value: EntraIdClientId }
      { name: 'TENANT_ID', value: subscription().tenantId }
      { name: 'UAMI_PRINCIPAL', value: managedIdentity.properties.principalId }
      { name: 'RG_NAME', value: resourceGroup().name }
    ]
    scriptContent: '''
      FIC_NAME="former-elite-${RG_NAME}-uami"
      EXISTING=$(az ad app federated-credential list --id "$APP_ID" --query "[?subject=='${UAMI_PRINCIPAL}'].name" -o tsv 2>/dev/null || echo "")
      if [ -n "$EXISTING" ]; then
        echo "FIC already exists for UAMI ${UAMI_PRINCIPAL} on app ${APP_ID}: ${EXISTING}"
      elif az ad app federated-credential create --id "$APP_ID" --parameters "{
          \"name\": \"${FIC_NAME}\",
          \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
          \"subject\": \"${UAMI_PRINCIPAL}\",
          \"audiences\": [\"api://AzureADTokenExchange\"]
        }"; then
        echo "FIC added"
      else
        # Fail-soft: the deployment identity (UAMI) usually has no Entra
        # app-write permission on a foreign App Registration. The app cannot
        # run until the FIC exists, but failing the whole deployment here
        # would strand the rest of the install. Surface the exact command.
        echo "WARNING: could not add FIC automatically (no Entra app-write permission)."
        echo "Run manually as an owner of the App Registration:"
        echo "az ad app federated-credential create --id ${APP_ID} --parameters '{\"name\":\"${FIC_NAME}\",\"issuer\":\"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",\"subject\":\"${UAMI_PRINCIPAL}\",\"audiences\":[\"api://AzureADTokenExchange\"]}'"
      fi
      exit 0
    '''
  }
  dependsOn: [managedIdentity]
}

// ============================================================================
// Log Analytics + audit table + Direct DCR (persistent hashed former audit)
// ============================================================================

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
  }
}

var auditColumns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'source', type: 'string' }
  { name: 'event_type', type: 'string' }
  { name: 'company_id', type: 'string' }
  { name: 'mode', type: 'string' }
  { name: 'apply', type: 'boolean' }
  { name: 'blocked', type: 'boolean' }
  { name: 'block_reason', type: 'string' }
  { name: 'snapshot_complete', type: 'boolean' }
  { name: 'own_active', type: 'int' }
  { name: 'own_former', type: 'int' }
  { name: 'sibling_active', type: 'int' }
  { name: 'manual', type: 'int' }
  { name: 'desired', type: 'int' }
  { name: 'preserve', type: 'int' }
  { name: 'add_planned', type: 'int' }
  { name: 'remove_planned', type: 'int' }
  { name: 'withheld', type: 'int' }
  { name: 'added', type: 'int' }
  { name: 'removed', type: 'int' }
  { name: 'notes', type: 'string' }
  { name: 'email_sha256', type: 'string' }
  { name: 'applied', type: 'boolean' }
  { name: 'tenant_id', type: 'string' }
  { name: 'details', type: 'string' }
]

resource auditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SOCRadar_EntraID_Audit_CL'
  properties: {
    schema: {
      name: 'SOCRadar_EntraID_Audit_CL'
      columns: auditColumns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    description: 'Entra ID Elite — former sync audit (Logs Ingestion API)'
    streamDeclarations: {
      'Custom-SOCRadar_EntraID_Audit_CL': { columns: auditColumns }
    }
    destinations: {
      logAnalytics: [
        { workspaceResourceId: workspace.id, name: 'law' }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-SOCRadar_EntraID_Audit_CL']
        destinations: ['law']
        transformKql: 'source'
        outputStream: 'Custom-SOCRadar_EntraID_Audit_CL'
      }
    ]
  }
  dependsOn: [auditTable]
}

resource dcrPublisherRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, managedIdentity.id, 'MonitoringMetricsPublisher')
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource tableDataRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, managedIdentity.id, 'StorageTableDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ============================================================================
// Function App (Y1 Linux consumption)
// ============================================================================

resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: hostingPlanName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  kind: 'linux'
  properties: { reserved: true }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: functionAppName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
  }
}

var storageConnection = 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${listKeys(storageAccount.id, '2023-05-01').keys[0].value};EndpointSuffix=core.windows.net'

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${managedIdentity.id}': {} }
  }
  properties: {
    serverFarmId: hostingPlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: storageConnection }
        { name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING', value: storageConnection }
        { name: 'WEBSITE_CONTENTSHARE', value: toLower(functionAppName) }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'AzureWebJobsFeatureFlags', value: 'EnableWorkerIndexing' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: reference(appInsights.id, '2020-02-02').ConnectionString }
        { name: 'WEBSITE_RUN_FROM_PACKAGE', value: empty(PackageUri) ? '1' : PackageUri }
        // Former sync (the elite feature)
        { name: 'FORMER_COMPANY_MAP', value: string(FormerCompanies.rows) }
        { name: 'SOCRADAR_BASE_URL', value: socradarBaseUrl }
        { name: 'FORMER_CLIENT_MODE', value: FormerClientMode }
        { name: 'FORMER_APPLY_CHANGES', value: string(FormerApplyChanges) }
        { name: 'FORMER_SYNC_SCHEDULE', value: formerSchedule }
        { name: 'FORMER_RUN_ON_STARTUP', value: string(RunOnStartup) }
        { name: 'ENABLE_FORMER_SYNC', value: 'true' }
        { name: 'ENABLE_CROSS_TENANT_SUPPRESS', value: 'true' }
        { name: 'INCLUDE_DELETED_USERS', value: string(IncludeDeletedUsers) }
        { name: 'RULESET_MODE', value: RulesetMode }
        { name: 'FORMER_MAX_ADDS', value: string(FormerMaxAdds) }
        { name: 'FORMER_MAX_REMOVALS', value: string(FormerMaxRemovals) }
        { name: 'FORMER_MAX_REMOVAL_PERCENT', value: string(FormerMaxRemovalPercent) }
        // Entra / identity
        { name: 'ENTRA_CLIENT_ID', value: resolvedAppClientId }
        { name: 'AZURE_CLIENT_ID', value: reference(managedIdentity.id, '2023-01-31').clientId }
        // The legacy ingestion timer stays dormant in the elite package: all
        // sources off, sparse schedule (the function still needs a valid cron
        // to index). ENTRA_TENANT_IDS satisfies load() validation only.
        { name: 'POLLING_SCHEDULE', value: '0 0 3 * * *' }
        { name: 'ENABLE_BOTNET_SOURCE', value: 'false' }
        { name: 'ENABLE_PII_SOURCE', value: 'false' }
        { name: 'ENABLE_VIP_SOURCE', value: 'false' }
        { name: 'ENABLE_USER_LOOKUP', value: 'false' }
        { name: 'RUN_ON_STARTUP', value: 'false' }
        { name: 'SOCRADAR_API_KEY', value: 'unused-former-map-mode' }
        // Non-empty placeholder: cfg.load() requires it, and the dormant daily
        // ingestion timer would otherwise throw on every fire.
        { name: 'SOCRADAR_COMPANY_ID', value: 'unused-former-map-mode' }
        { name: 'ENTRA_TENANT_IDS', value: tenant().tenantId }
        // Audit (DCR Logs Ingestion)
        { name: 'DCR_IMMUTABLE_ID', value: reference(dcr.id, '2023-03-11').immutableId }
        { name: 'DCR_ENDPOINT', value: reference(dcr.id, '2023-03-11').endpoints.logsIngestion }
        { name: 'WORKSPACE_ID', value: reference(workspace.id, '2023-09-01').customerId }
        { name: 'STORAGE_ACCOUNT_NAME', value: storageAccountName }
      ]
    }
  }
  dependsOn: [tableDataRole]
}

// First run: restart after package mount so the startup sync fires promptly.
resource triggerFirstRun 'Microsoft.Resources/deploymentScripts@2020-10-01' = if (!empty(PackageUri) && RunOnStartup) {
  name: 'triggerFirstRun-${suffix}'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${managedIdentity.id}': {} }
  }
  properties: {
    azCliVersion: '2.50.0'
    retentionInterval: 'PT1H'
    timeout: 'PT15M'
    scriptContent: 'sleep 30 && az functionapp restart --name $FA_NAME --resource-group $RG_NAME && echo restarted'
    environmentVariables: [
      { name: 'FA_NAME', value: functionAppName }
      { name: 'RG_NAME', value: resourceGroup().name }
    ]
  }
  dependsOn: [functionApp, faContributorRole]
}

// The restart script (and FIC script) run as the UAMI — it needs rights on the app.
resource faContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionApp.id, managedIdentity.id, 'WebsiteContributor')
  scope: functionApp
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = functionAppName
output previewUrl string = 'https://${functionAppName}.azurewebsites.net/api/former/preview?code=<function-key>'
output entraClientId string = resolvedAppClientId
output workspaceName string = workspaceName
output consentNote string = CreateAppRegistration && !GrantAdminConsent ? 'Grant admin consent to the new App Registration (Entra portal > App registrations > Entra ID Elite > API permissions), and consent it in every sibling tenant.' : 'Consent handled (existing app or automated grant). Sibling tenants still need the multi-tenant app consented once each.'
output ficNote string = CreateAppRegistration ? 'FIC created automatically.' : (SkipFicCreation ? 'FIC skipped — add it manually for the UAMI principal.' : 'FIC added to the existing App Registration by deployment script.')

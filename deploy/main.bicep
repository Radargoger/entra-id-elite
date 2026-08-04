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

@description('Suppress a person across every company in the map: someone still active in one tenant is added to the former-employee list of the others. Only meaningful when the companies belong to the same organisation. Turn this off if any two of them are unrelated, so one customer\'s staff never appears in another\'s list.')
param EnableCrossTenantSuppress bool = true

@description('Comma-separated tenant GUIDs that belong to the group but have no company row of their own, such as a holding tenant. Their active members are suppressed for every company; they never receive a former list. The companies in the grid already suppress each other, so this is only for tenants the grid cannot express.')
param GroupTenantIds string = ''

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

// 'standart' was the spelling in earlier releases and is still set in running
// installations. The app accepts it and normalises it, so an upgrade does not
// change behaviour under them; only new deployments get this spelling.
@description('standard sends disabled Members to the former list; strict only logs them as review-needed.')
@allowed(['standard', 'strict'])
param RulesetMode string = 'standard'

@description('Absolute cap on adds per run per company.')
param FormerMaxAdds int = 500

@description('Absolute cap on removals per run per company.')
param FormerMaxRemovals int = 100

@description('Removals may not exceed this percentage of the remote list.')
param FormerMaxRemovalPercent int = 50

@description('Also monitor leaked credentials. Each company row is checked against its own tenants only.')
param EnableLeakMonitoring bool = false

@description('Leak sources to pull from the platform.')
@allowed(['botnet', 'pii', 'vip'])
param LeakSources array = ['botnet', 'pii']

@description('What to do with a match. Log only records the match; Respond also changes the account in Entra ID.')
@allowed(['logOnly', 'respond'])
param LeakResponse string = 'logOnly'

@description('Actions taken when LeakResponse is respond.')
@allowed(['revokeSessions', 'forcePasswordChange', 'disableAccount', 'resetMfa', 'confirmCompromised'])
param LeakResponseActions array = ['revokeSessions']

@description('Ceiling on account changes per company per source in each run — a run with three companies and two sources can change up to six times this number. Once a slot reaches it, matches keep being recorded, the remaining actions wait, and the window is re-read next run.')
param LeakMaxActionsPerRun int = 50

@description('Days the idempotency ledger keeps a window before its rows are removed. Rows older than this cannot be reached by any re-read, so keeping them only grows the table. Values below 30 are raised to 30 by the app.')
@minValue(30)
param LeakLedgerRetentionDays int = 90

@description('Hours between leak import runs.')
@allowed([1, 3, 6, 12, 24])
param LeakImportIntervalHours int = 6

@description('How many days of history to scan on the very first run (before a checkpoint exists). Larger values catch older breaches but make the first run slower.')
@allowed([7, 30, 90, 180, 365])
param LeakInitialLookbackDays int = 30

@description('Security group used by the add/remove group actions. Leave empty to disable them.')
param SecurityGroupId string = ''

@description('Your own email domains, comma-separated. When set, only addresses in these domains are looked up in Entra ID and everything else in a feed is dropped before it leaves the app. Leave empty to look up every address the feed returns.')
param VerifiedDomains string = ''

@description('URL of the FunctionApp deployment package (zip). Leave empty to deploy infrastructure only and publish code separately.')
// The shared build is always v1.0.0. Internal iterations are tracked in git,
// not in the tag customers deploy from, so this URL stays put and the release
// asset behind it is what moves.
param PackageUri string = 'https://github.com/Radargoger/entra-id-elite/releases/download/v1.0.0/FunctionApp.zip'

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

resource stateTables 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = [for t in ['EntraIDState', 'FormerManual', 'FormerOwnership', 'LeakActionLedger']: {
  parent: tableService
  name: t
}]

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
}

// ============================================================================
// Microsoft Graph: App Registration + SP + FIC (least-privilege for former
// sync: User.Read.All covers both active/disabled Members and
// /directory/deletedItems). Existing-app path adds the FIC via CLI script.
// ============================================================================

var graphUniqueAppName = 'entra-former-${suffix}'
var readGraphRoleIds = [
  'df021288-bdef-4463-88db-98f22de89214' // User.Read.All
]
// Write permissions are requested only for the responses actually turned on.
// A tenant admin should never be asked to consent to a capability the
// deployment will not use.
var respondOn = EnableLeakMonitoring && LeakResponse == 'respond'
var actionGraphRoleIds = union(
  (respondOn && contains(LeakResponseActions, 'revokeSessions')) ? ['77f3a031-c388-4f99-b373-dc68676a979e'] : [],
  (respondOn && contains(LeakResponseActions, 'forcePasswordChange')) ? ['cc117bb9-00cf-4eb8-b580-ea2a878fe8f7'] : [],
  (respondOn && contains(LeakResponseActions, 'disableAccount')) ? ['3011c876-62b7-4ada-afa2-506cbbecc68c'] : [],
  (respondOn && contains(LeakResponseActions, 'resetMfa')) ? ['50483e42-d915-4231-9639-7fdb7fd190e5'] : [],
  (respondOn && contains(LeakResponseActions, 'confirmCompromised')) ? ['656f6061-f9fe-4807-9708-6a2e0934df76'] : [],
  (respondOn && !empty(SecurityGroupId)) ? ['dbaae8cf-10b5-4b86-a4a1-f871c94c6695'] : []
)
var eliteGraphRoleIds = union(readGraphRoleIds, actionGraphRoleIds)

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

// Automatic consent covers the read permissions only. Permission to change
// accounts is granted by a human on the consent screen, so nobody ends up with
// disable-account rights as a side effect of ticking a deployment checkbox.
// Note that removing a role here does not revoke a grant already made.
resource adminConsentGrants 'Microsoft.Graph/appRoleAssignedTo@v1.0' = [for roleId in readGraphRoleIds: if (CreateAppRegistration && GrantAdminConsent) {
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
      ADDED=false
      EXISTING=$(az ad app federated-credential list --id "$APP_ID" --query "[?subject=='${UAMI_PRINCIPAL}'].name" -o tsv 2>/dev/null || echo "")
      if [ -n "$EXISTING" ]; then
        echo "FIC already exists for UAMI ${UAMI_PRINCIPAL} on app ${APP_ID}: ${EXISTING}"
        ADDED=true
      elif az ad app federated-credential create --id "$APP_ID" --parameters "{
          \"name\": \"${FIC_NAME}\",
          \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
          \"subject\": \"${UAMI_PRINCIPAL}\",
          \"audiences\": [\"api://AzureADTokenExchange\"]
        }"; then
        echo "FIC added"
        ADDED=true
      else
        # Fail-soft: the deployment identity (UAMI) usually has no Entra
        # app-write permission on a foreign App Registration. The app cannot
        # run until the FIC exists, but failing the whole deployment here
        # would strand the rest of the install. Surface the exact command.
        echo "WARNING: could not add FIC automatically (no Entra app-write permission)."
        echo "Run the command from the deployment output 'ficManualCommand' as an owner of the App Registration."
      fi
      # Report what actually happened. The Outputs blade is the only place most
      # operators look, so it must not claim a success the script did not
      # achieve: without the FIC the app gets no Graph token and every directory
      # lookup is skipped, quietly. Keep this JSON trivial -- quoting through
      # bicep, ARM and the shell is a three-layer escaping trap, and a malformed
      # output file fails the whole deployment.
      if [ "$ADDED" = "true" ]; then
        echo '{"ficAdded": true}' > "$AZ_SCRIPTS_OUTPUT_PATH"
      else
        echo '{"ficAdded": false}' > "$AZ_SCRIPTS_OUTPUT_PATH"
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
  // consent_revoked carries the Entra error code that explains why consent
  // stopped working. Without the column the one diagnostic that matters was
  // dropped and the event arrived saying only that something failed.
  { name: 'aadsts_code', type: 'string' }
]

// Leak monitoring tables. company_id is carried on every row: one deployment
// serves several companies and a finding that cannot be attributed to one of
// them is not actionable. Columns a stream does not declare are dropped by the
// ingestion API without an error, so these lists must stay in step with the
// records the code sends.
var leakCommonColumns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'company_id', type: 'string' }
  { name: 'email', type: 'string' }
  { name: 'is_employee', type: 'boolean' }
  { name: 'source', type: 'string' }
  { name: 'alarm_id', type: 'int' }
  { name: 'password_present', type: 'boolean' }
  { name: 'password_masked', type: 'string' }
  { name: 'is_plaintext', type: 'boolean' }
  { name: 'entra_status', type: 'string' }
  { name: 'entra_tenant_id', type: 'string' }
  // The Graph object ID of the account that was matched. This is the only
  // field that joins a row here to Microsoft Entra ID's own audit log, which
  // is where a customer goes to confirm independently that a change the app
  // reports really happened. Without it the two records cannot be lined up.
  { name: 'entra_user_id', type: 'string' }
  { name: 'entra_account_enabled', type: 'boolean' }
  { name: 'severity', type: 'string' }
  { name: 'actions_taken', type: 'dynamic' }
]

var botnetColumns = union(leakCommonColumns, [
  { name: 'url', type: 'string' }
  { name: 'device_ip', type: 'string' }
  { name: 'device_os', type: 'string' }
  { name: 'country', type: 'string' }
  { name: 'log_date', type: 'string' }
  { name: 'password', type: 'string' }
  { name: 'mfa_methods_deleted', type: 'int' }
  { name: 'mfa_methods_skipped', type: 'int' }
])

var piiColumns = union(leakCommonColumns, [
  { name: 'source_name', type: 'string' }
  { name: 'breach_date', type: 'string' }
  { name: 'discovery_date', type: 'string' }
  { name: 'password', type: 'string' }
  { name: 'mfa_methods_deleted', type: 'int' }
  { name: 'mfa_methods_skipped', type: 'int' }
])

var vipColumns = union(leakCommonColumns, [
  { name: 'keyword', type: 'string' }
  { name: 'vip_name', type: 'string' }
  { name: 'status', type: 'string' }
  { name: 'discovery_date', type: 'string' }
  { name: 'source_name', type: 'string' }
  // The MFA counters are written by the response path, which does not care
  // which feed the match came from. Leaving them out here dropped them from
  // every VIP row without an error.
  { name: 'mfa_methods_deleted', type: 'int' }
  { name: 'mfa_methods_skipped', type: 'int' }
])

// Import run summaries live in their own table. Merging them into the former
// audit table would mean a schema change on deployments that already hold
// reconcile history, and there is no way back from that.
var importAuditColumns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'source', type: 'string' }
  { name: 'company_id', type: 'string' }
  { name: 'total_records', type: 'int' }
  { name: 'employee_records', type: 'int' }
  { name: 'found_count', type: 'int' }
  { name: 'not_found_count', type: 'int' }
  { name: 'actions_taken', type: 'int' }
  { name: 'error_count', type: 'int' }
  { name: 'domain_filtered', type: 'int' }
  { name: 'no_address_count', type: 'int' }
  { name: 'lookup_disabled_count', type: 'int' }
  { name: 'no_token_count', type: 'int' }
  { name: 'lookup_failed_count', type: 'int' }
  { name: 'capped', type: 'boolean' }
  { name: 'truncated', type: 'boolean' }
  { name: 'duration_sec', type: 'real' }
  { name: 'event_type', type: 'string' }
  { name: 'tenant_id', type: 'string' }
  { name: 'details', type: 'string' }
  { name: 'aadsts_code', type: 'string' }
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

// Deployed whether or not leak monitoring is on: an empty table costs nothing,
// while a conditional resource branch is the shape that produced install
// errors before.
resource botnetTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SOCRadar_Botnet_CL'
  properties: { schema: { name: 'SOCRadar_Botnet_CL', columns: botnetColumns } }
}

resource piiTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SOCRadar_PII_CL'
  properties: { schema: { name: 'SOCRadar_PII_CL', columns: piiColumns } }
}

resource vipTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SOCRadar_VIP_CL'
  properties: { schema: { name: 'SOCRadar_VIP_CL', columns: vipColumns } }
}

resource importAuditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SOCRadar_ImportAudit_CL'
  properties: { schema: { name: 'SOCRadar_ImportAudit_CL', columns: importAuditColumns } }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    description: 'Entra ID Elite — former sync audit and leak monitoring (Logs Ingestion API)'
    streamDeclarations: {
      'Custom-SOCRadar_EntraID_Audit_CL': { columns: auditColumns }
      'Custom-SOCRadar_Botnet_CL': { columns: botnetColumns }
      'Custom-SOCRadar_PII_CL': { columns: piiColumns }
      'Custom-SOCRadar_VIP_CL': { columns: vipColumns }
      'Custom-SOCRadar_ImportAudit_CL': { columns: importAuditColumns }
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
      {
        streams: ['Custom-SOCRadar_Botnet_CL']
        destinations: ['law']
        transformKql: 'source'
        outputStream: 'Custom-SOCRadar_Botnet_CL'
      }
      {
        streams: ['Custom-SOCRadar_PII_CL']
        destinations: ['law']
        transformKql: 'source'
        outputStream: 'Custom-SOCRadar_PII_CL'
      }
      {
        streams: ['Custom-SOCRadar_VIP_CL']
        destinations: ['law']
        transformKql: 'source'
        outputStream: 'Custom-SOCRadar_VIP_CL'
      }
      {
        streams: ['Custom-SOCRadar_ImportAudit_CL']
        destinations: ['law']
        transformKql: 'source'
        outputStream: 'Custom-SOCRadar_ImportAudit_CL'
      }
    ]
  }
  // Every table the streams write to must exist first, or a fresh deployment
  // creates the rule against tables that are not there yet.
  dependsOn: [auditTable, botnetTable, piiTable, vipTable, importAuditTable]
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

// Workspace-based, pointed at the same workspace the audit tables live in.
// As a classic component its traces sat in a separate resource, so answering
// "the app says it did this, did it?" meant two query surfaces and no way to
// join them. Now one KQL query can span the app's own traces and the rows it
// wrote.
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: functionAppName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
    WorkspaceResourceId: workspace.id
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
        { name: 'ENABLE_CROSS_TENANT_SUPPRESS', value: string(EnableCrossTenantSuppress) }
        { name: 'GROUP_TENANT_IDS', value: GroupTenantIds }
        { name: 'INCLUDE_DELETED_USERS', value: string(IncludeDeletedUsers) }
        { name: 'RULESET_MODE', value: RulesetMode }
        { name: 'FORMER_MAX_ADDS', value: string(FormerMaxAdds) }
        { name: 'FORMER_MAX_REMOVALS', value: string(FormerMaxRemovals) }
        { name: 'FORMER_MAX_REMOVAL_PERCENT', value: string(FormerMaxRemovalPercent) }
        // Entra / identity
        { name: 'ENTRA_CLIENT_ID', value: resolvedAppClientId }
        { name: 'AZURE_CLIENT_ID', value: reference(managedIdentity.id, '2023-01-31').clientId }
        // Leak monitoring, at half past. That misses the former sync only at
        // its default hourly setting: a sub-hourly interval of 5, 10, 15 or 30
        // minutes also fires at minute 30, so the two do overlap for four of
        // the ten values this form offers. Correctness does not rest on the
        // schedules missing each other -- the Graph credential cache holds its
        // tenant key in the same store as the credential, so concurrent runs
        // for different tenants cannot cross. The offset is only there to keep
        // the common case off one worker.
        { name: 'POLLING_SCHEDULE', value: '0 30 */${LeakImportIntervalHours} * * *' }
        { name: 'ENABLE_BOTNET_SOURCE', value: string(EnableLeakMonitoring && contains(LeakSources, 'botnet')) }
        { name: 'ENABLE_PII_SOURCE', value: string(EnableLeakMonitoring && contains(LeakSources, 'pii')) }
        { name: 'ENABLE_VIP_SOURCE', value: string(EnableLeakMonitoring && contains(LeakSources, 'vip')) }
        { name: 'ENABLE_USER_LOOKUP', value: string(EnableLeakMonitoring) }
        { name: 'ENTRA_ACTION_MODE', value: respondOn ? 'apply' : 'plan' }
        { name: 'ENTRA_MAX_ACTIONS_PER_RUN', value: string(LeakMaxActionsPerRun) }
        { name: 'LEAK_LEDGER_RETENTION_DAYS', value: string(LeakLedgerRetentionDays) }
        // Small enough that the records pulled can also be looked up in the
        // same run; otherwise a run fetches all day and never gets to the work.
        { name: 'MAX_PAGES_PER_RUN', value: '10' }
        { name: 'INITIAL_LOOKBACK_MINUTES', value: string(LeakInitialLookbackDays * 1440) }
        // Every action switch is written on both paths. Writing them only when
        // leak monitoring is on would remove them from the settings collection
        // when it is turned off, and the code defaults some of them to true —
        // so switching off would switch actions back on.
        { name: 'ENABLE_REVOKE_SESSION', value: string(respondOn && contains(LeakResponseActions, 'revokeSessions')) }
        { name: 'ENABLE_PASSWORD_CHANGE', value: string(respondOn && contains(LeakResponseActions, 'forcePasswordChange')) }
        { name: 'ENABLE_DISABLE_ACCOUNT', value: string(respondOn && contains(LeakResponseActions, 'disableAccount')) }
        { name: 'ENABLE_FORCE_MFA_REREGISTRATION', value: string(respondOn && contains(LeakResponseActions, 'resetMfa')) }
        { name: 'ENABLE_CONFIRM_RISKY', value: string(respondOn && contains(LeakResponseActions, 'confirmCompromised')) }
        { name: 'ENABLE_ADD_TO_GROUP', value: string(respondOn && !empty(SecurityGroupId)) }
        { name: 'ENABLE_REMOVE_FROM_GROUP', value: 'false' }
        { name: 'ENABLE_ENABLE_ACCOUNT', value: 'false' }
        // Not offered: ROPC needs a public-client setting this template does not
        // write, and incident creation needs workspace ids it does not pass.
        { name: 'ENABLE_ROPC', value: 'false' }
        { name: 'ENABLE_CREATE_INCIDENT', value: 'false' }
        { name: 'ENABLE_RESOLVE_ALARM', value: 'false' }
        { name: 'SECURITY_GROUP_ID', value: SecurityGroupId }
        // Addresses outside these domains are dropped before any lookup, so a
        // feed row for someone who is not yours never reaches Microsoft Graph.
        // Empty means every address the feed returns is looked up.
        { name: 'ENTRA_ID_VERIFIED_DOMAINS', value: VerifiedDomains }
        // Same switch as the former sync. It used to be pinned false here,
        // which meant a customer who enabled leaked-credential monitoring saw
        // nothing until the schedule came round, up to six hours later, with
        // no hint that this was expected. With Respond selected the first run
        // now also acts at install time; the form says so where the responses
        // are chosen.
        { name: 'RUN_ON_STARTUP', value: string(RunOnStartup) }
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
    // Quoted on purpose: a resource-group name can contain spaces, and an
    // unquoted expansion would split it into extra CLI arguments.
    scriptContent: 'set -euo pipefail; sleep 30 && az functionapp restart --name "$FA_NAME" --resource-group "$RG_NAME" && echo restarted'
    environmentVariables: [
      { name: 'FA_NAME', value: functionAppName }
      { name: 'RG_NAME', value: resourceGroup().name }
    ]
  }
  dependsOn: [functionApp, faContributorRole]
}

// The restart script runs as the UAMI, so it needs rights on the app — but
// only when that script exists. This assignment used to be unconditional, so
// deployments that never ran the restart still granted the runtime identity a
// permanent Website Contributor on its own app. Same condition as the script.
resource faContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(PackageUri) && RunOnStartup) {
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
// 'Consent handled' was a guess dressed as a fact on the reuse path: this
// deployment cannot read an App Registration it does not own, so it has no way
// to know whether the permissions are still granted. Same failure shape as the
// FIC note below — an install that reads as finished and looks nobody up.
output consentNote string = CreateAppRegistration
  ? (GrantAdminConsent
      ? 'Consent granted by the deployment. Each sibling tenant still needs the multi-tenant app consented once.'
      : 'Grant admin consent to the new App Registration (Entra portal > App registrations > Entra ID Elite > API permissions), and consent it in every sibling tenant.')
  : 'Not checked here: the deployment cannot read the permissions of an App Registration it does not own. Confirm the reused app still has its Graph permissions granted, and that each sibling tenant has consented to the multi-tenant app once.'
// Reports what the script achieved, not what it attempted. Claiming the
// federated credential is in place when it is not leaves an install that looks
// healthy and silently skips every directory lookup.
output ficNote string = CreateAppRegistration
  ? 'FIC created automatically.'
  : (SkipFicCreation
      ? 'FIC skipped — add it manually for the UAMI principal.'
      : (addFicToExistingApp.properties.outputs.ficAdded
          ? 'FIC is in place on the existing App Registration.'
          : 'CHECK THIS — the deployment could not add the federated credential, and without Entra read permission it also cannot tell whether a suitable one already exists. Confirm with GET /api/former/preview: if snapshot_complete is false the credential is missing, and an owner of the App Registration must run the command in ficManualCommand. Do not use leak/preview for this: it reports no reachable tenant whenever leak monitoring is off, which is the default. Until then no user is looked up or acted on.'))

// Built here rather than inside the script: the command carries quotes and the
// script's output file has to survive bicep, ARM and shell quoting in turn.
output ficManualCommand string = CreateAppRegistration || SkipFicCreation
  ? ''
  : (addFicToExistingApp.properties.outputs.ficAdded
      ? ''
      : 'az ad app federated-credential create --id ${EntraIdClientId} --parameters \'{"name":"former-elite-${resourceGroup().name}-uami","issuer":"https://login.microsoftonline.com/${subscription().tenantId}/v2.0","subject":"${managedIdentity.properties.principalId}","audiences":["api://AzureADTokenExchange"]}\'')

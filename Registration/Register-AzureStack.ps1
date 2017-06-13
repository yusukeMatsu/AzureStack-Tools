<###################################################
 #                                                 #
 #  Copyright (c) Microsoft. All rights reserved.  #
 #                                                 #
 ##################################################>

#requires -Version 4.0
#requires -Modules @{ModuleName = "AzureRM.Profile" ; ModuleVersion = "2.7"} 
#requires -Modules @{ModuleName = "AzureRM.Resources" ; ModuleVersion = "3.7"} 

 <#
.SYNOPSIS
    Script to register Azure Stack in Azure given registration data file, which needs to contain Azure Bridge Object Identifier
    Requires Azure connectivity to register with Azure
.EXAMPLE
    $registrationRequestFile = "c:\temp\registration.json"
    $registrationOutputFile = "c:\temp\registrationOutput.json"
    Register-AzureStack.ps1 -BillingModel PayAsYouUse -EnableSyndication -ReportUsage -SubscriptionId $azureSubscriptionId -AzureAdTenantId $AzureDirectoryTenantId `
    -RegistrationRequestFile $registrationRequestFile -RegistrationOutputFile $registrationOutputFile -Location "westcentralus" -Verbose
#>

[CmdletBinding()]
param 
(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Capacity', 'PayAsYouUse', 'Development')]
    [string] $BillingModel,

    [Parameter(Mandatory=$false)]
    [switch] $EnableSyndication,

    [Parameter(Mandatory=$false)]
    [switch] $ReportUsage,

    [Parameter(Mandatory=$true)]
    [ValidateSet('AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureGermanCloud')]
    [string] $AzureEnvironmentName,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [string] $Location = "westcentralus",

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string] $RegistrationRequestFile,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string] $RegistrationOutputFile,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [string] $AgreementNumber
)

# --------------------------------------------------------------------------------------
# Get-Token from already setup Azure Environment

function Get-Token
{
    $azureEnvironment = Get-AzureRmEnvironment -Name $AzureEnvironmentName -ErrorAction Stop

    $tokenTraceProperties = @('DisplayableId', 'GivenName', 'ClientId', 'UniqueId', 'TenantId', 'Resource', 'Authority', 'IdentityProvider', 'ExpiresOn') # FamilyName, IsMultipleResourceRefreshToken, AccessToken, RefreshToken, IdToken
    $tokens = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems()
    Write-Verbose "Usable acccess tokens initialized: $($tokens | Select $tokenTraceProperties | Format-List | Out-String)"

    try
    {
        $subscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
        Select-AzureRmSubscription -SubscriptionId $SubscriptionId
    }
    catch
    {
        Write-Error -Message "Get-AzureRmSubscription failed, run Login-AzureRmAccount to setup Azure PowerShell environment first. `r`n$($_.Exception.Message)"
    }

    $tenantId = $subscriptionInfo.TenantId

    $armToken = $tokens |
        Where Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId |
        Where { $_.TenantId -eq $tenantId } |
        Where { $_.ExpiresOn -gt [datetime]::UtcNow } |
        Select -First 1

    Write-Verbose "Using access token: $($armToken | Select $tokenTraceProperties | Format-List | Out-String)"

    $armAccessToken = $armToken.AccessToken

    return $armAccessToken
}

# --------------------------------------------------------------------------------------
# Main

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$VerbosePreference = [System.Management.Automation.ActionPreference]::Continue

Write-Verbose "$($MyInvocation.MyCommand.Name) : BEGIN on $($env:COMPUTERNAME) as $("$env:USERDOMAIN\$env:USERNAME")"

$registrationFileData = Get-Content -Path $RegistrationRequestFile -Raw | ConvertFrom-Json

$registrationData = @{
    BillingModel         = $BillingModel
    AgreementNumber      = $AgreementNumber
    EnableMarketplace    = ($EnableSyndication -eq $true)
    EnableUsage          = ($ReportUsage -eq $true)
    ObjectId             = $registrationFileData.ObjectId
    CloudId              = $registrationFileData.CloudId
    Issuer               = $registrationFileData.Issuer
    RegionNames          = @(,$registrationFileData.RegionNames)
}

# ---------------------------------------------------------
# Initialize the resource group

$armToken = Get-Token

if(-not $armToken)
{
    Write-Error "Cannot get Access Token to call ARM. Run Login-AzureRmAccount first to setup Azure Powershell environment"
}

$ResourceGroupName = "acrp-$($registrationData.CloudId)"
Write-Verbose "Initializing Resource Group '$ResourceGroupName'"
$resourceGroup = New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -Force
Write-Verbose "Resource group: $(ConvertTo-Json $resourceGroup)"

# ---------------------------------------------------------
# Initialize the registration resource

$azureEnvironment = Get-AzureRmEnvironment -Name $AzureEnvironmentName -ErrorAction Stop
$armResource = $azureEnvironment.ActiveDirectoryServiceEndpointResourceId
$armEndpoint = $azureEnvironment.ResourceManagerUrl

$AzureServicePrincipalName = $registrationFileData.ServicePrincipalName
Write-Verbose "retrieved object id of ARM Application : $($registrationData.ObjectId)"
Write-Verbose "retrieved service principal name of ARM Application : $AzureServicePrincipalName"

$RegistrationName = "registration-acrp-$($registrationData.CloudId)"

$commonRequestParams = @{
    Headers     =  @{ Authorization = "Bearer $armToken" }
    ContentType = 'application/json'
}

try
{
    Write-Verbose "Trying to update registration resource properties with the Azure Stack registration data"

    $regDataJson = ConvertTo-Json $registrationData -Compress -Depth 4
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($regDataJson)
    $regDataBase64Str = [Convert]::ToBase64String($bytes)

    $registrationResource = [pscustomobject]@{
        Id         = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.AzureStack/registrations/$RegistrationName"
        Name       = $RegistrationName
        Type       = "Microsoft.AzureStack/registrations"
        Location   = $Location
        Properties = @{
            RegistrationToken = $regDataBase64Str
        }
    }

    $putRegistrationResourceRequest = @{
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
        Uri    = "$armEndpoint".TrimEnd('/') + $registrationResource.Id + '?api-version=2016-01-01'
        Body   = ConvertTo-Json $registrationResource -Compress
    }

    Write-Verbose "Initializing Azure Registration Resource: $($putRegistrationResourceRequest.Body)"
    $registrationResourceResponse = Invoke-RestMethod @commonRequestParams @putRegistrationResourceRequest -ErrorAction Stop
   
}
catch
{
    Write-Verbose "Fallback, trying with just ObjectId in Properties"
    $registrationResource = [pscustomobject]@{
        Id         = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.AzureStack/registrations/$RegistrationName"
        Name       = $RegistrationName
        Type       = "Microsoft.AzureStack/registrations"
        Location   = $Location
        Properties = [pscustomobject]@{
                            "ObjectId" = $registrationData.ObjectId
                     } 
        }

     $putRegistrationResourceRequest = @{
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
        Uri    = "$armEndpoint".TrimEnd('/') + $registrationResource.Id + '?api-version=2016-01-01'
        Body   = ConvertTo-Json $registrationResource -Compress
    }

    Write-Verbose "Initializing Azure Registration Resource: $($putRegistrationResourceRequest.Body)"
    $registrationResourceResponse = Invoke-RestMethod @commonRequestParams @putRegistrationResourceRequest -ErrorAction Stop
}

Write-Verbose "Registration resource: $(ConvertTo-Json $registrationResourceResponse)"

# ---------------------------------------------------------
# RBAC the Azure identity to the registration resource group

# The RBAC assignment is not idempotent, so must first check if it already exists
$requestUri = $armEndpoint.TrimEnd('/') + "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01"
Write-Verbose "Calling ARM to check if RBAC assignment already exists... ($requestUri)"

try
{
    $existingRbacAssignments = (Invoke-WebRequest -UseBasicParsing @commonRequestParams -Uri $requestUri -Verbose -ErrorAction Stop -TimeoutSec 300).Content | ConvertFrom-Json
    Write-Verbose "Existing RBAC assignments: $(ConvertTo-Json $existingRbacAssignments -Depth 4)"
}
catch
{
    # In the case of errors, there is no response returned to caller (even when error action is set to ignore, continue, etc.) so we extract the response from the thrown exception (if there is one)
    $traceResponse = $_.Exception.Response | Select Method,ResponseUri,StatusCode,StatusDescription,IsFromCache,LastModified | ConvertTo-Json

    # Trace the message to verbose stream as well in case error is not traced in same file as other verbose logs
    $traceMessage = "An error occurred while trying to make an authenticated API call to Resource Manager: $_`r`n`r`nAdditional details: $traceResponse"
    Write-Verbose "ERROR: $traceMessage"

    throw New-Object System.InvalidOperationException($traceMessage)
}

$contributorRoleId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

$existingAssignment = $existingRbacAssignments.Value |
    Where { $_.Properties.PrincipalId      -eq $registrationData.ObjectId } |
    Where { $_.Properties.RoleDefinitionId -eq "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$contributorRoleId" } |
    Where { $_.Properties.scope -eq $scope}

if ($existingAssignment)
{
    Write-Verbose "Owner role assignment for Bridge Application service principal for scope $scope already created!" -Verbose
}
else
{
    $roleAssignmentName = [guid]::NewGuid().ToString()

    $rbacAssignmentResource = [PSCustomObject]@{
        Id       = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Authorization/roleAssignments/$roleAssignmentName"
        Name     = $roleAssignmentName
        Type     = "Microsoft.Authorization/roleAssignments"
        Location = $Location
        Properties = @{
            RoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$contributorRoleId"
            PrincipalId      = $registrationData.ObjectId
            Scope            = $scope
        }
    }

    $rbacAssignmentRequest = @{
        Method = "PUT"
        Uri    = $armEndpoint.TrimEnd('/') + "$($rbacAssignmentResource.Id)?api-version=2015-07-01"
        Body   = $rbacAssignmentResource | ConvertTo-Json
    }

    try
    {
        Write-Verbose "Granting RBAC permission to the Bridge identity on the Azure subscription scope: $scope :`r`n$($rbacAssignmentRequest.Body)"
        $response = (Invoke-WebRequest -UseBasicParsing @commonRequestParams @rbacAssignmentRequest -ErrorAction Stop -Verbose -TimeoutSec 300).Content | ConvertFrom-Json
        Write-Verbose "RBAC assignment response: $(ConvertTo-Json $response)"
    }
    catch
    {
        # In the case of errors, there is no response returned to caller (even when error action is set to ignore, continue, etc.) so we extract the response from the thrown exception (if there is one)
        $traceResponse = $_.Exception.Response | Select Method,ResponseUri,StatusCode,StatusDescription,IsFromCache,LastModified | ConvertTo-Json

        # Trace the message to verbose stream as well in case error is not traced in same file as other verbose logs
        $traceMessage = "An error occurred while trying to perform an RBAC assignment: $_`r`n`r`nAdditional details: $traceResponse"
        Write-Verbose "ERROR: $traceMessage"

        throw New-Object System.InvalidOperationException($traceMessage)
    }
}

$registrationResourceResponse | ConvertTo-Json |Out-File -FilePath $RegistrationOutputFile
write-verbose "Registration response file: $RegistrationOutputFile"

Write-Verbose "$($MyInvocation.MyCommand.Name) : END on $($env:COMPUTERNAME) as $("$env:USERDOMAIN\$env:USERNAME")"

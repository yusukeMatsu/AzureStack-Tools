# Copyright (c) Microsoft Corporation. All rights reserved.
# {FileName} {Version} {DateTime}
# {BuildRepo} {BuildBranch} {BuildType}-{BuildArchitecture}

#requires -Version 4.0
#requires -Module AzureRM.Profile
#requires -Module AzureRM.Resources

<#
.SYNOPSIS
    Initializes the Azure PowerShell environment
#>
[CmdletBinding(DefaultParameterSetName='UserCredential')]
param
(
     # The environment of the Azure credential and subscription.
    [Parameter(Mandatory=$false)]
    [ValidateSet('AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureGermanCloud')]
    [string] $AzureEnvironmentName,

    # The Azure credential with "owner" permissions on the target Azure Subscription.
    [Parameter(Mandatory=$false, ParameterSetName="UserCredential")]
    [ValidateNotNull()]
    [pscredential] $AzureCredential,

    [Parameter(Mandatory=$true)]
    [string] $AzureAdTenantId,

    [Parameter(Mandatory=$true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true, ParameterSetName="AccessToken")]
    [ValidateNotNull()]
    [securestring] $AccessToken,

    [Parameter(Mandatory=$true, ParameterSetName="AccessToken")]
    [ValidateNotNull()]
    [string] $AzureAccountId,

    [Parameter(Mandatory = $false)]
    [switch] $ServicePrincipal,

    [Parameter(Mandatory=$true, ParameterSetName="ServicePrincipal")]
    [ValidateNotNull()]
    [string] $ServicePrincipalCertThumbprint,

    [Parameter(Mandatory=$true, ParameterSetName="ServicePrincipal")]
    [ValidateNotNull()]
    [string] $ClientId
)

# ---------------------------------------------------------
# Initialize Azure Powershell environment

#region Azure Powershell initialization
if($ServicePrincipal)
{
    if($ClientId -and $ServicePrincipalCertThumbprint)
    {
        Write-Verbose "Using service principal to initialize Azure Powershell environment"
        $azureEnvironment = Get-AzureRmEnvironment -Name $AzureEnvironmentName -ErrorAction Stop
        Add-AzureRmAccount -Environment $azureEnvironment -TenantId $AzureAdTenantId -ServicePrincipal -CertificateThumbprint $ServicePrincipalCertThumbprint -ApplicationId $ClientId
        $subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
        Write-Verbose "Selected Azure Subscription: $(ConvertTo-Json $subscription)"
    }
    else
    {
        throw "ServicePrincipal option was provided but ClientId or ClientCert is null"
    }
}
elseif($AccessToken -and $AzureAccountId)
{
    Write-Verbose "Using refresh token to initialize Azure Powershell environment"
    $azureEnvironment = Get-AzureRmEnvironment -Name $AzureEnvironmentName
    Add-AzureRmAccount -AccessToken $AccessToken -EnvironmentName $AzureEnvironmentName -TenantId $AzureAdTenantId -AccountId $AzureAccountId -SubscriptionId $SubscriptionId -Verbose 
    $subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
}
else
{
    Write-Verbose "Using user credential to initialize Azure Powershell environment"
    $azureEnvironment = Get-AzureRmEnvironment -Name $AzureEnvironmentName -ErrorAction Stop
    if($AzureCredential)
    {
        Write-Verbose "Using provided user credentials"
        Add-AzureRmAccount -Environment $azureEnvironment -Credential $AzureCredential -TenantId $AzureAdTenantId
        $subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
        Initialize-GraphEnvironment -DirectoryTenantId $AzureAdTenantId -UserCredential $AzureCredential -Environment $AzureEnvironmentName
        Write-Verbose "Selected Azure Subscription: $(ConvertTo-Json $subscription)"
    }
    else
    {
        Write-Verbose "Using interactive flow to initialize Azure Powershell environment"
        Login-AzureRmAccount -Environment $azureEnvironment -EnvironmentName
    }
}
#endregion

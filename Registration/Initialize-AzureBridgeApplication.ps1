<###################################################
 #                                                 #
 #  Copyright (c) Microsoft. All rights reserved.  #
 #                                                 #
 ##################################################>

#requires -Version 4.0
#requires -Modules @{ModuleName = "AzureRM.Profile" ; ModuleVersion = "2.7"} 
#requires -Modules @{ModuleName = "AzureRM.Resources" ; ModuleVersion = "3.7"} 

<#
.Synopsis
   Creates Azure Bridge application and imports Key Credential 
.EXAMPLE
   .\Initialize-AzureBridgeApplication.ps1 -ClientCertPath "c:\temp\clientcert.cer" [-ApplicationId <String>] [-HomePage <String>] [-ApplicationDisplayName <String>] [-Force] [-AzureEnvironmentName <String>] [-AzureCredential 
    <PSCredential>] [-ServicePrincipal] [<CommonParameters>]

#>

[CmdletBinding(DefaultParameterSetName='NewApp')]
param 
(
    # Cert to import
    [Parameter(Mandatory=$true)]
    [string] $ClientCertPath,

    [Parameter(Mandatory=$true, ParameterSetName="UpdateKeyCred")]
    [ValidateNotNull()]
    [string] $ApplicationId,

    [Parameter(Mandatory=$true, ParameterSetName="UpdateKeyCred")]
    [ValidateNotNull()]
    [string] $SpObjectId,

    [Parameter(Mandatory=$true, ParameterSetName="NewApp")]
    [ValidateNotNull()]
    [string] $ApplicationIdUri,

    [Parameter(Mandatory=$false, ParameterSetName="NewApp")]
    [ValidateNotNull()]
    [string] $ApplicationHomePage,

    [Parameter(Mandatory=$true, ParameterSetName="NewApp")]
    [ValidateNotNull()]
    [string] $ApplicationDisplayName
)

# --------------------------------------------------------------------------------------
# Main

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$VerbosePreference = [System.Management.Automation.ActionPreference]::Continue

# ---------------------------------------------------------
# Create Application if it doesn't exist or add key cred
# if application exists

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($clientCertPath)
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

Write-Verbose "Create or Update Azure AD application and service principal for Azure Bridge"

$keyId = [guid]::NewGuid()
$keyCredential = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
$keyCredential.KeyId = $keyId
$keyCredential.CertValue = $keyValue
$keyCredential.StartDate = $cert.NotBefore
$keyCredential.EndDate = $cert.NotAfter

Write-Verbose -Message "Key Credential = $(ConvertTo-Json $keyCredential)" 

$azureAdAppParameters = @{
                            DisplayName    = $ApplicationDisplayName
                            IdentifierUris = @($ApplicationIdUri)
                            HomePage       = $ApplicationHomePage
                            KeyCredentials = @($keyCredential)
                        }

$adApp = Get-AzureRmADApplication -DisplayNameStartWith $ApplicationDisplayName
if($adApp)
{
    Write-Warning "AD application with display name $ApplicationDisplayName already exists"
}
else
{
    $adApp = New-AzureRmADApplication @azureAdAppParameters -ErrorAction SilentlyContinue
    Write-Verbose "Created Azure AD application for Azure Bridge : $(ConvertTo-Json $adApp)"
}

$adSp = Get-AzureRmADServicePrincipal -SearchString $ApplicationDisplayName
if($adSp)
{
    Write-Warning "AD service principal with display name $ApplicationDisplayName already exists"
}
else
{
    $adSp = New-AzureRmADServicePrincipal -ApplicationId $adApp.ApplicationId -ErrorAction SilentlyContinue
    Write-Verbose "Created Azure AD service principal for Azure Bridge : $(ConvertTo-Json $adSp)" 
}

$spCreds = Get-AzureRmADSpCredential -ObjectId $adSp.Id 

if($spCreds)
{
    Write-Warning "Service principal with following keys exist, new key for client cert $ClientCertPath will be added"
    foreach($spCred in $spCreds)
    {
        Write-Verbose "StartDate: $($spCred.StartDate) EndDate: $($spCred.EndDate) KeyId: $($spCred.KeyId) KeyType: $($spCred.Type)"
    }
}

$spCred = New-AzureRmADSpCredential -ObjectId $adSp.Id -CertValue $keyValue -StartDate $cert.NotBefore -EndDate $cert.NotAfter -ErrorAction SilentlyContinue
Write-Verbose "Added Key credential cert thumbprint $($cert.Thumbprint) start date: $($cert.NotBefore) end date: $($cert.NotAfter)" 

$spCreds = Get-AzureRmADSpCredential -ObjectId $adSp.Id

# Return info about the Azure Bridge application that was created or updated
 $bridgeAppInfo = @{
        ObjectId               = $adApp.ObjectId
        ApplicationId          = $adApp.ApplicationId
        ServicePrincipalObjId  = $adSp.Id
        ServicePrincipalNames  = $adSp.ServicePrincipalNames
        SPCredentialInfo       = $spCreds
}

($bridgeAppInfo)

$bridgeAppInfoFile = [System.IO.Path]::GetTempFileName()
ConvertTo-Json $bridgeAppInfo | Out-File -FilePath $bridgeAppInfoFile

Write-Verbose "Azure Bridge Application info : $(ConvertTo-Json $bridgeAppInfo)"
Write-Verbose "Use ServicePrincipal Object Id : $($adSp.Id) when running New-RegistrationRequest.ps1 script in AzureStack"
Write-Verbose "Azure Bridge App info file : $bridgeAppInfoFile "

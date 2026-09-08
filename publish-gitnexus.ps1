#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Tag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ACR_NAME = 'crappmoddevswc'
$RESOURCE_GROUP = 'app-modernization'
$AKS_CLUSTER = 'aks-appmod-dev-swc'
$K8S_NAMESPACE = 'app-modernization'
$IMAGE_NAME = 'gitnexus-server'
$DEPLOYMENT_NAME = 'gitnexus-server'
$DEFAULT_TAG = 'latest'

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE"
    }
}

Assert-Command 'az'
Assert-Command 'kubectl'

if ([string]::IsNullOrWhiteSpace($Tag)) {
    $Tag = Read-Host "Image tag (Enter for $DEFAULT_TAG)"
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = $DEFAULT_TAG
    }
}

if ($Tag -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw "Invalid image tag '$Tag'. Use 1-128 characters: letters, numbers, '.', '_' or '-'."
}

Push-Location $PSScriptRoot
try {
    Write-Host "Checking Azure login..."
    & az account show --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Tool 'az' @('login')
    }

    $LOGIN_SERVER = (& az acr show `
        --name $ACR_NAME `
        --resource-group $RESOURCE_GROUP `
        --query loginServer `
        --output tsv).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($LOGIN_SERVER)) {
        throw "Unable to resolve the ACR login server."
    }

    $IMAGE_REFERENCE = "${LOGIN_SERVER}/${IMAGE_NAME}:${Tag}"
    Write-Host "ACR:   $LOGIN_SERVER"
    Write-Host "Image: $IMAGE_REFERENCE"
    Write-Host "Context: $PSScriptRoot"

    Write-Host "`nChecking ACR health..."
    & az @(
        'acr', 'check-health',
        '--name', $ACR_NAME,
        '--ignore-errors',
        '--yes'
    )
    $healthExitCode = $LASTEXITCODE
    if ($healthExitCode -ne 0) {
        Write-Warning (
            "ACR health check returned exit code $healthExitCode. " +
            "Continuing because az acr build runs in Azure and does not require local Helm or Docker."
        )
    }

    Write-Host "`nBuilding and pushing the image in ACR..."
    Invoke-Tool 'az' @(
        'acr', 'build',
        '--registry', $ACR_NAME,
        '--platform', 'linux/amd64',
        '--build-arg', 'TARGETARCH=amd64',
        '--file', '.\Dockerfile.cli',
        '--image', "${IMAGE_NAME}:${Tag}",
        '.'
    )

    Write-Host "`nLoading AKS credentials..."
    Invoke-Tool 'az' @(
        'aks', 'get-credentials',
        '--resource-group', $RESOURCE_GROUP,
        '--name', $AKS_CLUSTER,
        '--overwrite-existing'
    )

    Write-Host "`nUpdating the Kubernetes Deployment..."
    Invoke-Tool 'kubectl' @(
        '--namespace', $K8S_NAMESPACE,
        'set', 'image',
        "deployment/$DEPLOYMENT_NAME",
        "${IMAGE_NAME}=${IMAGE_REFERENCE}"
    )

    # Required when reusing a tag such as latest-with-reindex.
    Write-Host "Restarting the Deployment to pull the new image..."
    Invoke-Tool 'kubectl' @(
        '--namespace', $K8S_NAMESPACE,
        'rollout', 'restart',
        "deployment/$DEPLOYMENT_NAME"
    )

    Write-Host "`nWaiting for the rollout..."
    Invoke-Tool 'kubectl' @(
        '--namespace', $K8S_NAMESPACE,
        'rollout', 'status',
        "deployment/$DEPLOYMENT_NAME",
        '--timeout=10m'
    )

    Write-Host "`nCurrent GitNexus pods:"
    Invoke-Tool 'kubectl' @(
        '--namespace', $K8S_NAMESPACE,
        'get', 'pods',
        '--selector', 'app=gitnexus-server',
        '--output', 'wide'
    )

    Write-Host "`nPublished and deployed: $IMAGE_REFERENCE"
}
finally {
    Pop-Location
}

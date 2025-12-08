# This tool is provided "as is" without any warranties or support. 


Write-Host """
██████╗░███████╗░█████╗░░█████╗░████████╗██████╗░███████╗██╗███╗░░██╗██████╗░
██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝╚════██╗██╔════╝██║████╗░██║██╔══██╗
██████╔╝█████╗░░███████║██║░░╚═╝░░░██║░░░░░███╔═╝█████╗░░██║██╔██╗██║██║░░██║
██╔══██╗██╔══╝░░██╔══██║██║░░██╗░░░██║░░░██╔══╝░░██╔══╝░░██║██║╚████║██║░░██║
██║░░██║███████╗██║░░██║╚█████╔╝░░░██║░░░███████╗██║░░░░░██║██║░╚███║██████╔╝
╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░╚════╝░░░░╚═╝░░░╚══════╝╚═╝░░░░░╚═╝╚═╝░░╚══╝╚═════╝░
by e-Xpert Solutions"""

Write-Host ""
Write-Host ""

# ======================================================
# Vulnerable version definitions
# ======================================================
$vulnerabilityThresholds = @{
    "react-server-dom-webpack" = @{
        "19.0" = "19.0.0"
        "19.1" = "19.1.1"
        "19.2" = "19.2.0"
    }
    "react-server-dom-turbopack" = @{
        "19.0" = "19.0.0"
        "19.1" = "19.1.1"
        "19.2" = "19.2.0"
    }
    "react-server-dom-parcel" = @{
        "19.0" = "19.0.0"
        "19.1" = "19.1.1"
        "19.2" = "19.2.0"
    }
    "react" = @{
        "19.0" = "19.0.0"
        "19.1" = "19.1.1"
        "19.2" = "19.2.0"
    }
    "react-dom" = @{
        "19.0" = "19.0.0"
        "19.1" = "19.1.1"
        "19.2" = "19.2.0"
    }
    "next" = @{
        "15.0" = "15.0.4"
        "15.1" = "15.1.8"
        "19.2" = "15.2.5"
        "15.3" = "15.3.5"
        "15.4" = "15.4.7"
        "15.5" = "15.5.6"
        "16.0" = "16.0.6"
    }
}

$vulnerableNextJSCanary = @("14.3.0-canary.77")

$hostname = $env:COMPUTERNAME

# ======================================================
# Normalize version to [version] type for comparison
# ======================================================
function Normalize-Version {
    param([string]$v)

    $v = $v.Trim().TrimStart("^","~")

    # Remove prerelease tags (e.g., -beta, -rc)
    $v = $v.Split("-")[0]

    $parts = $v -split "\."
    while ($parts.Count -lt 3) { $parts += "0" }
    return [version]($parts[0..2] -join ".")
}

# ======================================================
# Test if React package version is vulnerable
# ======================================================
function Test-VersionIsVulnerable {
    param(
        [string]$InstalledVersion,
        [hashtable]$Thresholds  # per-minor-version cutoff
    )

    $norm = Normalize-Version $InstalledVersion
    $majorMinor = "$($norm.Major).$($norm.Minor)"

    if (-not $Thresholds.ContainsKey($majorMinor)) {
        return $false   # no threshold → safe
    }

    $cutoff = Normalize-Version $Thresholds[$majorMinor]

    return ($norm -le $cutoff)
}

# ======================================================
# Test if NextJS canary version is vulnerable
# ======================================================
function Test-VersionIsVulnerable-Canary {
    param(
        [string]$InstalledVersion,
        [string[]]$VulnerableVersions
    )

    # Example: 14.3.0-canary.120
    $instMain, $instCanary = $InstalledVersion -split "-canary\."
    $vulnMain, $vulnCanary = $VulnerableVersions -split "-canary\."

    $instVer = Normalize-Version $instMain
    $vulnVer = Normalize-Version $vulnMain

    if ($instVer -lt $vulnVer) { return $false }
    if ($instVer -gt $vulnVer) { return $true }

    # Main versions equal → compare canary index
    return ([int]$instCanary -ge [int]$vulnCanary)
}

# ======================================================
# Scan for package.json files
# ======================================================
if ($PSScriptRoot) {
    $BasePath = $PSScriptRoot
} else {
    $BasePath = (Get-Location).Path
}

Write-Host "Scanning $BasePath and subfolders for package.json..." -ForegroundColor Cyan
$packageFiles = Get-ChildItem -Path $BasePath -Recurse -Filter "package.json" -ErrorAction SilentlyContinue

if ($packageFiles.Count -eq 0) {
    Write-Host "No package.json found." -ForegroundColor Yellow
    exit
}

# ======================================================
# Process each package.json
# ======================================================
$results = @()

foreach ($pkg in $packageFiles) {

    Write-Host "`nProcessing: $($pkg.DirectoryName)" -ForegroundColor Green

    try {
        $json = Get-Content $pkg.FullName | ConvertFrom-Json
    } catch {
        Write-Host "Cannot read JSON." -ForegroundColor Red
        continue
    }

    # Merge dependencies + devDependencies
    $dependencies = @{}
    if ($json.dependencies) {
        foreach ($prop in $json.dependencies.psobject.Properties) {
            $dependencies[$prop.Name] = $prop.Value
        }
    }
    if ($json.devDependencies) {
        foreach ($prop in $json.devDependencies.psobject.Properties) {
            $dependencies[$prop.Name] = $prop.Value
        }
    }

    # ==================================================
    # Check each package
    # ==================================================
    foreach ($lib in $dependencies.Keys) {

        $version = $dependencies[$lib].TrimStart("^","~")
        $isVulnerable = $false
        $vulnSource = ""

        switch ($lib) {

            "react-server-dom-webpack" {
                if (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["react-server-dom-webpack"]) {
                    $isVulnerable = $true
                    $vulnSource = "react-server-dom-webpack"
                }
            }

            "react-server-dom-turbopack" {
                if (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["react-server-dom-turbopack"]) {
                    $isVulnerable = $true
                    $vulnSource = "react-server-dom-turbopack"
                }
            }

            "react-server-dom-parcel" {
                if (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["react-server-dom-parcel"]) {
                    $isVulnerable = $true
                    $vulnSource = "react-server-dom-parcel"
                }
            }

            "react" {
                if (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["react"]) {
                    $isVulnerable = $true
                    $vulnSource = "react"
                }
            }

            "react-dom" {
                if (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["react-dom"]) {
                    $isVulnerable = $true
                    $vulnSource = "react-dom"
                }
            }

            "next" {
                if ($version -like "*canary*") {
                    if (Test-VersionIsVulnerable-Canary $version $vulnerableNextJSCanary) {
                        $isVulnerable = $true
                        $vulnSource = "nextJS (canary)"
                    }
                }
                #elseif ($vulnerableNextJS -contains $version) {
                elseif (Test-VersionIsVulnerable -InstalledVersion $version -Thresholds $vulnerabilityThresholds["next"]) {
                    $isVulnerable = $true
                    $vulnSource = "nextJS"
                }
            }
        }

        if ($isVulnerable) {
            Write-Host "❗ $lib $version is VULNERABLE" -ForegroundColor Red

            $results += [PSCustomObject]@{
                Hostname    = $hostname
                Project     = $pkg.DirectoryName
                Package     = $lib
                Installed   = $version
                Vulnerable  = $true
            }
        }
    }
}

# ======================================================
# Output results
# ======================================================
Write-Host "`nScan complete.`n" -ForegroundColor Cyan
if ($results) {
    $results | Format-Table -AutoSize
}
else {
    Write-Host "No vulnerable version." -ForegroundColor Cyan
}

$csvPath = Join-Path $BasePath "$hostname-react-audit.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`nReport saved to:`n$csvPath" -ForegroundColor Green


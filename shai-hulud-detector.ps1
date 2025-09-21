# Shai-Hulud NPM Supply Chain Attack Detection Script (PowerShell)
# Version: 1.2.0
# Detects indicators of compromise from the September 2025 npm attack
# Usage: .\shai-hulud-detector.ps1 [-Path] <directory_to_scan> [-Paranoid]

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,
    
    [Parameter()]
    [switch]$Paranoid,
    
    [Parameter()]
    [switch]$Help
)

# Show help
if ($Help) {
    Write-Host @"
Usage: .\shai-hulud-detector.ps1 [-Path] <directory_to_scan> [-Paranoid]

OPTIONS:
  -Path        Directory to scan for Shai-Hulud indicators
               Supports paths with spaces, special characters, relative/absolute paths
  -Paranoid    Enable additional security checks (typosquatting, network patterns)
               These are general security features, not specific to Shai-Hulud
  -Help        Show this help message

EXAMPLES:
  .\shai-hulud-detector.ps1 "C:\path with spaces\project"       # Quoted path with spaces
  .\shai-hulud-detector.ps1 .\relative-path                     # Relative path
  .\shai-hulud-detector.ps1 "C:\path-with-dashes\project"       # Path with dashes
  .\shai-hulud-detector.ps1 C:\simple\path -Paranoid           # Paranoid mode
"@
    exit 0
}

# Check if Path is provided when not showing help
if ([string]::IsNullOrEmpty($Path)) {
    Write-Host "Error: Path parameter is required. Use -Help for usage information." -ForegroundColor Red
    exit 1
}

# Normalize and validate the path
function Initialize-ScanPath {
    param([string]$InputPath)
    
    try {
        # Handle empty or null paths
        if ([string]::IsNullOrWhiteSpace($InputPath)) {
            throw "Path cannot be empty or whitespace only"
        }
        
        # Remove quotes if present (PowerShell sometimes preserves them)
        $CleanPath = $InputPath.Trim('"', "'")
        
        # Resolve relative paths and normalize
        if ([System.IO.Path]::IsPathRooted($CleanPath)) {
            # Absolute path - normalize it
            $ResolvedPath = [System.IO.Path]::GetFullPath($CleanPath)
        } else {
            # Relative path - resolve against current directory
            $ResolvedPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $CleanPath))
        }
        
        # Validate the path exists and is a directory
        if (-not (Test-Path -Path $ResolvedPath -PathType Container)) {
            if (Test-Path -Path $ResolvedPath -PathType Leaf) {
                throw "Path '$ResolvedPath' exists but is a file, not a directory"
            } else {
                throw "Directory '$ResolvedPath' does not exist"
            }
        }
        
        # Additional validation for problematic characters
        $ProblematicChars = @('<', '>', '|', '*', '?')
        foreach ($char in $ProblematicChars) {
            if ($ResolvedPath.Contains($char)) {
                Write-Warning "Path contains potentially problematic character '$char': $ResolvedPath"
            }
        }
        
        # Check for very long paths (Windows limitation)
        if ($ResolvedPath.Length -gt 260) {
            Write-Warning "Path is very long ($($ResolvedPath.Length) characters) and may cause issues on some Windows systems"
        }
        
        Write-Verbose "Normalized path: '$InputPath' -> '$ResolvedPath'"
        return $ResolvedPath
        
    } catch {
        Write-Host "Error processing path '$InputPath': $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Initialize and validate the scan path
$ScanPath = Initialize-ScanPath -InputPath $Path

# Color codes for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

# Show file content preview (simplified for less verbose output)
function Show-FilePreview {
    param(
        [string]$FilePath,
        [string]$Context
    )
    
    # Only show file preview for HIGH RISK items to reduce noise
    if ($Context -like "*HIGH RISK*") {
        Write-Host "   File: $FilePath" -ForegroundColor Blue
        Write-Host "   Context: $Context" -ForegroundColor Blue
        Write-Host ""
    }
}

# Known malicious file hashes (source: https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
$MALICIOUS_HASHLIST = @(
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
)

# Global arrays to store findings
$global:WORKFLOW_FILES = @()
$global:MALICIOUS_HASHES = @()
$global:COMPROMISED_FOUND = @()
$global:SUSPICIOUS_CONTENT = @()
$global:CRYPTO_PATTERNS = @()
$global:GIT_BRANCHES = @()
$global:POSTINSTALL_HOOKS = @()
$global:TRUFFLEHOG_ACTIVITY = @()
$global:SHAI_HULUD_REPOS = @()
$global:NAMESPACE_WARNINGS = @()
$global:LOW_RISK_FINDINGS = @()
$global:INTEGRITY_ISSUES = @()
$global:TYPOSQUATTING_WARNINGS = @()
$global:NETWORK_EXFILTRATION_WARNINGS = @()

# Load compromised packages from external file
function Load-CompromisedPackages {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $packagesFile = Join-Path $scriptDir "compromised-packages.txt"
    
    $script:COMPROMISED_PACKAGES = @()
    
    if (Test-Path $packagesFile) {
        $content = Get-Content $packagesFile
        foreach ($line in $content) {
            # Skip comments and empty lines
            if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            
            # Add valid package:version lines to array
            if ($line -match '^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+') {
                $script:COMPROMISED_PACKAGES += $line
            }
        }
        
        Write-ColorOutput "Loaded $($script:COMPROMISED_PACKAGES.Count) compromised packages from $packagesFile" -Color Blue
    }
    else {
        Write-ColorOutput "Warning: $packagesFile not found, using embedded package list" -Color Yellow
        $script:COMPROMISED_PACKAGES = @(
            "@ctrl/tinycolor:4.1.0"
            "@ctrl/tinycolor:4.1.1"
            "@ctrl/tinycolor:4.1.2"
            "@ctrl/deluge:1.2.0"
            "angulartics2:14.1.2"
            "koa2-swagger-ui:5.11.1"
            "koa2-swagger-ui:5.11.2"
        )
    }
}

# Known compromised namespaces
$COMPROMISED_NAMESPACES = @(
    "@crowdstrike"
    "@art-ws"
    "@ngx"
    "@ctrl"
    "@nativescript-community"
    "@ahmedhfarag"
    "@operato"
    "@teselagen"
    "@things-factory"
    "@hestjs"
    "@nstudio"
    "@basic-ui-components-stc"
    "@nexe"
    "@thangved"
    "@tnf-dev"
    "@ui-ux-gang"
    "@yoobic"
)

# Check for shai-hulud workflow files
function Check-WorkflowFiles {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for malicious workflow files..." -Color Blue
    
    $files = Get-ChildItem -Path $ScanDir -Filter "shai-hulud-workflow.yml" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $global:WORKFLOW_FILES += $file.FullName
    }
}

# Calculate SHA256 hash
function Get-FileHashSHA256 {
    param([string]$FilePath)
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    }
    catch {
        return $null
    }
}

# Check file hashes against known malicious hash
function Check-FileHashes {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking file hashes for known malicious content..." -Color Blue
    
    $files = Get-ChildItem -Path $ScanDir -Include "*.js","*.ts","*.json" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        $fileHash = Get-FileHashSHA256 -FilePath $file.FullName
        if ($fileHash -and $MALICIOUS_HASHLIST -contains $fileHash) {
            $global:MALICIOUS_HASHES += "$($file.FullName):$fileHash"
        }
    }
}

# Check package.json files for compromised packages
function Check-Packages {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking package.json files for compromised packages..." -Color Blue
    
    $packageFiles = Get-ChildItem -Path $ScanDir -Filter "package.json" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($packageFile in $packageFiles) {
        $content = Get-Content -Path $packageFile.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            # Check for specific compromised packages
            foreach ($packageInfo in $script:COMPROMISED_PACKAGES) {
                $parts = $packageInfo -split ':'
                $packageName = $parts[0]
                $maliciousVersion = $parts[1]
                
                if ($content -match [regex]::Escape($packageName)) {
                    # Try to extract version using simpler pattern
                    $versionPattern = [regex]::Escape($packageName) + '.*?' + [regex]::Escape($maliciousVersion)
                    if ($content -match $versionPattern) {
                        $global:COMPROMISED_FOUND += "$($packageFile.FullName):$packageName@$maliciousVersion"
                    }
                }
            }
            
            # Check for suspicious namespaces
            foreach ($namespace in $COMPROMISED_NAMESPACES) {
                if ($content -match [regex]::Escape("$namespace/")) {
                    $global:NAMESPACE_WARNINGS += "$($packageFile.FullName):Contains packages from compromised namespace: $namespace"
                }
            }
        }
    }
}

# Check for suspicious postinstall hooks
function Check-PostinstallHooks {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for suspicious postinstall hooks..." -Color Blue
    
    $packageFiles = Get-ChildItem -Path $ScanDir -Filter "package.json" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($packageFile in $packageFiles) {
        $content = Get-Content -Path $packageFile.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            # Use simpler pattern matching
            if ($content -match '"postinstall"') {
                # Extract the postinstall command more safely
                $lines = $content -split "`n"
                foreach ($line in $lines) {
                    if ($line -like '*"postinstall"*:*') {
                        $parts = $line -split ':', 2
                        if ($parts.Count -eq 2) {
                            $postinstallCmd = $parts[1].Trim().Trim('"')
                            # Check for suspicious patterns
                            if ($postinstallCmd -match 'curl|wget|node -e|eval') {
                                $global:POSTINSTALL_HOOKS += "$($packageFile.FullName):Suspicious postinstall: $postinstallCmd"
                            }
                        }
                    }
                }
            }
        }
    }
}

# Check for suspicious content patterns
function Check-Content {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for suspicious content patterns..." -Color Blue
    
    $files = Get-ChildItem -Path $ScanDir -Include "*.js","*.ts","*.json","*.yml","*.yaml" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            if ($content -match 'webhook\.site') {
                $global:SUSPICIOUS_CONTENT += "$($file.FullName):webhook.site reference"
            }
            if ($content -match 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7') {
                $global:SUSPICIOUS_CONTENT += "$($file.FullName):malicious webhook endpoint"
            }
        }
    }
}

# Check for cryptocurrency theft patterns
function Check-CryptoTheftPatterns {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for cryptocurrency theft patterns..." -Color Blue
    
    $files = Get-ChildItem -Path $ScanDir -Include "*.js","*.ts","*.json" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            # Check for wallet address patterns
            if ($content -match '0x[a-fA-F0-9]{40}' -and $content -match 'ethereum|wallet|address|crypto') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):Ethereum wallet address patterns detected"
            }
            
            # Check for XMLHttpRequest hijacking
            if ($content -match 'XMLHttpRequest\.prototype\.send') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):XMLHttpRequest prototype modification detected"
            }
            
            # Check for specific malicious functions
            if ($content -match 'checkethereumw|runmask|newdlocal|_0x19ca67') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):Known crypto theft function names detected"
            }
            
            # Check for known attacker wallets
            if ($content -match '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):Known attacker wallet address detected - HIGH RISK"
            }
            
            # Check for npmjs.help phishing domain
            if ($content -match 'npmjs\.help') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):Phishing domain npmjs.help detected"
            }
            
            # Check for javascript obfuscation
            if ($content -match 'javascript-obfuscator') {
                $global:CRYPTO_PATTERNS += "$($file.FullName):JavaScript obfuscation detected"
            }
        }
    }
}

# Check for shai-hulud git branches
function Check-GitBranches {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for suspicious git branches..." -Color Blue
    
    $gitDirs = Get-ChildItem -Path $ScanDir -Filter ".git" -Directory -Recurse -Force -ErrorAction SilentlyContinue
    
    foreach ($gitDir in $gitDirs) {
        $repoDir = $gitDir.Parent.FullName
        $headsDir = Join-Path $gitDir.FullName "refs\heads"
        
        if (Test-Path $headsDir) {
            $branches = Get-ChildItem -Path $headsDir -Filter "*shai-hulud*" -File -ErrorAction SilentlyContinue
            foreach ($branch in $branches) {
                $commitHash = Get-Content -Path $branch.FullName -ErrorAction SilentlyContinue
                if ($commitHash) {
                    $global:GIT_BRANCHES += "${repoDir}:Branch '$($branch.Name)' (commit: $($commitHash.Substring(0, [Math]::Min(8, $commitHash.Length)))...)"
                }
            }
        }
    }
}

# Helper function to check for legitimate patterns
function Test-LegitimatePattern {
    param(
        [string]$FilePath,
        [string]$ContentSample
    )
    
    # Vue.js development patterns
    if ($ContentSample -match 'process\.env\.NODE_ENV' -and $ContentSample -match 'production') {
        return $true  # legitimate
    }
    
    # Common framework patterns
    if ($ContentSample -match 'createApp|Vue|React|Angular') {
        return $true  # legitimate
    }
    
    # Package manager and build tool patterns
    if ($ContentSample -match 'webpack|vite|rollup|parcel|esbuild') {
        return $true  # legitimate
    }
    
    # Common development patterns
    if ($ContentSample -match 'package\.json|tsconfig|eslint|prettier') {
        return $true  # legitimate
    }
    
    # Express.js and server patterns
    if ($ContentSample -match 'express\(\)|app\.listen|req\.body|res\.json') {
        return $true  # legitimate
    }
    
    return $false  # potentially suspicious
}

# Helper function to determine file context
function Get-FileContext {
    param([string]$FilePath)
    
    if ($FilePath -match '\\node_modules\\') { return "node_modules" }
    if ($FilePath -match '\.(md|txt|rst)$') { return "documentation" }
    if ($FilePath -match '\.d\.ts$') { return "type_definitions" }
    if ($FilePath -match '\\(dist|build|public)\\') { return "build_output" }
    if ((Split-Path -Leaf $FilePath) -match 'config') { return "configuration" }
    
    return "source_code"
}

# Check for Trufflehog activity
function Check-TrufflehogActivity {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for Trufflehog activity and secret scanning..." -Color Blue
    
    # Look for trufflehog binary files
    $binaryFiles = Get-ChildItem -Path $ScanDir -Filter "*trufflehog*" -Recurse -File -ErrorAction SilentlyContinue
    foreach ($binaryFile in $binaryFiles) {
        $global:TRUFFLEHOG_ACTIVITY += "$($binaryFile.FullName):HIGH:Trufflehog binary found"
    }
    
    # Check for trufflehog activity in files
    $files = Get-ChildItem -Path $ScanDir -Include "*.js","*.py","*.sh","*.json" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $context = Get-FileContext -FilePath $file.FullName
            
            # Check for trufflehog references
            if ($content -match 'trufflehog|TruffleHog') {
                switch ($context) {
                    "documentation" { continue }
                    { $_ -in "node_modules", "type_definitions", "build_output" } {
                        $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):MEDIUM:Contains trufflehog references in $context"
                    }
                    default {
                        if ($content -match 'subprocess' -and $content -match 'curl') {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):HIGH:Suspicious trufflehog execution pattern"
                        }
                        else {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):MEDIUM:Contains trufflehog references in source code"
                        }
                    }
                }
            }
            
            # Check for credential scanning patterns
            if ($content -match 'AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN') {
                switch ($context) {
                    { $_ -in "type_definitions", "documentation" } { continue }
                    "node_modules" {
                        if (-not (Test-LegitimatePattern -FilePath $file.FullName -ContentSample $content)) {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):LOW:Credential patterns in node_modules"
                        }
                    }
                    "configuration" {
                        if ($content -notmatch 'DefinePlugin|webpack') {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):MEDIUM:Credential patterns in configuration"
                        }
                    }
                    default {
                        if ($content -match 'webhook\.site|curl|https\.request') {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):HIGH:Credential patterns with potential exfiltration"
                        }
                        elseif (-not (Test-LegitimatePattern -FilePath $file.FullName -ContentSample $content)) {
                            $global:TRUFFLEHOG_ACTIVITY += "$($file.FullName):MEDIUM:Contains credential scanning patterns"
                        }
                    }
                }
            }
        }
    }
}

# Check for Shai-Hulud repositories
function Check-ShaiHuludRepos {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking for Shai-Hulud repositories and migration patterns..." -Color Blue
    
    $gitDirs = Get-ChildItem -Path $ScanDir -Filter ".git" -Directory -Recurse -ErrorAction SilentlyContinue
    
    foreach ($gitDir in $gitDirs) {
        $repoDir = $gitDir.Parent.FullName
        $repoName = Split-Path -Leaf $repoDir
        
        # Check repository name
        if ($repoName -match 'shai-hulud|Shai-Hulud') {
            $global:SHAI_HULUD_REPOS += "${repoDir}:Repository name contains 'Shai-Hulud'"
        }
        
        # Check for migration pattern
        if ($repoName -match '-migration') {
            $global:SHAI_HULUD_REPOS += "${repoDir}:Repository name contains migration pattern"
        }
        
        # Check git config for shai-hulud references
        $gitConfig = Join-Path $gitDir.FullName "config"
        if (Test-Path $gitConfig) {
            $configContent = Get-Content -Path $gitConfig -Raw -ErrorAction SilentlyContinue
            if ($configContent -match 'shai-hulud|Shai-Hulud') {
                $global:SHAI_HULUD_REPOS += "${repoDir}:Git remote contains 'Shai-Hulud'"
            }
        }
        
        # Check for suspicious data.json
        $dataJson = Join-Path $repoDir "data.json"
        if (Test-Path $dataJson) {
            $dataContent = Get-Content -Path $dataJson -Raw -ErrorAction SilentlyContinue
            if ($dataContent -match 'eyJ' -and $dataContent -match '==') {
                $global:SHAI_HULUD_REPOS += "${repoDir}:Contains suspicious data.json (possible base64-encoded credentials)"
            }
        }
    }
}

# Transform pnpm-lock.yaml to pseudo-package-lock format
function Transform-PnpmYaml {
    param([string]$FilePath)
    
    $output = @{
        packages = @{}
    }
    
    $lines = Get-Content -Path $FilePath
    $depth = 0
    $path = @()
    
    foreach ($line in $lines) {
        # Find indentation
        $indentMatch = [regex]::Match($line, '^(\s*)')
        $currentDepth = $indentMatch.Groups[1].Value.Length / 2
        
        # Remove comments and trim
        $line = $line -replace '#.*$', ''
        $line = $line.Trim()
        
        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        
        # Split into key/value
        if ($line -match '^([^:]+):(.*)$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            
            # Update path
            if ($currentDepth -ge $path.Count) {
                $path += $key
            } else {
                $path[$currentDepth] = $key
                $path = $path[0..$currentDepth]
            }
            
            # We're interested in packages section at depth 2
            if ($path.Count -gt 0 -and $path[0] -eq 'packages' -and $currentDepth -eq 2) {
                # Remove quotes
                $key = $key.Trim("'", '"')
                
                # Extract name and version
                if ($key -match '^(.+)@([^@]+)$') {
                    $name = $matches[1]
                    $version = $matches[2]
                    $output.packages[$name] = @{ version = $version }
                }
            }
        }
    }
    
    return $output | ConvertTo-Json -Depth 10
}

# Check package integrity
function Check-PackageIntegrity {
    param([string]$ScanDir)
    
    Write-ColorOutput "Checking package lock files for integrity issues..." -Color Blue
    
    $lockFiles = Get-ChildItem -Path $ScanDir -Include "package-lock.json","yarn.lock","pnpm-lock.yaml" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($lockFile in $lockFiles) {
        $originalFile = $lockFile.FullName
        $content = Get-Content -Path $lockFile.FullName -Raw -ErrorAction SilentlyContinue
        
        # Transform pnpm-lock.yaml if needed
        if ($lockFile.Name -eq "pnpm-lock.yaml" -and $content) {
            try {
                $content = Transform-PnpmYaml -FilePath $lockFile.FullName
            }
            catch {
                Write-Verbose "Failed to transform pnpm-lock.yaml: $_"
                continue
            }
        }
        
        if ($content) {
            # Check for compromised packages in lockfiles
            foreach ($packageInfo in $script:COMPROMISED_PACKAGES) {
                $parts = $packageInfo -split ':'
                $packageName = $parts[0]
                $maliciousVersion = $parts[1]
                
                if ($content -match [regex]::Escape($packageName)) {
                    if ($content -match [regex]::Escape($maliciousVersion)) {
                        $global:INTEGRITY_ISSUES += "${originalFile}:Compromised package in lockfile: $packageName@$maliciousVersion"
                    }
                }
            }
            
            # Check for suspicious integrity hash patterns (may indicate tampering)
            $integrityPattern = '"integrity"\s*:\s*"sha[0-9]+\-[A-Za-z0-9+/=]+"'
            $suspiciousHashes = ([regex]::Matches($content, $integrityPattern)).Count
            
            # Note: We're counting integrity hashes but not using the count for now
            # This matches the bash script behavior
            
            # Check for recently modified lockfiles with @ctrl packages
            if ($content -match '@ctrl') {
                $fileAge = (Get-Date) - $lockFile.LastWriteTime
                if ($fileAge.TotalDays -lt 30) {
                    $global:INTEGRITY_ISSUES += "${originalFile}:Recently modified lockfile contains @ctrl packages (potential worm activity)"
                }
            }
        }
    }
}

# Check for typosquatting and homoglyph attacks
function Check-Typosquatting {
    param([string]$ScanDir)
    
    # Popular packages commonly targeted for typosquatting
    $popularPackages = @(
        "react", "vue", "angular", "express", "lodash", "axios", "typescript",
        "webpack", "babel", "eslint", "jest", "mocha", "chalk", "debug",
        "commander", "inquirer", "yargs", "request", "moment", "underscore",
        "jquery", "bootstrap", "socket.io", "redis", "mongoose", "passport"
    )
    
    # Get all package.json files
    $packageFiles = Get-ChildItem -Path $ScanDir -Filter "package.json" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($packageFile in $packageFiles) {
        $content = Get-Content -Path $packageFile.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            try {
                $packageData = $content | ConvertFrom-Json
                
                # Check all dependency sections
                $allDeps = @()
                if ($packageData.dependencies) { $allDeps += $packageData.dependencies.PSObject.Properties.Name }
                if ($packageData.devDependencies) { $allDeps += $packageData.devDependencies.PSObject.Properties.Name }
                if ($packageData.peerDependencies) { $allDeps += $packageData.peerDependencies.PSObject.Properties.Name }
                if ($packageData.optionalDependencies) { $allDeps += $packageData.optionalDependencies.PSObject.Properties.Name }
                
                foreach ($packageName in $allDeps) {
                    # Skip empty or invalid package names
                    if ([string]::IsNullOrEmpty($packageName) -or $packageName.Length -lt 2) { continue }
                    
                    # Check for non-ASCII characters (Unicode/homoglyphs)
                    if ($packageName -match '[^\x00-\x7F]') {
                        $global:TYPOSQUATTING_WARNINGS += "$($packageFile.FullName):Potential Unicode/homoglyph characters in package: $packageName"
                    }
                    
                    # Check for confusable character patterns
                    $confusables = @{
                        'rn' = 'm'; 'vv' = 'w'; 'cl' = 'd'; 'ii' = 'i'; 'nn' = 'n'; 'oo' = 'o'
                    }
                    
                    foreach ($pattern in $confusables.Keys) {
                        if ($packageName -match $pattern) {
                            $global:TYPOSQUATTING_WARNINGS += "$($packageFile.FullName):Potential typosquatting pattern '$pattern' in package: $packageName"
                        }
                    }
                    
                    # Check similarity to popular packages
                    foreach ($popular in $popularPackages) {
                        # Skip exact matches
                        if ($packageName -eq $popular) { continue }
                        
                        # Skip common legitimate variations
                        if ($packageName -match '^(test|tests|testing|types|util|utils|core|lib|libs|common|shared)$') { continue }
                        
                        # Check for single character differences (typos)
                        if ($packageName.Length -eq $popular.Length -and $packageName.Length -gt 4) {
                            $diffCount = 0
                            for ($i = 0; $i -lt $packageName.Length; $i++) {
                                if ($packageName[$i] -ne $popular[$i]) {
                                    $diffCount++
                                }
                            }
                            
                            if ($diffCount -eq 1) {
                                # Avoid common legitimate variations with hyphens
                                if (-not ($packageName -match '-' -or $popular -match '-')) {
                                    $global:TYPOSQUATTING_WARNINGS += "$($packageFile.FullName):Potential typosquatting of '$popular': $packageName (1 character difference)"
                                }
                            }
                        }
                        
                        # Check for missing character
                        if ($packageName.Length -eq ($popular.Length - 1)) {
                            for ($i = 0; $i -le $popular.Length; $i++) {
                                if ($i -lt $popular.Length) {
                                    $testName = $popular.Substring(0, $i) + $popular.Substring($i + 1)
                                    if ($packageName -eq $testName) {
                                        $global:TYPOSQUATTING_WARNINGS += "$($packageFile.FullName):Potential typosquatting of '$popular': $packageName (missing character)"
                                        break
                                    }
                                }
                            }
                        }
                        
                        # Check for extra character
                        if ($packageName.Length -eq ($popular.Length + 1)) {
                            for ($i = 0; $i -le $packageName.Length; $i++) {
                                if ($i -lt $packageName.Length) {
                                    $testName = $packageName.Substring(0, $i) + $packageName.Substring($i + 1)
                                    if ($testName -eq $popular) {
                                        $global:TYPOSQUATTING_WARNINGS += "$($packageFile.FullName):Potential typosquatting of '$popular': $packageName (extra character)"
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                # Ignore JSON parsing errors
            }
        }
    }
}

# Check for network exfiltration patterns
function Check-NetworkExfiltration {
    param([string]$ScanDir)
    
    # Suspicious domains and patterns beyond webhook.site
    $suspiciousDomains = @(
        "pastebin.com", "hastebin.com", "ix.io", "0x0.st", "transfer.sh",
        "file.io", "anonfiles.com", "mega.nz", "dropbox.com/s/",
        "discord.com/api/webhooks", "telegram.org", "t.me",
        "ngrok.io", "localtunnel.me", "serveo.net",
        "requestbin.com", "webhook.site", "beeceptor.com",
        "pipedream.com", "zapier.com/hooks"
    )
    
    # IP address patterns
    $ipPattern = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    $ipPortPattern = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{4,5}\b'
    
    $files = Get-ChildItem -Path $ScanDir -Include "*.js","*.ts","*.json" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        # Skip vendor/library files to reduce false positives
        if ($file.FullName -notmatch '\\(vendor|node_modules)\\' -and 
            $file.Name -ne "package-lock.json" -and 
            $file.Name -ne "yarn.lock") {
            
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                # Check for hardcoded IP addresses
                $ipMatches = [regex]::Matches($content, $ipPattern)
                $ipPortMatches = [regex]::Matches($content, $ipPortPattern)
                
                if ($ipMatches.Count -gt 0 -or $ipPortMatches.Count -gt 0) {
                    $uniqueIPs = @()
                    foreach ($match in $ipMatches) {
                        $ip = $match.Value
                        # Skip common safe IPs
                        if ($ip -ne "127.0.0.1" -and $ip -ne "0.0.0.0" -and $ip -notmatch '^255\.') {
                            $uniqueIPs += $ip
                        }
                    }
                    foreach ($match in $ipPortMatches) {
                        $uniqueIPs += $match.Value
                    }
                    
                    if ($uniqueIPs.Count -gt 0) {
                        $ipList = ($uniqueIPs | Select-Object -Unique -First 3) -join ', '
                        if ($file.Name -match '\.min\.js$') {
                            $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Hardcoded IP addresses found (minified file): $ipList"
                        } else {
                            $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Hardcoded IP addresses found: $ipList"
                        }
                    }
                }
                
                # Check for suspicious domains
                foreach ($domain in $suspiciousDomains) {
                    $escapedDomain = [regex]::Escape($domain)
                    # Use word boundaries and URL patterns to avoid false positives
                    $pattern = "https?://[^\s]*$escapedDomain|[\s`"`']$escapedDomain[\s/`"`']"
                    
                    if ($content -match $pattern) {
                        # Get line number and context
                        $lines = $content -split "`n"
                        for ($i = 0; $i -lt $lines.Count; $i++) {
                            if ($lines[$i] -match $pattern -and $lines[$i] -notmatch '^\s*(#|//)') {
                                $lineNum = $i + 1
                                $snippet = $lines[$i].Trim()
                                
                                # Truncate long lines
                                if ($snippet.Length -gt 80) {
                                    $domainIndex = $snippet.IndexOf($domain)
                                    if ($domainIndex -gt 0) {
                                        $start = [Math]::Max(0, $domainIndex - 20)
                                        $length = [Math]::Min(60, $snippet.Length - $start)
                                        $snippet = "..." + $snippet.Substring($start, $length) + "..."
                                    } else {
                                        $snippet = $snippet.Substring(0, 77) + "..."
                                    }
                                }
                                
                                $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Suspicious domain found: $domain at line ${lineNum}: $snippet"
                                break
                            }
                        }
                    }
                }
                
                # Check for base64-encoded URLs
                if ($content -match 'atob\s*\(' -or $content -match 'base64.*decode') {
                    $lines = $content -split "`n"
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        if ($lines[$i] -match 'atob\s*\(' -or $lines[$i] -match 'base64.*decode') {
                            $lineNum = $i + 1
                            $snippet = $lines[$i].Trim()
                            if ($snippet.Length -gt 80) {
                                $snippet = $snippet.Substring(0, 77) + "..."
                            }
                            $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Base64 decoding detected at line ${lineNum}: $snippet"
                            break
                        }
                    }
                }
                
                # Check for DNS-over-HTTPS patterns
                if ($content -match 'dns-query' -or $content -match 'application/dns-message') {
                    $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):DNS-over-HTTPS pattern detected"
                }
                
                # Check for WebSocket connections to external endpoints
                if ($content -match 'ws://' -or $content -match 'wss://') {
                    $wsEndpoints = [regex]::Matches($content, 'wss?://[^"''\s]+')
                    foreach ($match in $wsEndpoints) {
                        $endpoint = $match.Value
                        # Flag WebSocket connections that aren't localhost
                        if ($endpoint -notmatch 'localhost|127\.0\.0\.1') {
                            $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):WebSocket connection to external endpoint: $endpoint"
                        }
                    }
                }
                
                # Check for suspicious HTTP headers
                if ($content -match 'X-Exfiltrate|X-Data-Export|X-Credential') {
                    $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Suspicious HTTP headers detected"
                }
                
                # Check for btoa/atob near network operations
                if ($file.FullName -notmatch '\\(vendor|node_modules)\\' -and $file.Name -notmatch '\.min\.js$') {
                    # Check for btoa (base64 encoding)
                    if ($content -match 'btoa\s*\(') {
                        $lines = $content -split "`n"
                        for ($i = 0; $i -lt $lines.Count; $i++) {
                            if ($lines[$i] -match 'btoa\s*\(') {
                                $lineNum = $i + 1
                                # Check context (3 lines before and after)
                                $contextStart = [Math]::Max(0, $i - 3)
                                $contextEnd = [Math]::Min($lines.Count - 1, $i + 3)
                                $context = $lines[$contextStart..$contextEnd] -join "`n"
                                
                                # Check if near network operations
                                if ($context -match 'fetch|XMLHttpRequest|axios|\$\.ajax|http\.request') {
                                    # Make sure it's not just legitimate auth
                                    if ($context -notmatch 'Authorization:|Basic |Bearer ') {
                                        $snippet = $lines[$i].Trim()
                                        if ($snippet.Length -gt 80) {
                                            $snippet = $snippet.Substring(0, 77) + "..."
                                        }
                                        $global:NETWORK_EXFILTRATION_WARNINGS += "$($file.FullName):Suspicious base64 encoding near network operation at line ${lineNum}: $snippet"
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# Generate report
function Generate-Report {
    param([bool]$ParanoidMode)
    
    Write-Host ""
    Write-ColorOutput "==============================================" -Color Blue
    if ($ParanoidMode) {
        Write-ColorOutput "  SHAI-HULUD + PARANOID SECURITY REPORT" -Color Blue
    }
    else {
        Write-ColorOutput "      SHAI-HULUD DETECTION REPORT" -Color Blue
    }
    Write-ColorOutput "==============================================" -Color Blue
    Write-Host ""
    
    $highRisk = 0
    $mediumRisk = 0
    
    # Report findings by category
    if ($global:WORKFLOW_FILES.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Malicious workflow files detected:" -Color Red
        foreach ($file in $global:WORKFLOW_FILES) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: Known malicious workflow filename"
            $highRisk++
        }
        Write-Host ""
    }
    
    if ($global:MALICIOUS_HASHES.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Files with known malicious hashes:" -Color Red
        foreach ($entry in $global:MALICIOUS_HASHES) {
            $parts = $entry -split ':'
            Write-Host "   - $($parts[0])"
            Write-Host "     Hash: $($parts[1])"
            Show-FilePreview -FilePath $parts[0] -Context "HIGH RISK: File matches known malicious SHA-256 hash"
            $highRisk++
        }
        Write-Host ""
    }
    
    if ($global:COMPROMISED_FOUND.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Compromised package versions detected:" -Color Red
        foreach ($entry in $global:COMPROMISED_FOUND) {
            $parts = $entry -split ':', 2
            Write-Host "   - Package: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            Show-FilePreview -FilePath $parts[0] -Context "HIGH RISK: Contains compromised package version: $($parts[1])"
            $highRisk++
        }
        Write-ColorOutput "   NOTE: These specific package versions are known to be compromised." -Color Yellow
        Write-ColorOutput "   You should immediately update or remove these packages." -Color Yellow
        Write-Host ""
    }
    
    if ($global:SUSPICIOUS_CONTENT.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Suspicious content patterns:" -Color Yellow
        foreach ($entry in $global:SUSPICIOUS_CONTENT) {
            $parts = $entry -split ':', 2
            Write-Host "   - Pattern: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            $mediumRisk++
        }
        Write-Host ""
    }
    
    # Categorize crypto patterns
    $cryptoHigh = @()
    $cryptoMedium = @()
    foreach ($entry in $global:CRYPTO_PATTERNS) {
        if ($entry -match 'HIGH RISK|Known attacker wallet|XMLHttpRequest prototype') {
            $cryptoHigh += $entry
        }
        else {
            $cryptoMedium += $entry
        }
    }
    
    if ($cryptoHigh.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Cryptocurrency theft patterns detected:" -Color Red
        foreach ($entry in $cryptoHigh) {
            $parts = $entry -split ':', 2
            if ($parts.Count -eq 2) {
                Write-Host "   - Pattern: $($parts[1])"
                Write-Host "     Found in: $($parts[0])"
                Show-FilePreview -FilePath $parts[0] -Context "HIGH RISK: Cryptocurrency theft pattern: $($parts[1])"
            } else {
                Write-Host "   - $entry"
            }
            $highRisk++
        }
        Write-Host ""
    }
    
    if ($cryptoMedium.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Potential cryptocurrency manipulation patterns:" -Color Yellow
        foreach ($entry in $cryptoMedium) {
            Write-Host "   - $entry"
            $mediumRisk++
        }
        Write-Host ""
    }
    
    if ($global:GIT_BRANCHES.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Suspicious git branches:" -Color Yellow
        foreach ($entry in $global:GIT_BRANCHES) {
            $parts = $entry -split ':', 2
            Write-Host "   - Repository: $($parts[0])"
            Write-Host "     $($parts[1])"
            Write-Host "     Git Investigation Commands:" -ForegroundColor Blue
            Write-Host "       cd '$($parts[0])'" -ForegroundColor Cyan
            Write-Host "       git log --oneline -10 shai-hulud" -ForegroundColor Cyan
            Write-Host "       git show shai-hulud" -ForegroundColor Cyan
            Write-Host "       git diff main...shai-hulud" -ForegroundColor Cyan
            Write-Host ""
            $mediumRisk++
        }
        Write-ColorOutput "   NOTE: 'shai-hulud' branches may indicate compromise." -Color Yellow
        Write-ColorOutput "   Use the commands above to investigate each branch." -Color Yellow
        Write-Host ""
    }
    
    if ($global:POSTINSTALL_HOOKS.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Suspicious postinstall hooks detected:" -Color Red
        foreach ($entry in $global:POSTINSTALL_HOOKS) {
            $parts = $entry -split ':', 2
            Write-Host "   - Hook: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            Show-FilePreview -FilePath $parts[0] -Context "HIGH RISK: Suspicious postinstall hook: $($parts[1])"
            $highRisk++
        }
        Write-Host ""
    }
    
    # Categorize Trufflehog findings
    $trufflehogHigh = @()
    $trufflehogMedium = @()
    $trufflehogLow = @()
    
    foreach ($entry in $global:TRUFFLEHOG_ACTIVITY) {
        $parts = $entry -split ':', 3
        if ($parts.Count -ge 3) {
            $riskLevel = $parts[1]
            
            switch ($riskLevel) {
                "HIGH" { $trufflehogHigh += "$($parts[0]):$($parts[2])" }
                "MEDIUM" { $trufflehogMedium += "$($parts[0]):$($parts[2])" }
                "LOW" { $trufflehogLow += "$($parts[0]):$($parts[2])" }
            }
        }
    }
    
    if ($trufflehogHigh.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Trufflehog/secret scanning activity detected:" -Color Red
        foreach ($entry in $trufflehogHigh) {
            $parts = $entry -split ':', 2
            Write-Host "   - Activity: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            Show-FilePreview -FilePath $parts[0] -Context "HIGH RISK: $($parts[1])"
            $highRisk++
        }
        Write-Host ""
    }
    
    if ($trufflehogMedium.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Potentially suspicious secret scanning patterns:" -Color Yellow
        foreach ($entry in $trufflehogMedium) {
            $parts = $entry -split ':', 2
            Write-Host "   - Pattern: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            $mediumRisk++
        }
        Write-Host ""
    }
    
    foreach ($entry in $trufflehogLow) {
        $global:LOW_RISK_FINDINGS += "Trufflehog pattern: $entry"
    }
    
    if ($global:SHAI_HULUD_REPOS.Count -gt 0) {
        Write-ColorOutput "HIGH RISK: Shai-Hulud repositories detected:" -Color Red
        foreach ($entry in $global:SHAI_HULUD_REPOS) {
            $parts = $entry -split ':', 2
            Write-Host "   - Repository: $($parts[0])"
            Write-Host "     $($parts[1])"
            $highRisk++
        }
        Write-Host ""
    }
    
    if ($global:NAMESPACE_WARNINGS.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Packages from compromised namespaces:" -Color Yellow
        foreach ($entry in $global:NAMESPACE_WARNINGS) {
            $parts = $entry -split ':', 2
            Write-Host "   - Warning: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            $mediumRisk++
        }
        Write-Host ""
    }
    
    if ($global:INTEGRITY_ISSUES.Count -gt 0) {
        Write-ColorOutput "MEDIUM RISK: Package integrity issues detected:" -Color Yellow
        foreach ($entry in $global:INTEGRITY_ISSUES) {
            $parts = $entry -split ':', 2
            Write-Host "   - Issue: $($parts[1])"
            Write-Host "     Found in: $($parts[0])"
            $mediumRisk++
        }
        Write-Host ""
    }
    
    # Paranoid mode findings
    if ($ParanoidMode) {
        if ($global:TYPOSQUATTING_WARNINGS.Count -gt 0) {
            Write-ColorOutput "MEDIUM RISK (PARANOID): Potential typosquatting detected:" -Color Yellow
            $shown = 0
            foreach ($entry in $global:TYPOSQUATTING_WARNINGS) {
                if ($shown -ge 5) { break }
                $parts = $entry -split ':', 2
                Write-Host "   - Warning: $($parts[1])"
                Write-Host "     Found in: $($parts[0])"
                $mediumRisk++
                $shown++
            }
            if ($global:TYPOSQUATTING_WARNINGS.Count -gt 5) {
                Write-Host "   - ... and $($global:TYPOSQUATTING_WARNINGS.Count - 5) more typosquatting warnings (truncated for brevity)"
            }
            Write-Host ""
        }
        
        if ($global:NETWORK_EXFILTRATION_WARNINGS.Count -gt 0) {
            Write-ColorOutput "MEDIUM RISK (PARANOID): Network exfiltration patterns detected:" -Color Yellow
            $shown = 0
            foreach ($entry in $global:NETWORK_EXFILTRATION_WARNINGS) {
                if ($shown -ge 5) { break }
                $parts = $entry -split ':', 2
                Write-Host "   - Warning: $($parts[1])"
                Write-Host "     Found in: $($parts[0])"
                $mediumRisk++
                $shown++
            }
            if ($global:NETWORK_EXFILTRATION_WARNINGS.Count -gt 5) {
                Write-Host "   - ... and $($global:NETWORK_EXFILTRATION_WARNINGS.Count - 5) more network warnings (truncated for brevity)"
            }
            Write-Host ""
        }
    }
    
    # Summary
    $totalIssues = $highRisk + $mediumRisk
    $lowRiskCount = $global:LOW_RISK_FINDINGS.Count
    
    Write-ColorOutput "==============================================" -Color Blue
    if ($totalIssues -eq 0) {
        Write-ColorOutput "No indicators of Shai-Hulud compromise detected." -Color Green
        Write-ColorOutput "Your system appears clean from this specific attack." -Color Green
        
        if ($lowRiskCount -gt 0) {
            Write-Host ""
            Write-ColorOutput "LOW RISK FINDINGS (informational only):" -Color Blue
            foreach ($finding in $global:LOW_RISK_FINDINGS) {
                Write-Host "   - $finding"
            }
            Write-ColorOutput "   NOTE: These are likely legitimate framework code or dependencies." -Color Blue
        }
    }
    else {
        Write-ColorOutput "SUMMARY:" -Color Red
        Write-ColorOutput "   High Risk Issues: $highRisk" -Color Red
        Write-ColorOutput "   Medium Risk Issues: $mediumRisk" -Color Yellow
        if ($lowRiskCount -gt 0) {
            Write-ColorOutput "   Low Risk (informational): $lowRiskCount" -Color Blue
        }
        Write-ColorOutput "   Total Critical Issues: $totalIssues" -Color Blue
        Write-Host ""
        Write-ColorOutput "IMPORTANT:" -Color Yellow
        Write-ColorOutput "   - High risk issues likely indicate actual compromise" -Color Yellow
        Write-ColorOutput "   - Medium risk issues require manual investigation" -Color Yellow
        Write-ColorOutput "   - Low risk issues are likely false positives from legitimate code" -Color Yellow
        if ($ParanoidMode) {
            Write-ColorOutput "   - Issues marked (PARANOID) are general security checks, not Shai-Hulud specific" -Color Yellow
        }
        Write-ColorOutput "   - Consider running additional security scans" -Color Yellow
        Write-ColorOutput "   - Review your npm audit logs and package history" -Color Yellow
    }
    Write-ColorOutput "==============================================" -Color Blue
}

# Main execution
Write-ColorOutput "Starting Shai-Hulud detection scan..." -Color Green
if ($Paranoid) {
    Write-ColorOutput "Scanning directory: $ScanPath (with paranoid mode enabled)" -Color Blue
}
else {
    Write-ColorOutput "Scanning directory: $ScanPath" -Color Blue
}
Write-Host ""

# Load compromised packages
Load-CompromisedPackages

# Run core detection checks
Check-WorkflowFiles -ScanDir $ScanPath
Check-FileHashes -ScanDir $ScanPath
Check-Packages -ScanDir $ScanPath
Check-PostinstallHooks -ScanDir $ScanPath
Check-Content -ScanDir $ScanPath
Check-CryptoTheftPatterns -ScanDir $ScanPath
Check-TrufflehogActivity -ScanDir $ScanPath
Check-GitBranches -ScanDir $ScanPath
Check-ShaiHuludRepos -ScanDir $ScanPath
Check-PackageIntegrity -ScanDir $ScanPath

# Run additional checks in paranoid mode
if ($Paranoid) {
    Write-ColorOutput "Checking for typosquatting and homoglyph attacks..." -Color Blue
    Check-Typosquatting -ScanDir $ScanPath
    Write-ColorOutput "Checking for network exfiltration patterns..." -Color Blue
    Check-NetworkExfiltration -ScanDir $ScanPath
}

# Generate report
Generate-Report -ParanoidMode $Paranoid
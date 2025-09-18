@echo off
setlocal enabledelayedexpansion

:: Shai-Hulud NPM Supply Chain Attack Detection Script
:: Detects indicators of compromise from the September 2025 npm attack
:: Usage: shai-hulud-detector.bat [--paranoid] <directory_to_scan>

:: Known malicious file hash
set "MALICIOUS_HASH=46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

:: Initialize arrays as environment variables
set /a WORKFLOW_FILES_COUNT=0
set /a MALICIOUS_HASHES_COUNT=0
set /a COMPROMISED_FOUND_COUNT=0
set /a SUSPICIOUS_CONTENT_COUNT=0
set /a GIT_BRANCHES_COUNT=0
set /a POSTINSTALL_HOOKS_COUNT=0
set /a TRUFFLEHOG_ACTIVITY_COUNT=0
set /a SHAI_HULUD_REPOS_COUNT=0
set /a NAMESPACE_WARNINGS_COUNT=0
set /a LOW_RISK_FINDINGS_COUNT=0
set /a INTEGRITY_ISSUES_COUNT=0
set /a TYPOSQUATTING_WARNINGS_COUNT=0
set /a NETWORK_EXFILTRATION_WARNINGS_COUNT=0

:: Initialize variables
set "PARANOID_MODE=false"
set "FULL_SCAN=false"
set "SCAN_DIR="

:: Parse command line arguments
:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="--paranoid" (
    set "PARANOID_MODE=true"
    shift
    goto parse_args
)
if "%~1"=="--full-scan" (
    set "FULL_SCAN=true"
    shift
    goto parse_args
)
if "%~1"=="--help" goto usage
if "%~1"=="-h" goto usage
if "%~1:~0,1%"=="-" (
    echo Unknown option: %~1
    goto usage
)
if "!SCAN_DIR!"=="" (
    set "SCAN_DIR=%~1"
    shift
    goto parse_args
) else (
    echo Too many arguments
    goto usage
)

:end_parse

:: Set up scan directories
set "TEMP_DIRS_FILE=%TEMP%\shai_hulud_dirs_%RANDOM%.txt"

if "!SCAN_DIR!"=="" (
    :: Auto-discover project directories
    call :discover_project_directories
) else (
    if not exist "!SCAN_DIR!" (
        call :print_red "Error: Directory '!SCAN_DIR!' does not exist."
        exit /b 1
    )
    :: Convert to absolute path and save to temp file
    for %%i in ("!SCAN_DIR!") do echo %%~fi > "!TEMP_DIRS_FILE!"
)

echo.
call :print_blue "=============================================="
call :print_blue "    SHAI-HULUD ATTACK DETECTION TOOL"
call :print_blue "=============================================="
echo.

:: Load compromised packages
call :load_compromised_packages
echo.

:: Count directories to scan
set /a DIRS_TO_SCAN=0
if exist "!TEMP_DIRS_FILE!" (
    for /f %%l in ('type "!TEMP_DIRS_FILE!" 2^>nul ^| find /c /v ""') do set /a DIRS_TO_SCAN=%%l
)

call :print_green "[*] Starting Shai-Hulud detection scan..."
call :print_blue "[+] Scanning !DIRS_TO_SCAN! directories"
if "!PARANOID_MODE!"=="true" (
    call :print_yellow "[!] Paranoid mode enabled - includes additional security checks beyond core Shai-Hulud detection"
    echo    Additional checks: typosquatting detection, network exfiltration patterns
) else (
    echo    Running core Shai-Hulud detection checks only
)
echo    Analyzing JavaScript, TypeScript, JSON files and package configurations...
echo.

:: Scan each discovered directory
if exist "!TEMP_DIRS_FILE!" (
    for /f "delims=" %%d in ('type "!TEMP_DIRS_FILE!"') do (
        call :print_green "[*] Scanning: %%d"
        echo ----------------------------------------

        :: Run core Shai-Hulud detection checks
        call :check_workflow_files "%%d"
        call :check_file_hashes "%%d"
        call :check_packages "%%d"
        call :check_postinstall_hooks "%%d"
        call :check_content "%%d"
        call :check_trufflehog_activity "%%d"
        call :check_git_branches "%%d"
        call :check_shai_hulud_repos "%%d"
        call :check_package_integrity "%%d"

        :: Run additional security checks only in paranoid mode
        if "!PARANOID_MODE!"=="true" (
            echo.
            call :print_blue "[-]+ Checking for typosquatting and homoglyph attacks..."
            call :check_typosquatting "%%d"
            call :print_blue "[-]+ Checking for network exfiltration patterns..."
            call :check_network_exfiltration "%%d"
        )

        echo.
    )
)

:: Clean up temp file
if exist "!TEMP_DIRS_FILE!" del "!TEMP_DIRS_FILE!"

call :print_green "[*] Scanning completed! Generating report..."
echo.

:: Generate report
call :generate_report "!PARANOID_MODE!"
goto :eof

:usage
echo Usage: %0 [--paranoid] [--full-scan] [directory_to_scan]
echo.
echo OPTIONS:
echo   --paranoid    Enable additional security checks (typosquatting, network patterns)
echo                 These are general security features, not specific to Shai-Hulud
echo   --full-scan   Include cache directories (.cache, node_modules\.cache, etc.) in auto-discovery
echo                 By default, cache directories are excluded for performance
echo.
echo ARGUMENTS:
echo   directory_to_scan    Directory to scan (optional, defaults to auto-discovery from home)
echo.
echo EXAMPLES:
echo   %0                                          # Auto-discover and scan all projects from home
echo   %0 --full-scan                              # Auto-discover including cache directories
echo   %0 C:\path\to\your\project                  # Core Shai-Hulud detection on specific directory
echo   %0 --paranoid                               # Auto-discover with advanced security checks
echo   %0 --paranoid --full-scan                   # Full scan with advanced security checks
echo   %0 --paranoid C:\path\to\your\project       # Core + advanced security checks on specific directory
exit /b 1

:: Auto-discover project directories from home directory
:discover_project_directories
if "!FULL_SCAN!"=="true" (
    call :print_blue "[*] Auto-discovering project directories from %USERPROFILE% (full scan including cache directories)..."
) else (
    call :print_blue "[*] Auto-discovering project directories from %USERPROFILE% (excluding cache directories)..."
)

:: Create temporary file to store discovered directories
set "TEMP_DIRS_FILE=%TEMP%\shai_hulud_dirs_%RANDOM%.txt"
if exist "!TEMP_DIRS_FILE!" del "!TEMP_DIRS_FILE!"

:: Common project indicators
set "PROJECT_INDICATORS=package.json package-lock.json yarn.lock node_modules .git Cargo.toml requirements.txt pom.xml build.gradle composer.json Gemfile go.mod"

:: Search for common project files and get their directories
for /f "delims=" %%f in ('dir /s /b "%USERPROFILE%\package.json" 2^>nul') do (
    call :filter_cache_dirs "%%f" "%%~dpf"
)
for /f "delims=" %%f in ('dir /s /b "%USERPROFILE%\.git" 2^>nul') do (
    call :filter_cache_dirs "%%f" "%%~dpf"
)
for /f "delims=" %%f in ('dir /s /b "%USERPROFILE%\requirements.txt" 2^>nul') do (
    call :filter_cache_dirs "%%f" "%%~dpf"
)

:: Remove duplicates and create final list
if exist "!TEMP_DIRS_FILE!" (
    sort "!TEMP_DIRS_FILE!" | findstr /v "^$" > "!TEMP_DIRS_FILE!.sorted"
    if exist "!TEMP_DIRS_FILE!.sorted" (
        move "!TEMP_DIRS_FILE!.sorted" "!TEMP_DIRS_FILE!" >nul
    )
)

:: Count discovered directories
set /a DISCOVERED_COUNT=0
if exist "!TEMP_DIRS_FILE!" (
    for /f %%l in ('type "!TEMP_DIRS_FILE!" 2^>nul ^| find /c /v ""') do set /a DISCOVERED_COUNT=%%l
)

if !DISCOVERED_COUNT! equ 0 (
    call :print_yellow "[!] No project directories found in %USERPROFILE%"
    call :print_blue "    Falling back to scanning home directory directly"
    echo %USERPROFILE% > "!TEMP_DIRS_FILE!"
    set /a DISCOVERED_COUNT=1
) else (
    call :print_green "[+] Found !DISCOVERED_COUNT! project directories"
    if exist "!TEMP_DIRS_FILE!" (
        for /f "delims=" %%d in (type "!TEMP_DIRS_FILE!") do (
            echo    [*] %%d
        )
    )
)

goto :eof

:: Filter cache directories based on FULL_SCAN setting
:filter_cache_dirs
set "file_path=%~1"
set "dir_path=%~2"

:: Always skip AppData
echo %file_path% | findstr /i "AppData" >nul && goto :eof

:: If FULL_SCAN is true, include everything (except AppData)
if "!FULL_SCAN!"=="true" (
    echo %dir_path% >> "!TEMP_DIRS_FILE!"
    goto :eof
)

:: Skip cache directories if not doing full scan
echo %file_path% | findstr /i "\.cache" >nul && goto :eof
echo %file_path% | findstr /i "node_modules\\\.cache" >nul && goto :eof
echo %file_path% | findstr /i "\.npm" >nul && goto :eof
echo %file_path% | findstr /i "\.yarn" >nul && goto :eof
echo %file_path% | findstr /i "__pycache__" >nul && goto :eof
echo %file_path% | findstr /i "\\venv\\" >nul && goto :eof
echo %file_path% | findstr /i "\.venv" >nul && goto :eof
echo %file_path% | findstr /i "\\target\\" >nul && goto :eof
echo %file_path% | findstr /i "\\build\\" >nul && goto :eof
echo %file_path% | findstr /i "\\dist\\" >nul && goto :eof
echo %file_path% | findstr /i "Temp" >nul && goto :eof

:: If not filtered out, add to temp file
echo %dir_path% >> "!TEMP_DIRS_FILE!"
goto :eof

:print_green
echo %~1
goto :eof

:print_red
echo %~1
goto :eof

:print_yellow
echo %~1
goto :eof

:print_blue
echo %~1
goto :eof

:load_compromised_packages
set "script_dir=%~dp0"
set "packages_file=%script_dir%compromised-packages.txt"

set /a COMPROMISED_PACKAGES_COUNT=0

if exist "!packages_file!" (
    for /f "usebackq delims=" %%a in ("!packages_file!") do (
        set "line=%%a"
        :: Skip comments and empty lines
        if not "!line:~0,1!"=="#" if not "!line!"=="" (
            :: Check if line matches package:version pattern
            echo !line! | findstr /r "^[a-zA-Z@][^:]*:[0-9]*\.[0-9]*\.[0-9]*" >nul
            if not errorlevel 1 (
                set /a COMPROMISED_PACKAGES_COUNT+=1
                set "COMPROMISED_PACKAGES[!COMPROMISED_PACKAGES_COUNT!]=!line!"
            )
        )
    )
    call :print_blue "[+] Loaded !COMPROMISED_PACKAGES_COUNT! compromised packages from !packages_file!"
    echo    Package database contains known malicious versions from Shai-Hulud attack
) else (
    call :print_yellow "[!]  Warning: !packages_file! not found, using embedded package list"
    :: Fallback to embedded list
    set /a COMPROMISED_PACKAGES_COUNT=7
    set "COMPROMISED_PACKAGES[1]=@ctrl/tinycolor:4.1.0"
    set "COMPROMISED_PACKAGES[2]=@ctrl/tinycolor:4.1.1"
    set "COMPROMISED_PACKAGES[3]=@ctrl/tinycolor:4.1.2"
    set "COMPROMISED_PACKAGES[4]=@ctrl/deluge:1.2.0"
    set "COMPROMISED_PACKAGES[5]=angulartics2:14.1.2"
    set "COMPROMISED_PACKAGES[6]=koa2-swagger-ui:5.11.1"
    set "COMPROMISED_PACKAGES[7]=koa2-swagger-ui:5.11.2"
)
goto :eof

:check_workflow_files
set "scan_dir=%~1"
call :print_blue "[-] Checking for malicious workflow files..."
echo    Searching for shai-hulud-workflow.yml files in directory tree...

set /a temp_count=0
for /r "!scan_dir!" %%f in (shai-hulud-workflow.yml) do (
    if exist "%%f" (
        set /a WORKFLOW_FILES_COUNT+=1
        set /a temp_count+=1
        set "WORKFLOW_FILES[!WORKFLOW_FILES_COUNT!]=%%f"
    )
)

if !temp_count! gtr 0 (
    call :print_yellow "   [FOUND] !temp_count! suspicious workflow file(s) detected!"
    echo    These files are known indicators of Shai-Hulud compromise
) else (
    call :print_green "   [OK] No malicious workflow files detected"
)
goto :eof

:check_file_hashes
set "scan_dir=%~1"
call :print_blue "[-] Checking file hashes for known malicious content..."
echo    Computing SHA-256 hashes for .js, .ts, .json files...
echo    Comparing against known malicious hash: !MALICIOUS_HASH!

set /a files_scanned=0
set /a initial_hash_count=!MALICIOUS_HASHES_COUNT!
for /r "!scan_dir!" %%f in (*.js *.ts *.json) do (
    if exist "%%f" (
        set /a files_scanned+=1
        if !files_scanned! lss 50 (
            set /a progress=!files_scanned!/10
            if !progress! gtr 0 (
                if !progress! equ 1 echo    Progress: Scanning files... (!files_scanned! processed^)
                if !progress! equ 2 echo    Progress: Scanning files... (!files_scanned! processed^)
            )
        )
        for /f "delims=" %%h in ('certutil -hashfile "%%f" SHA256 ^| findstr /v "SHA256" ^| findstr /v "CertUtil"') do (
            set "file_hash=%%h"
            set "file_hash=!file_hash: =!"
            if /i "!file_hash!"=="!MALICIOUS_HASH!" (
                set /a MALICIOUS_HASHES_COUNT+=1
                set "MALICIOUS_HASHES[!MALICIOUS_HASHES_COUNT!]=%%f:!file_hash!"
            )
        )
    )
)

set /a hash_matches=!MALICIOUS_HASHES_COUNT!-!initial_hash_count!
if !hash_matches! gtr 0 (
    call :print_red "   [CRITICAL] Found !hash_matches! file(s) with known malicious hashes!"
    echo    These files contain known Shai-Hulud malware code
) else (
    call :print_green "   [OK] No malicious file hashes detected"
    echo    Scanned !files_scanned! files - all hashes are clean
)
goto :eof

:check_packages
set "scan_dir=%~1"
call :print_blue "[-] Checking package.json files for compromised packages..."
echo    Searching for package.json files and analyzing dependencies...
echo    Checking against !COMPROMISED_PACKAGES_COUNT! known malicious package versions

for /r "!scan_dir!" %%f in (package.json) do (
    if exist "%%f" (
        :: Check for specific compromised packages
        for /l %%i in (1,1,!COMPROMISED_PACKAGES_COUNT!) do (
            set "package_info=!COMPROMISED_PACKAGES[%%i]!"
            for /f "tokens=1,2 delims=:" %%a in ("!package_info!") do (
                set "package_name=%%a"
                set "malicious_version=%%b"
                
                findstr /c:"\"!package_name!\"" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    for /f "delims=" %%v in ('findstr /a "\"!package_name!\"" "%%f" ^| findstr /o "\"[0-9]*\.[0-9]*\.[0-9]*\""') do (
                        set "found_version=%%v"
                        set "found_version=!found_version:~1,-1!"
                        if "!found_version!"=="!malicious_version!" (
                            set /a COMPROMISED_FOUND_COUNT+=1
                            set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=%%f:!package_name!@!malicious_version!"
                        )
                    )
                )
            )
        )
        
        :: Check for suspicious namespaces (simplified)
        findstr /c:"@ctrl/" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a NAMESPACE_WARNINGS_COUNT+=1
            set "NAMESPACE_WARNINGS[!NAMESPACE_WARNINGS_COUNT!]=%%f:Contains packages from compromised namespace: @ctrl"
        )
        
        findstr /c:"@crowdstrike/" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a NAMESPACE_WARNINGS_COUNT+=1
            set "NAMESPACE_WARNINGS[!NAMESPACE_WARNINGS_COUNT!]=%%f:Contains packages from compromised namespace: @crowdstrike"
        )
    )
)

set /a total_package_issues=!COMPROMISED_FOUND_COUNT!+!NAMESPACE_WARNINGS_COUNT!
if !total_package_issues! gtr 0 (
    call :print_yellow "   [FOUND] !total_package_issues! package-related issue(s) detected!"
    if !COMPROMISED_FOUND_COUNT! gtr 0 echo    - !COMPROMISED_FOUND_COUNT! exact compromised package version(s^) found
    if !NAMESPACE_WARNINGS_COUNT! gtr 0 echo    - !NAMESPACE_WARNINGS_COUNT! package(s^) from compromised namespaces
) else (
    call :print_green "   [OK] No compromised packages detected"
    echo    All package dependencies appear clean
)
goto :eof

:check_postinstall_hooks
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious postinstall hooks..."
echo    Analyzing package.json files for dangerous install scripts...

for /r "!scan_dir!" %%f in (package.json) do (
    if exist "%%f" (
        findstr /c:"\"postinstall\"" "%%f" >nul 2>&1
        if not errorlevel 1 (
            for /f "delims=" %%l in ('findstr /c:"\"postinstall\"" "%%f"') do (
                set "line=%%l"
                echo !line! | findstr /i "curl wget \"node -e\" eval" >nul 2>&1
                if not errorlevel 1 (
                    set /a POSTINSTALL_HOOKS_COUNT+=1
                    set "POSTINSTALL_HOOKS[!POSTINSTALL_HOOKS_COUNT!]=%%f:Suspicious postinstall found"
                )
            )
        )
    )
)

if !POSTINSTALL_HOOKS_COUNT! gtr 0 (
    call :print_red "   [!] Found !POSTINSTALL_HOOKS_COUNT! suspicious postinstall hook(s)"
) else (
    call :print_green "   [OK] No suspicious postinstall hooks detected"
)
goto :eof

:check_content
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious content patterns..."

for /r "!scan_dir!" %%f in (*.js *.ts *.json *.yml *.yaml) do (
    if exist "%%f" (
        findstr /c:"webhook.site" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a SUSPICIOUS_CONTENT_COUNT+=1
            set "SUSPICIOUS_CONTENT[!SUSPICIOUS_CONTENT_COUNT!]=%%f:webhook.site reference"
        )
        
        findstr /c:"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a SUSPICIOUS_CONTENT_COUNT+=1
            set "SUSPICIOUS_CONTENT[!SUSPICIOUS_CONTENT_COUNT!]=%%f:malicious webhook endpoint"
        )
    )
)

if !SUSPICIOUS_CONTENT_COUNT! gtr 0 (
    call :print_yellow "   Found !SUSPICIOUS_CONTENT_COUNT! suspicious content pattern(s)"
) else (
    call :print_green "   [OK] No suspicious content patterns detected"
)
goto :eof

:check_trufflehog_activity
set "scan_dir=%~1"
call :print_blue "[-] Checking for Trufflehog activity and secret scanning..."

:: Look for trufflehog binary files
for /r "!scan_dir!" %%f in (*trufflehog*) do (
    if exist "%%f" (
        set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
        set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Trufflehog binary found"
    )
)

:: Look for trufflehog references in files
for /r "!scan_dir!" %%f in (*.js *.py *.sh *.json) do (
    if exist "%%f" (
        findstr /i "trufflehog" "%%f" >nul 2>&1
        if not errorlevel 1 (
            echo %%f | findstr /i "node_modules" >nul 2>&1
            if not errorlevel 1 (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Contains trufflehog references in node_modules"
            ) else (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Contains trufflehog references in source code"
            )
        )
        
        findstr /i "AWS_ACCESS_KEY GITHUB_TOKEN NPM_TOKEN" "%%f" >nul 2>&1
        if not errorlevel 1 (
            echo %%f | findstr /i "node_modules" >nul 2>&1
            if not errorlevel 1 (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Credential patterns in node_modules"
            ) else (
                findstr /i "webhook.site curl https.request" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Credential patterns with potential exfiltration"
                ) else (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Contains credential scanning patterns"
                )
            )
        )
    )
)
goto :eof

:check_git_branches
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious git branches..."

for /r "!scan_dir!" %%d in (.git) do (
    if exist "%%d\refs\heads" (
        for /r "%%d\refs\heads" %%b in (*shai-hulud*) do (
            if exist "%%b" (
                set /a GIT_BRANCHES_COUNT+=1
                for %%p in ("%%d\..") do set "repo_dir=%%~fp"
                for %%n in ("%%b") do set "branch_name=%%~nxn"
                set "GIT_BRANCHES[!GIT_BRANCHES_COUNT!]=!repo_dir!:Branch '!branch_name!' found"
            )
        )
    )
)
goto :eof

:check_shai_hulud_repos
set "scan_dir=%~1"
call :print_blue "[-] Checking for Shai-Hulud repositories and migration patterns..."

for /r "!scan_dir!" %%d in (.git) do (
    for %%p in ("%%d\..") do set "repo_dir=%%~fp"
    for %%n in ("!repo_dir!") do set "repo_name=%%~nxn"
    
    echo !repo_name! | findstr /i "shai-hulud" >nul 2>&1
    if not errorlevel 1 (
        set /a SHAI_HULUD_REPOS_COUNT+=1
        set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Repository name contains 'Shai-Hulud'"
    )
    
    echo !repo_name! | findstr /i "migration" >nul 2>&1
    if not errorlevel 1 (
        set /a SHAI_HULUD_REPOS_COUNT+=1
        set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Repository name contains migration pattern"
    )
    
    if exist "%%d\config" (
        findstr /i "shai-hulud" "%%d\config" >nul 2>&1
        if not errorlevel 1 (
            set /a SHAI_HULUD_REPOS_COUNT+=1
            set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Git remote contains 'Shai-Hulud'"
        )
    )
    
    if exist "!repo_dir!\data.json" (
        findstr /c:"eyJ" "!repo_dir!\data.json" >nul 2>&1
        if not errorlevel 1 (
            set /a SHAI_HULUD_REPOS_COUNT+=1
            set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Contains suspicious data.json (possible base64-encoded credentials)"
        )
    )
)
goto :eof

:check_package_integrity
set "scan_dir=%~1"
call :print_blue "[-] Checking package lock files for integrity issues..."

for /r "!scan_dir!" %%f in (package-lock.json yarn.lock) do (
    if exist "%%f" (
        :: Check for compromised packages in lockfiles
        for /l %%i in (1,1,!COMPROMISED_PACKAGES_COUNT!) do (
            set "package_info=!COMPROMISED_PACKAGES[%%i]!"
            for /f "tokens=1,2 delims=:" %%a in ("!package_info!") do (
                set "package_name=%%a"
                set "malicious_version=%%b"
                
                findstr /c:"\"!package_name!\"" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    findstr /c:"\"!malicious_version!\"" "%%f" >nul 2>&1
                    if not errorlevel 1 (
                        set /a INTEGRITY_ISSUES_COUNT+=1
                        set "INTEGRITY_ISSUES[!INTEGRITY_ISSUES_COUNT!]=%%f:Compromised package in lockfile: !package_name!@!malicious_version!"
                    )
                )
            )
        )
        
        :: Check for @ctrl packages in recently modified lockfiles
        findstr /c:"@ctrl" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a INTEGRITY_ISSUES_COUNT+=1
            set "INTEGRITY_ISSUES[!INTEGRITY_ISSUES_COUNT!]=%%f:Lockfile contains @ctrl packages (potential worm activity)"
        )
    )
)

if !INTEGRITY_ISSUES_COUNT! gtr 0 (
    call :print_yellow "   Found !INTEGRITY_ISSUES_COUNT! package integrity issue(s)"
) else (
    call :print_green "   [OK] No package integrity issues detected"
)
goto :eof

:check_typosquatting
set "scan_dir=%~1"

:: Popular packages commonly targeted for typosquatting
set "popular_packages=react vue angular express lodash axios typescript webpack babel eslint jest mocha chalk debug commander inquirer yargs request moment underscore jquery bootstrap socket.io redis mongoose passport"

echo    Analyzing package names for typosquatting patterns...
echo    Checking against popular packages for character variations...

set /a packages_checked=0
for /r "!scan_dir!" %%f in (package.json) do (
    if exist "%%f" (
        set /a packages_checked+=1
        echo    Scanning: %%~nxf
        
        :: Process the package.json file line by line
        set "in_deps=0"
        for /f "usebackq delims=" %%l in ("%%f") do (
            set "line=%%l"
            
            :: Check if we're entering a dependencies section
            echo !line! | findstr /i "dependencies.*:" >nul 2>&1
            if not errorlevel 1 set "in_deps=1"
            
            :: If we're in dependencies section and line contains a package name
            if "!in_deps!"=="1" (
                echo !line! | findstr /r "\".*\":.*\"" >nul 2>&1
                if not errorlevel 1 (
                    :: Extract package name (everything between first quotes)
                    for /f "tokens=1,2 delims=:" %%a in ("!line!") do (
                        set "raw_name=%%a"
                        :: Remove leading spaces and quotes
                        set "pkg_name=!raw_name!"
                        for /l %%i in (1,1,10) do if "!pkg_name:~0,1!"==" " set "pkg_name=!pkg_name:~1!"
                        for /l %%i in (1,1,10) do if "!pkg_name:~0,1!"=="	" set "pkg_name=!pkg_name:~1!"
                        if "!pkg_name:~0,1!"=="\"" set "pkg_name=!pkg_name:~1,-1!"
                        
                        :: Check each popular package for typosquatting
                        for %%x in (!popular_packages!) do (
                            set "popular=%%x"
                            
                            :: Skip if exact match
                            if not "!pkg_name!"=="!popular!" (
                                :: Check for one character difference (typo)
                                call :check_one_char_diff "!pkg_name!" "!popular!"
                                if "!char_diff!"=="1" (
                                    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Potential typosquatting of '!popular!': !pkg_name! (1 char difference)"
                                )
                                
                                :: Check for missing character (e.g., reac instead of react)
                                call :strlen len1 "!pkg_name!"
                                call :strlen len2 "!popular!"
                                set /a len_diff=!len2!-!len1!
                                if !len_diff! equ 1 (
                                    :: Check if pkg_name is substring of popular
                                    echo !popular! | findstr /c:"!pkg_name!" >nul 2>&1
                                    if not errorlevel 1 (
                                        set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                        set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Potential typosquatting of '!popular!': !pkg_name! (missing char)"
                                    )
                                )
                                
                                :: Check for extra character (e.g., reactt instead of react)
                                set /a len_diff=!len1!-!len2!
                                if !len_diff! equ 1 (
                                    :: Check if popular is substring of pkg_name
                                    echo !pkg_name! | findstr /c:"!popular!" >nul 2>&1
                                    if not errorlevel 1 (
                                        set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                        set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Potential typosquatting of '!popular!': !pkg_name! (extra char)"
                                    )
                                )
                                
                                :: Check for common confusable patterns
                                call :check_confusables "!pkg_name!" "!popular!"
                                if "!has_confusable!"=="1" (
                                    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Potential typosquatting of '!popular!': !pkg_name! (confusable chars)"
                                )
                            )
                        )
                        
                        :: Check for Unicode/non-ASCII characters
                        :: This is limited in batch, but we can check for common Unicode lookalikes
                        echo !pkg_name! | findstr /r "[^a-zA-Z0-9@/._-]" >nul 2>&1
                        if not errorlevel 1 (
                            set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                            set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious characters in package name: !pkg_name!"
                        )
                        
                        :: Check for namespace confusion attacks
                        echo !pkg_name! | findstr /c:"@" >nul 2>&1
                        if not errorlevel 1 (
                            :: Extract namespace
                            for /f "tokens=1 delims=/" %%n in ("!pkg_name!") do set "namespace=%%n"
                            
                            :: Check for underscore vs hyphen confusion in popular namespaces
                            echo !namespace! | findstr /i "@types_" >nul 2>&1
                            if not errorlevel 1 (
                                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious namespace '!namespace!' (should be @types)"
                            )
                            echo !namespace! | findstr /i "@angular_" >nul 2>&1
                            if not errorlevel 1 (
                                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious namespace '!namespace!' (should be @angular)"
                            )
                            echo !namespace! | findstr /i "@typescript_" >nul 2>&1
                            if not errorlevel 1 (
                                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious namespace '!namespace!' (should be @typescript-eslint)"
                            )
                            echo !namespace! | findstr /i "@babel_" >nul 2>&1
                            if not errorlevel 1 (
                                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious namespace '!namespace!' (should be @babel)"
                            )
                            
                            :: Check for extra characters in namespace
                            echo !namespace! | findstr /i "@angularr @reactt @vuee @typess" >nul 2>&1
                            if not errorlevel 1 (
                                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Suspicious namespace with extra characters: !namespace!"
                            )
                        )
                    )
                )
                
                :: Check if we're exiting dependencies section
                echo !line! | findstr /c:"}" >nul 2>&1
                if not errorlevel 1 set "in_deps=0"
            )
        )
    )
)

:: Add completion message
if !TYPOSQUATTING_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "   [FOUND] !TYPOSQUATTING_WARNINGS_COUNT! potential typosquatting issue(s)"
    echo    Checked !packages_checked! package.json files
) else (
    call :print_green "   [OK] No typosquatting patterns detected"
    echo    Checked !packages_checked! package.json files
)
goto :eof

:: Helper function to calculate string length
:strlen
set "str=!%~2!"
set "len=0"
:strlen_loop
if defined str (
    set "str=!str:~1!"
    set /a len+=1
    goto :strlen_loop
)
set "%~1=!len!"
goto :eof

:: Helper function to check one character difference
:check_one_char_diff
set "str1=%~1"
set "str2=%~2"
set "char_diff=0"
call :strlen len1 "!str1!"
call :strlen len2 "!str2!"
if !len1! neq !len2! (
    set "char_diff=999"
    goto :eof
)
for /l %%i in (0,1,!len1!) do (
    if "!str1:~%%i,1!" neq "!str2:~%%i,1!" set /a char_diff+=1
)
goto :eof

:: Helper function to check confusable character patterns
:check_confusables
set "str1=%~1"
set "str2=%~2"
set "has_confusable=0"
:: Check for rn->m confusion
set "test1=!str1:rn=m!"
if "!test1!"=="!str2!" set "has_confusable=1"
:: Check for vv->w confusion
set "test1=!str1:vv=w!"
if "!test1!"=="!str2!" set "has_confusable=1"
:: Check for cl->d confusion
set "test1=!str1:cl=d!"
if "!test1!"=="!str2!" set "has_confusable=1"
:: Check for l->1 confusion
set "test1=!str1:l=1!"
if "!test1!"=="!str2!" set "has_confusable=1"
:: Check for 0->o confusion
set "test1=!str1:0=o!"
if "!test1!"=="!str2!" set "has_confusable=1"
goto :eof

:check_network_exfiltration
set "scan_dir=%~1"

echo    Analyzing files for network exfiltration patterns...
echo    Checking for suspicious domains, IP addresses, and data encoding...

set /a files_scanned=0
for /r "!scan_dir!" %%f in (*.js *.ts *.json *.mjs) do (
    if exist "%%f" (
        set /a files_scanned+=1
        
        :: Skip node_modules and vendor directories
        echo %%f | findstr /i "node_modules vendor" >nul 2>&1
        if errorlevel 1 (
            :: Check for all suspicious domains
            findstr /i "pastebin.com hastebin.com ix.io 0x0.st transfer.sh" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious file sharing domain found"
            )
            
            findstr /i "file.io anonfiles.com mega.nz dropbox.com/s/" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious cloud storage domain found"
            )
            
            findstr /i "discord.com/api/webhooks telegram.org t.me" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious messaging/webhook domain found"
            )
            
            findstr /i "ngrok.io localtunnel.me serveo.net" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious tunneling service found"
            )
            
            findstr /i "requestbin.com webhook.site beeceptor.com pipedream.com zapier.com/hooks" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious webhook/request capture service found"
            )
            
            :: Check for IP address patterns (simplified regex for batch)
            findstr /r "[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*" "%%f" >nul 2>&1
            if not errorlevel 1 (
                :: Extract and check if it's a private IP or has port
                for /f "tokens=*" %%i in ('findstr /r "[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*" "%%f" 2^>nul') do (
                    set "ip_line=%%i"
                    :: Check for private IP ranges
                    echo !ip_line! | findstr /r "10\.[0-9]" >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Private IP address found (10.x.x.x)"
                    )
                    echo !ip_line! | findstr /r "192\.168\." >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Private IP address found (192.168.x.x)"
                    )
                    echo !ip_line! | findstr /r "172\.1[6-9]\." >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Private IP address found (172.16-31.x.x)"
                    )
                    echo !ip_line! | findstr /r "172\.2[0-9]\." >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Private IP address found (172.16-31.x.x)"
                    )
                    echo !ip_line! | findstr /r "172\.3[01]\." >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Private IP address found (172.16-31.x.x)"
                    )
                    :: Check for IP with port
                    echo !ip_line! | findstr /r "[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*:[0-9]" >nul 2>&1
                    if not errorlevel 1 (
                        set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                        set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:IP address with port found (potential C2)"
                    )
                )
            )
            
            :: Check for base64 encoding near network operations
            findstr /c:"atob(" "%%f" >nul 2>&1
            if not errorlevel 1 (
                :: Check if file also contains network operations
                findstr /i "fetch XMLHttpRequest axios http\.request http\.get" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                    set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Base64 decoding found near network operations"
                )
            )
            
            :: Check for btoa (base64 encoding)
            findstr /c:"btoa(" "%%f" >nul 2>&1
            if not errorlevel 1 (
                :: Check if file also contains network operations
                findstr /i "fetch XMLHttpRequest axios post put" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                    set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Base64 encoding found near network operations"
                )
            )
            
            :: Check for WebSocket connections
            findstr /i "ws:// wss://" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:WebSocket connection detected"
            )
            
            :: Check for DNS-over-HTTPS patterns
            findstr /i "dns-query application/dns-message" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:DNS-over-HTTPS pattern detected"
            )
            
            :: Check for suspicious HTTP headers
            findstr /i "X-Exfiltrate X-Data-Export X-Credential X-Secret" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=%%f:Suspicious HTTP headers detected"
            )
        )
    )
)

:: Add completion message
if !NETWORK_EXFILTRATION_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "   [FOUND] !NETWORK_EXFILTRATION_WARNINGS_COUNT! network exfiltration pattern(s)"
    echo    Scanned !files_scanned! JavaScript/TypeScript/JSON files
) else (
    call :print_green "   [OK] No network exfiltration patterns detected"
    echo    Scanned !files_scanned! JavaScript/TypeScript/JSON files
)
goto :eof

:generate_report
set "paranoid_mode=%~1"
echo.
call :print_blue "=============================================="
if "!paranoid_mode!"=="true" (
    call :print_blue "  SHAI-HULUD + PARANOID SECURITY REPORT"
) else (
    call :print_blue "      SHAI-HULUD DETECTION REPORT"
)
call :print_blue "=============================================="
echo.

set /a high_risk=0
set /a medium_risk=0
set /a total_issues=0

:: Report malicious workflow files
if !WORKFLOW_FILES_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Malicious workflow files detected:"
    for /l %%i in (1,1,!WORKFLOW_FILES_COUNT!) do (
        echo    - !WORKFLOW_FILES[%%i]!
        set /a high_risk+=1
    )
    echo.
)

:: Report malicious file hashes
if !MALICIOUS_HASHES_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Files with known malicious hashes:"
    for /l %%i in (1,1,!MALICIOUS_HASHES_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!MALICIOUS_HASHES[%%i]!") do (
            echo    - %%a
            echo      Hash: %%b
        )
        set /a high_risk+=1
    )
    echo.
)

:: Report compromised packages
if !COMPROMISED_FOUND_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Compromised package versions detected:"
    for /l %%i in (1,1,!COMPROMISED_FOUND_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!COMPROMISED_FOUND[%%i]!") do (
            echo    - Package: %%b
            echo      Found in: %%a
        )
        set /a high_risk+=1
    )
    call :print_yellow "   NOTE: These specific package versions are known to be compromised."
    call :print_yellow "   You should immediately update or remove these packages."
    echo.
)

:: Report suspicious content
if !SUSPICIOUS_CONTENT_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK: Suspicious content patterns:"
    for /l %%i in (1,1,!SUSPICIOUS_CONTENT_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!SUSPICIOUS_CONTENT[%%i]!") do (
            echo    - Pattern: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    call :print_yellow "   NOTE: Manual review required to determine if these are malicious."
    echo.
)

:: Report git branches
if !GIT_BRANCHES_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK: Suspicious git branches:"
    for /l %%i in (1,1,!GIT_BRANCHES_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!GIT_BRANCHES[%%i]!") do (
            echo    - Repository: %%a
            echo      %%b
        )
        set /a medium_risk+=1
    )
    call :print_yellow "   NOTE: 'shai-hulud' branches may indicate compromise."
    echo.
)

:: Report suspicious postinstall hooks
if !POSTINSTALL_HOOKS_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Suspicious postinstall hooks detected:"
    for /l %%i in (1,1,!POSTINSTALL_HOOKS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!POSTINSTALL_HOOKS[%%i]!") do (
            echo    - Hook: %%b
            echo      Found in: %%a
        )
        set /a high_risk+=1
    )
    call :print_yellow "   NOTE: Postinstall hooks can execute arbitrary code during package installation."
    echo.
)

:: Report Trufflehog activity
if !TRUFFLEHOG_ACTIVITY_COUNT! gtr 0 (
    call :print_yellow "[!]  RISK: Trufflehog/secret scanning activity detected:"
    for /l %%i in (1,1,!TRUFFLEHOG_ACTIVITY_COUNT!) do (
        for /f "tokens=1,2,3 delims=:" %%a in ("!TRUFFLEHOG_ACTIVITY[%%i]!") do (
            echo    - Activity: %%c
            echo      Found in: %%a
            echo      Risk Level: %%b
            if "%%b"=="HIGH" set /a high_risk+=1
            if "%%b"=="MEDIUM" set /a medium_risk+=1
        )
    )
    echo.
)

:: Report Shai-Hulud repositories
if !SHAI_HULUD_REPOS_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Shai-Hulud repositories detected:"
    for /l %%i in (1,1,!SHAI_HULUD_REPOS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!SHAI_HULUD_REPOS[%%i]!") do (
            echo    - Repository: %%a
            echo      %%b
        )
        set /a high_risk+=1
    )
    call :print_yellow "   NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration."
    echo.
)

:: Report namespace warnings
if !NAMESPACE_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK: Packages from compromised namespaces:"
    for /l %%i in (1,1,!NAMESPACE_WARNINGS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!NAMESPACE_WARNINGS[%%i]!") do (
            echo    - Warning: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    echo.
)

:: Report package integrity issues
if !INTEGRITY_ISSUES_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK: Package integrity issues detected:"
    for /l %%i in (1,1,!INTEGRITY_ISSUES_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!INTEGRITY_ISSUES[%%i]!") do (
            echo    - Issue: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    echo.
)

:: Report typosquatting warnings (only in paranoid mode)
if "!paranoid_mode!"=="true" if !TYPOSQUATTING_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK (PARANOID): Potential typosquatting attacks detected:"
    for /l %%i in (1,1,!TYPOSQUATTING_WARNINGS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!TYPOSQUATTING_WARNINGS[%%i]!") do (
            echo    - Warning: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    echo.
)

:: Report network exfiltration warnings (only in paranoid mode)
if "!paranoid_mode!"=="true" if !NETWORK_EXFILTRATION_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
    for /l %%i in (1,1,!NETWORK_EXFILTRATION_WARNINGS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!NETWORK_EXFILTRATION_WARNINGS[%%i]!") do (
            echo    - Warning: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    echo.
)

set /a total_issues=high_risk+medium_risk

:: Summary
call :print_blue "=============================================="
if !total_issues! equ 0 (
    call :print_green "[OK] No indicators of Shai-Hulud compromise detected."
    call :print_green "Your system appears clean from this specific attack."
) else (
    call :print_red "[-] SUMMARY:"
    call :print_red "   High Risk Issues: !high_risk!"
    call :print_yellow "   Medium Risk Issues: !medium_risk!"
    call :print_blue "   Total Critical Issues: !total_issues!"
    echo.
    call :print_yellow "[!]  IMPORTANT:"
    call :print_yellow "   - High risk issues likely indicate actual compromise"
    call :print_yellow "   - Medium risk issues require manual investigation"
    if "!paranoid_mode!"=="true" (
        call :print_yellow "   - Issues marked (PARANOID) are general security checks, not Shai-Hulud specific"
    )
    call :print_yellow "   - Consider running additional security scans"
    call :print_yellow "   - Review your npm audit logs and package history"
)
call :print_blue "=============================================="
goto :eof
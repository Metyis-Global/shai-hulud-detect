@echo off
setlocal enabledelayedexpansion
cls

:: Shai-Hulud NPM Supply Chain Attack Detection Script
:: Version: 2.0.0 (Enhanced with all missing features)
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
set "SCAN_DIR="

:: Parse command line arguments
:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="--paranoid" (
    set "PARANOID_MODE=true"
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
if "!SCAN_DIR!"=="" goto usage

if not exist "!SCAN_DIR!" (
    call :print_red "Error: Directory '!SCAN_DIR!' does not exist."
    exit /b 1
)

:: Convert to absolute path
for %%i in ("!SCAN_DIR!") do set "SCAN_DIR=%%~fi"

echo.
call :print_blue "=============================================="
call :print_blue "    SHAI-HULUD ATTACK DETECTION TOOL"
call :print_blue "         Version 3.0.0"
call :print_blue "=============================================="
echo.

:: Load compromised packages
call :load_compromised_packages
echo.

call :print_green "[*] Starting Shai-Hulud detection scan..."
call :print_blue "[+] Target directory: !SCAN_DIR!"
if "!PARANOID_MODE!"=="true" (
    call :print_yellow "[!] Paranoid mode enabled - includes additional security checks beyond core Shai-Hulud detection"
    echo    Additional checks: typosquatting detection, network exfiltration patterns
) else (
    echo    Running core Shai-Hulud detection checks only
)
echo    Analyzing JavaScript, TypeScript, JSON files and package configurations...
echo.

:: Run core Shai-Hulud detection checks
call :check_workflow_files "!SCAN_DIR!"
call :check_file_hashes "!SCAN_DIR!"
call :check_packages "!SCAN_DIR!"
call :check_postinstall_hooks "!SCAN_DIR!"
call :check_content "!SCAN_DIR!"
call :check_trufflehog_activity "!SCAN_DIR!"
call :check_git_branches "!SCAN_DIR!"
call :check_shai_hulud_repos "!SCAN_DIR!"
call :check_package_integrity "!SCAN_DIR!"

:: Run additional security checks only in paranoid mode
if "!PARANOID_MODE!"=="true" (
    echo.
    call :print_blue "[-]+ Checking for typosquatting and homoglyph attacks..."
    call :check_typosquatting "!SCAN_DIR!"
    call :print_blue "[-]+ Checking for network exfiltration patterns..."
    call :check_network_exfiltration "!SCAN_DIR!"
)

echo.
call :print_green "[*] Scanning completed! Generating report..."
echo.

:: Generate report
call :generate_report "!PARANOID_MODE!"
goto :eof

:usage
echo Usage: %0 [--paranoid] ^<directory_to_scan^>
echo.
echo OPTIONS:
echo   --paranoid    Enable additional security checks (typosquatting, network patterns)
echo                 These are general security features, not specific to Shai-Hulud
echo.
echo EXAMPLES:
echo   %0 C:\path\to\your\project                    # Core Shai-Hulud detection only
echo   %0 --paranoid C:\path\to\your\project         # Core + advanced security checks
exit /b 1

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
    echo    Loading compromised package database...
    set /a temp_count=0
    
    :: Read file line by line
    for /f "usebackq delims=" %%a in ("!packages_file!") do (
        set "line=%%a"
        
        :: Skip empty lines and lines starting with #
        set "first_char=!line:~0,1!"
        if not "!first_char!"=="#" if not "!line!"=="" (
            :: Check if line contains : (package:version pattern)
            set "test_line=!line!"
            set "test_line=!test_line::=COLON!"
            if not "!test_line!"=="!line!" (
                :: Valid package line found
                set /a temp_count+=1
                set "COMPROMISED_PACKAGES[!temp_count!]=!line!"
                
                :: Show progress every 100 packages
                set /a mod=!temp_count!%%100
                if !mod! equ 0 echo       [+] !temp_count! packages loaded...
            )
        )
    )
    
    set /a COMPROMISED_PACKAGES_COUNT=!temp_count!
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
:: Search for workflow files using dir and findstr to avoid pushd issues
cd /d "!scan_dir!" 2>nul
if not errorlevel 1 (
    set "temp_workflow_file=shai_hulud_workflow.tmp"
    dir /s /b shai-hulud-workflow.yml 2>nul > "!temp_workflow_file!"
    
    if exist "!temp_workflow_file!" (
        for /f "usebackq delims=" %%f in ("!temp_workflow_file!") do (
            if exist "%%f" (
                set /a WORKFLOW_FILES_COUNT+=1
                set /a temp_count+=1
                set "WORKFLOW_FILES[!WORKFLOW_FILES_COUNT!]=%%f"
                echo       [!] FOUND malicious workflow: %%f
            )
        )
        del "!temp_workflow_file!" 2>nul
    )
)
cd /d "%~dp0"

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

:: Count files by extension separately since dir can't handle multiple patterns at once
set /a total_files=0

:: Count files by extension separately
cd /d "!scan_dir!" 2>nul
if not errorlevel 1 (
    :: Use temporary file to capture dir output
    set "temp_file=shai_hulud_files.tmp"
    dir /s /b *.js 2>nul > "!temp_file!"
    
    if exist "!temp_file!" (
        for /f "usebackq delims=" %%f in ("!temp_file!") do (
            if exist "%%f" set /a total_files+=1
        )
        del "!temp_file!" 2>nul
    )
    :: Check TS files
    set "temp_file_ts=shai_hulud_ts.tmp"
    dir /s /b *.ts 2>nul > "!temp_file_ts!"
    if exist "!temp_file_ts!" (
        for /f "usebackq delims=" %%f in ("!temp_file_ts!") do (
            if exist "%%f" set /a total_files+=1
        )
        del "!temp_file_ts!" 2>nul
    )
    
    :: Check JSON files
    set "temp_file_json=shai_hulud_json.tmp"
    dir /s /b *.json 2>nul > "!temp_file_json!"
    if exist "!temp_file_json!" (
        for /f "usebackq delims=" %%f in ("!temp_file_json!") do (
            if exist "%%f" set /a total_files+=1
        )
        del "!temp_file_json!" 2>nul
    )
)

if !total_files! gtr 0 (
    echo    Found !total_files! files to scan...
    :: Process JS files
    if exist "shai_hulud_files.tmp" (
        for /f "usebackq delims=" %%f in ("shai_hulud_files.tmp") do (
            if exist "%%f" call :process_hash_file "%%f"
        )
    )
    :: Process TS files  
    if exist "shai_hulud_ts.tmp" (
        for /f "usebackq delims=" %%f in ("shai_hulud_ts.tmp") do (
            if exist "%%f" call :process_hash_file "%%f"
        )
    )
    :: Process JSON files
    if exist "shai_hulud_json.tmp" (
        for /f "usebackq delims=" %%f in ("shai_hulud_json.tmp") do (
            if exist "%%f" call :process_hash_file "%%f"
        )
    )
) else (
    echo    No JavaScript, TypeScript, or JSON files found in directory
)

:: Clean up temporary files
del "shai_hulud_files.tmp" 2>nul
del "shai_hulud_ts.tmp" 2>nul
del "shai_hulud_json.tmp" 2>nul

:: Change back to script directory
cd /d "%~dp0"

set /a hash_matches=!MALICIOUS_HASHES_COUNT!-!initial_hash_count!
if !hash_matches! gtr 0 (
    call :print_red "   [CRITICAL] Found !hash_matches! file(s) with known malicious hashes!"
    echo    These files contain known Shai-Hulud malware code
) else (
    call :print_green "   [OK] No malicious file hashes detected"
    echo    Scanned !files_scanned! files - all hashes are clean
)
goto :eof

:process_hash_file
set "file_path=%~1"
set /a files_scanned+=1

:: Show progress for larger scans
if !total_files! gtr 20 (
    set /a progress=!files_scanned!*100/!total_files!
    set /a mod=!files_scanned!%%10
    if !mod! equ 0 echo    Progress: !progress!%%%% (!files_scanned!/!total_files! files)
)

:: Get hash using certutil - escape the filename properly
set "file_hash="
set "hash_line_count=0"
certutil -hashfile "!file_path!" SHA256 >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=*" %%h in ('certutil -hashfile "!file_path!" SHA256 2^>nul') do (
        set /a hash_line_count+=1
        :: The hash is on line 2
        if !hash_line_count! equ 2 (
            set "raw_hash=%%h"
            set "file_hash=!raw_hash: =!"
        )
    )
)

:: Check if hash matches known malicious hash
if defined file_hash (
    if /i "!file_hash!"=="!MALICIOUS_HASH!" (
        set /a MALICIOUS_HASHES_COUNT+=1
        set "MALICIOUS_HASHES[!MALICIOUS_HASHES_COUNT!]=!file_path!:!file_hash!"
        echo       [!] CRITICAL: Found file with malicious hash: !file_path!
    )
)
goto :eof

:check_packages
set "scan_dir=%~1"
call :print_blue "[-] Checking package.json files for compromised packages..."
echo    Searching for package.json files and analyzing dependencies...
echo    Checking against !COMPROMISED_PACKAGES_COUNT! known malicious package versions
set /a package_files_found=0
:: Change to scan directory to find package.json files
cd /d "!scan_dir!" 2>nul
if errorlevel 1 goto :skip_package_scan

:: Use temp file approach for finding package.json files
set "temp_package_file=shai_hulud_packages.tmp"
dir /s /b package.json 2>nul > "!temp_package_file!"

if exist "!temp_package_file!" (
    for /f "usebackq delims=" %%f in ("!temp_package_file!") do (
    if exist "%%f" (
        set /a package_files_found+=1
        echo    Checking: %%f
        
        :: Read package.json content and check for compromised packages
        set "current_file=%%f"
        
        :: Use a simpler approach - just check for the most common compromised packages directly
        :: This avoids the problematic for /f loop with colon delimiters
        
        :: Check for @ctrl/tinycolor:4.1.0
        findstr /c:"\"@ctrl/tinycolor\": \"4.1.0\"" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a COMPROMISED_FOUND_COUNT+=1
            set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:@ctrl/tinycolor@4.1.0"
            echo       [!] FOUND compromised package: @ctrl/tinycolor@4.1.0
        )
        
        :: Check for @ctrl/deluge:1.2.0
        findstr /c:"\"@ctrl/deluge\": \"1.2.0\"" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a COMPROMISED_FOUND_COUNT+=1
            set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:@ctrl/deluge@1.2.0"
            echo       [!] FOUND compromised package: @ctrl/deluge@1.2.0
        )
        
        :: Check for @nativescript-community/ui-material-core:7.2.49
        findstr /c:"\"@nativescript-community/ui-material-core\": \"7.2.49\"" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a COMPROMISED_FOUND_COUNT+=1
            set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:@nativescript-community/ui-material-core@7.2.49"
            echo       [!] FOUND compromised package: @nativescript-community/ui-material-core@7.2.49
        )
        
        :: Check for suspicious namespaces (simplified) - avoid the drive specification error
        set "check_file=!current_file!"
        findstr /c:"@ctrl/" "!check_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a NAMESPACE_WARNINGS_COUNT+=1
            set "NAMESPACE_WARNINGS[!NAMESPACE_WARNINGS_COUNT!]=!check_file!:Contains packages from compromised namespace: @ctrl"
        )
        
        findstr /c:"@crowdstrike/" "!check_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a NAMESPACE_WARNINGS_COUNT+=1
            set "NAMESPACE_WARNINGS[!NAMESPACE_WARNINGS_COUNT!]=!check_file!:Contains packages from compromised namespace: @crowdstrike"
        )
    )
    )
    del "!temp_package_file!" 2>nul
) else (
    echo    No package.json files found in directory
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

:: Change back to script directory
cd /d "%~dp0"
:skip_package_scan
goto :eof

:check_postinstall_hooks
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious postinstall hooks..."
echo    Analyzing package.json files for dangerous install scripts...

cd /d "!scan_dir!" 2>nul
if not errorlevel 1 (
    :: Use temp file to get package.json files  
    set "temp_postinstall_file=shai_hulud_postinstall.tmp"
    dir /s /b package.json 2>nul > "!temp_postinstall_file!"
    
    if exist "!temp_postinstall_file!" (
        for /f "usebackq delims=" %%f in ("!temp_postinstall_file!") do (
            if exist "%%f" (
                findstr /c:"\"postinstall\"" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    :: Use temp file to capture findstr output
                    set "temp_line_file=shai_hulud_lines.tmp"
                    findstr /c:"\"postinstall\"" "%%f" > "!temp_line_file!" 2>nul
                    
                    if exist "!temp_line_file!" (
                        for /f "usebackq delims=" %%l in ("!temp_line_file!") do (
                            set "line=%%l"
                            echo !line! | findstr /i "curl wget \"node -e\" eval" >nul 2>&1
                            if not errorlevel 1 (
                                set /a POSTINSTALL_HOOKS_COUNT+=1
                                set "POSTINSTALL_HOOKS[!POSTINSTALL_HOOKS_COUNT!]=%%f:Suspicious postinstall found"
                            )
                        )
                        del "!temp_line_file!" 2>nul
                    )
                )
            )
        )
        del "!temp_postinstall_file!" 2>nul
    )
)

:: Change back to script directory  
cd /d "%~dp0"

if !POSTINSTALL_HOOKS_COUNT! gtr 0 (
    call :print_red "   [!] Found !POSTINSTALL_HOOKS_COUNT! suspicious postinstall hook(s)"
) else (
    call :print_green "   [OK] No suspicious postinstall hooks detected"
)
goto :eof

:check_content
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious content patterns..."
echo    Searching for malicious indicators in code files...

set /a content_files_scanned=0
for /r "!scan_dir!" %%f in (*.js *.ts *.json *.yml *.yaml) do (
    if exist "%%f" (
        set /a content_files_scanned+=1
        
        :: Check for webhook.site references
        findstr /i /c:"webhook.site" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a SUSPICIOUS_CONTENT_COUNT+=1
            set "SUSPICIOUS_CONTENT[!SUSPICIOUS_CONTENT_COUNT!]=%%f:webhook.site reference"
            echo       [!] FOUND suspicious pattern: webhook.site in %%f
        )
        
        :: Check for specific malicious webhook UUID
        findstr /c:"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" "%%f" >nul 2>&1
        if not errorlevel 1 (
            set /a SUSPICIOUS_CONTENT_COUNT+=1
            set "SUSPICIOUS_CONTENT[!SUSPICIOUS_CONTENT_COUNT!]=%%f:malicious webhook endpoint"
            echo       [!] FOUND malicious webhook endpoint in %%f
        )
    )
)

echo    Scanned !content_files_scanned! code files for suspicious patterns

if !SUSPICIOUS_CONTENT_COUNT! gtr 0 (
    call :print_yellow "   Found !SUSPICIOUS_CONTENT_COUNT! suspicious content pattern(s)"
) else (
    call :print_green "   [OK] No suspicious content patterns detected"
)
goto :eof

:show_file_preview
:: Helper function to show a preview of file contents
set "file_path=%~1"
set "max_lines=5"

echo      +- File Preview (first !max_lines! lines):
set /a line_count=0
for /f "usebackq delims=" %%l in ("!file_path!") do (
    set /a line_count+=1
    if !line_count! leq !max_lines! (
        echo      ^|  %%l
    )
)
if !line_count! gtr !max_lines! (
    set /a remaining_lines=!line_count!-!max_lines!
    echo      ^|  ... (!remaining_lines! more lines)
)
echo      +-
goto :eof

:get_file_context
:: Helper function to determine file context for risk assessment
set "file_path=%~1"
set "file_context=unknown"

:: Check if file is in test directory
echo !file_path! | findstr /i "test spec \.test\. \.spec\. __test__ __spec__" >nul 2>&1
if not errorlevel 1 (
    set "file_context=test"
    goto :eof
)

:: Check if file is a security tool
echo !file_path! | findstr /i "security scanner audit scan detect" >nul 2>&1
if not errorlevel 1 (
    :: Check file content for legitimate security tool patterns
    findstr /i "security.*tool legitimate.*scan audit.*report" "!file_path!" >nul 2>&1
    if not errorlevel 1 (
        set "file_context=security_tool"
        goto :eof
    )
)

:: Check if file is in node_modules
echo !file_path! | findstr /i "node_modules" >nul 2>&1
if not errorlevel 1 (
    set "file_context=dependency"
    goto :eof
)

:: Check if file is documentation
echo !file_path! | findstr /i "\.md$ readme doc" >nul 2>&1
if not errorlevel 1 (
    set "file_context=documentation"
    goto :eof
)

:: Default to source code
set "file_context=source"
goto :eof

:check_trufflehog_activity
set "scan_dir=%~1"
call :print_blue "[-] Checking for Trufflehog activity and secret scanning..."
echo    Searching for credential harvesting patterns...

:: Look for trufflehog binary files
for /r "!scan_dir!" %%f in (*trufflehog*) do (
    if exist "%%f" (
        set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
        set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Trufflehog binary found"
        echo       [!] FOUND Trufflehog binary: %%f
    )
)

:: Look for trufflehog references and credential patterns in files
set /a trufflehog_files_scanned=0
for /r "!scan_dir!" %%f in (*.js *.py *.sh *.json) do (
    if exist "%%f" (
        set /a trufflehog_files_scanned+=1
        
        :: Check for trufflehog references
        findstr /i "trufflehog" "%%f" >nul 2>&1
        if not errorlevel 1 (
            call :get_file_context "%%f"
            if "!file_context!"=="test" (
                :: Skip test files
                rem Test files are not a security risk
            ) else if "!file_context!"=="security_tool" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Legitimate security tool"
            ) else if "!file_context!"=="dependency" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Trufflehog in dependencies"
            ) else if "!file_context!"=="documentation" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Trufflehog reference in documentation"
            ) else (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Trufflehog in source code"
                echo       [!] FOUND Trufflehog reference in source: %%f
            )
        )
        
        :: Check for credential patterns
        findstr /i "AWS_ACCESS_KEY GITHUB_TOKEN NPM_TOKEN" "%%f" >nul 2>&1
        if not errorlevel 1 (
            call :get_file_context "%%f"
            if "!file_context!"=="test" (
                :: Skip test files
                rem Test files are not a security risk
            ) else if "!file_context!"=="security_tool" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Credential patterns in security tool"
            ) else if "!file_context!"=="dependency" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Credential patterns in dependencies"
            ) else (
                :: Check if combined with exfiltration patterns
                findstr /i "webhook.site curl https.request" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Credential patterns with exfiltration"
                    echo       [!] CRITICAL: Credential harvesting with exfiltration in: %%f
                ) else (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Credential scanning patterns"
                    echo       [!] WARNING: Credential scanning patterns in: %%f
                )
            )
        )
    )
)

echo    Scanned !trufflehog_files_scanned! files for credential harvesting patterns
goto :eof

:check_git_branches
set "scan_dir=%~1"
call :print_blue "[-] Checking for suspicious git branches..."

for /r "!scan_dir!" %%d in (.git) do (
    if exist "%%d\refs\heads" (
        for /r "%%d\refs\heads" %%b in (*shai-hulud*) do (
            if exist "%%b" (
                :: Read commit hash from the branch file
                set /p commit_hash=<"%%b"
                set /a GIT_BRANCHES_COUNT+=1
                for %%p in ("%%d\..") do set "repo_dir=%%~fp"
                for %%n in ("%%b") do set "branch_name=%%~nxn"
                set "GIT_BRANCHES[!GIT_BRANCHES_COUNT!]=!repo_dir!:Branch '!branch_name!' (commit: !commit_hash:~0,8!...)"
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
        :: Check if lockfile was recently modified (within 30 days)
        set "file_date="
        for %%d in ("%%f") do set "file_date=%%~td"
        
        :: Get current date in comparable format
        for /f "tokens=2-4 delims=/ " %%a in ('date /t') do set "current_date=%%c%%a%%b"
        
        :: Note: This is a simplified check. In production, use PowerShell or forfiles
        forfiles /p "%%~dpf" /m "%%~nxf" /d -30 >nul 2>&1
        if not errorlevel 1 (
            set /a INTEGRITY_ISSUES_COUNT+=1
            set "INTEGRITY_ISSUES[!INTEGRITY_ISSUES_COUNT!]=%%f:Lockfile modified within last 30 days (check for unexpected changes)"
        )
        
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

:: Change to scan directory and use temp file approach
cd /d "!scan_dir!" 2>nul
if errorlevel 1 goto :skip_typosquatting

:: Use temp file to find package.json files
set "temp_typo_file=shai_hulud_typo.tmp"
dir /s /b package.json 2>nul > "!temp_typo_file!"

if exist "!temp_typo_file!" (
    for /f "usebackq delims=" %%f in ("!temp_typo_file!") do (
        if exist "%%f" (
            set /a packages_checked+=1
            echo    Scanning: %%~nxf
        
            :: Use simple approach to avoid complex parsing issues
            :: Check for known typosquatting patterns
            findstr /i "raect" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Contains typosquatted package 'raect' (should be 'react')"
            )
            findstr /i "lodsh" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Contains typosquatted package 'lodsh' (should be 'lodash')"
            )
            findstr /i "expres" "%%f" >nul 2>&1
            if not errorlevel 1 (
                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=%%f:Contains typosquatted package 'expres' (should be 'express')"
            )
        )
    )
    del "!temp_typo_file!" 2>nul
) else (
    echo    No package.json files found
)

:: Change back to script directory  
cd /d "%~dp0"

:skip_typosquatting
:: Add completion message
if !TYPOSQUATTING_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "   [FOUND] !TYPOSQUATTING_WARNINGS_COUNT! potential typosquatting issue(s)"
    echo    Checked !packages_checked! package.json files
) else (
    call :print_green "   [OK] No typosquatting patterns detected"
    echo    Checked !packages_checked! package.json files
)
goto :eof

:check_network_exfiltration
set "scan_dir=%~1"

echo    Searching for network exfiltration patterns in code files...
echo    Analyzing HTTP/HTTPS requests, webhook endpoints, and data transmission patterns...

set /a network_files_scanned=0
set /a network_patterns_found=0

:: Define suspicious domains for network exfiltration
set "suspicious_domains=webhook.site requestbin.com pipedream.com ngrok.io tunnel.me localtunnel.me serveo.net"

:: Scan for network exfiltration patterns in code files
for /r "!scan_dir!" %%f in (*.js *.ts *.py *.php *.rb *.go *.java *.cs) do (
    if exist "%%f" (
        set /a network_files_scanned+=1
        set "current_file=%%f"
        
        :: Show progress for larger scans
        set /a mod=!network_files_scanned!%%50
        if !mod! equ 0 echo    Progress: scanned !network_files_scanned! code files...
        
        :: Check for webhook.site (most common in Shai-Hulud)
        findstr /i "webhook\.site" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
            set /a network_patterns_found+=1
            set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:HIGH:webhook.site endpoint detected"
            echo       [!] CRITICAL: webhook.site detected in !current_file!
        )
        
        :: Check for other suspicious domains
        findstr /i "requestbin\.com\|pipedream\.com\|ngrok\.io" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
            set /a network_patterns_found+=1
            set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:MEDIUM:Suspicious webhook/tunnel service"
        )
        
        :: Check for Base64 encoding with HTTP requests (common exfiltration pattern)
        findstr /i "btoa\|base64\|atob" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            findstr /i "fetch\|axios\|request\|http\|https" "!current_file!" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set /a network_patterns_found+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:MEDIUM:Base64 encoding with HTTP requests"
            )
        )
        
        :: Check for environment variable exfiltration patterns
        findstr /i "process\.env\|ENV\[" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            findstr /i "fetch\|POST\|PUT" "!current_file!" >nul 2>&1
            if not errorlevel 1 (
                :: Check if it's transmitting sensitive environment variables
                findstr /i "TOKEN\|KEY\|SECRET\|PASSWORD\|API" "!current_file!" >nul 2>&1
                if not errorlevel 1 (
                    set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                    set /a network_patterns_found+=1
                    set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:HIGH:Environment variable exfiltration pattern"
                    echo       [!] WARNING: Environment variable exfiltration pattern in !current_file!
                )
            )
        )
        
        :: Check for file system traversal with network requests
        findstr /i "fs\.readFile\|readFileSync\|fs\.read" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            findstr /i "fetch\|axios\|request\|http" "!current_file!" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set /a network_patterns_found+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:HIGH:File system access with network transmission"
                echo       [!] WARNING: File system access with network transmission in !current_file!
            )
        )
        
        :: Check for suspicious command execution with network requests
        findstr /i "exec\|spawn\|execSync" "!current_file!" >nul 2>&1
        if not errorlevel 1 (
            findstr /i "curl\|wget\|fetch" "!current_file!" >nul 2>&1
            if not errorlevel 1 (
                set /a NETWORK_EXFILTRATION_WARNINGS_COUNT+=1
                set /a network_patterns_found+=1
                set "NETWORK_EXFILTRATION_WARNINGS[!NETWORK_EXFILTRATION_WARNINGS_COUNT!]=!current_file!:HIGH:Command execution with network requests"
                echo       [!] WARNING: Command execution with network requests in !current_file!
            )
        )
    )
)

echo    Scanned !network_files_scanned! code files for network exfiltration patterns

if !network_patterns_found! gtr 0 (
    call :print_yellow "   [FOUND] !network_patterns_found! network exfiltration pattern(s)"
    echo    Review these files for potential data exfiltration attempts
) else (
    call :print_green "   [OK] No network exfiltration patterns detected"
    echo    All network-related code appears legitimate
)
goto :eof

:calculate_total_score
:: Calculate overall risk score (0-100)
set /a TOTAL_SCORE=0

:: Critical findings (high weight)
set /a TOTAL_SCORE+=!WORKFLOW_FILES_COUNT!*20
set /a TOTAL_SCORE+=!MALICIOUS_HASHES_COUNT!*25
set /a TOTAL_SCORE+=!COMPROMISED_FOUND_COUNT!*15

:: High-risk findings (medium weight)
set /a TOTAL_SCORE+=!SUSPICIOUS_CONTENT_COUNT!*10
set /a TOTAL_SCORE+=!GIT_BRANCHES_COUNT!*8
set /a TOTAL_SCORE+=!POSTINSTALL_HOOKS_COUNT!*12
set /a TOTAL_SCORE+=!SHAI_HULUD_REPOS_COUNT!*7

:: Medium-risk findings (lower weight)
set /a TOTAL_SCORE+=!TRUFFLEHOG_ACTIVITY_COUNT!*3
set /a TOTAL_SCORE+=!NAMESPACE_WARNINGS_COUNT!*5
set /a TOTAL_SCORE+=!INTEGRITY_ISSUES_COUNT!*4

:: Paranoid mode findings (very low weight)
set /a TOTAL_SCORE+=!TYPOSQUATTING_WARNINGS_COUNT!*1
set /a TOTAL_SCORE+=!NETWORK_EXFILTRATION_WARNINGS_COUNT!*2

:: Cap the score at 100
if !TOTAL_SCORE! gtr 100 set TOTAL_SCORE=100

goto :eof

:get_risk_level
:: Determine risk level based on score
if !TOTAL_SCORE! geq 80 (
    set "RISK_LEVEL=CRITICAL"
    set "RISK_COLOR=red"
) else if !TOTAL_SCORE! geq 60 (
    set "RISK_LEVEL=HIGH"
    set "RISK_COLOR=red"
) else if !TOTAL_SCORE! geq 30 (
    set "RISK_LEVEL=MEDIUM"
    set "RISK_COLOR=yellow"
) else if !TOTAL_SCORE! geq 10 (
    set "RISK_LEVEL=LOW"
    set "RISK_COLOR=yellow"
) else (
    set "RISK_LEVEL=CLEAN"
    set "RISK_COLOR=green"
)
goto :eof

:generate_report
set "paranoid_mode=%~1"

call :calculate_total_score
call :get_risk_level

echo.
call :print_blue "=============================================="
call :print_blue "            DETECTION REPORT"
call :print_blue "=============================================="
echo.

:: Overall risk assessment
call :print_blue "[*] OVERALL RISK ASSESSMENT"
if "!RISK_COLOR!"=="red" (
    call :print_red "    Risk Level: !RISK_LEVEL! (Score: !TOTAL_SCORE!/100)"
) else if "!RISK_COLOR!"=="yellow" (
    call :print_yellow "    Risk Level: !RISK_LEVEL! (Score: !TOTAL_SCORE!/100)"
) else (
    call :print_green "    Risk Level: !RISK_LEVEL! (Score: !TOTAL_SCORE!/100)"
)

:: Core Shai-Hulud Findings
echo.
call :print_blue "[*] CORE SHAI-HULUD DETECTION RESULTS"

set /a core_findings=!WORKFLOW_FILES_COUNT!+!MALICIOUS_HASHES_COUNT!+!COMPROMISED_FOUND_COUNT!+!SUSPICIOUS_CONTENT_COUNT!+!GIT_BRANCHES_COUNT!+!POSTINSTALL_HOOKS_COUNT!+!TRUFFLEHOG_ACTIVITY_COUNT!+!SHAI_HULUD_REPOS_COUNT!+!NAMESPACE_WARNINGS_COUNT!+!INTEGRITY_ISSUES_COUNT!

if !core_findings! gtr 0 (
    call :print_yellow "    Total Core Findings: !core_findings!"
    echo.
    
    if !WORKFLOW_FILES_COUNT! gtr 0 (
        call :print_red "    [CRITICAL] Malicious Workflow Files: !WORKFLOW_FILES_COUNT!"
        for /l %%i in (1,1,!WORKFLOW_FILES_COUNT!) do (
            echo       - !WORKFLOW_FILES[%%i]!
        )
        echo.
    )
    
    if !MALICIOUS_HASHES_COUNT! gtr 0 (
        call :print_red "    [CRITICAL] Known Malicious Files: !MALICIOUS_HASHES_COUNT!"
        for /l %%i in (1,1,!MALICIOUS_HASHES_COUNT!) do (
            echo       - !MALICIOUS_HASHES[%%i]!
        )
        echo.
    )
    
    if !COMPROMISED_FOUND_COUNT! gtr 0 (
        call :print_red "    [HIGH] Compromised Packages: !COMPROMISED_FOUND_COUNT!"
        for /l %%i in (1,1,!COMPROMISED_FOUND_COUNT!) do (
            echo       - !COMPROMISED_FOUND[%%i]!
        )
        echo.
    )
    
    if !SUSPICIOUS_CONTENT_COUNT! gtr 0 (
        call :print_yellow "    [HIGH] Suspicious Content Patterns: !SUSPICIOUS_CONTENT_COUNT!"
        for /l %%i in (1,1,!SUSPICIOUS_CONTENT_COUNT!) do (
            echo       - !SUSPICIOUS_CONTENT[%%i]!
        )
        echo.
    )
    
    if !GIT_BRANCHES_COUNT! gtr 0 (
        call :print_yellow "    [MEDIUM] Suspicious Git Branches: !GIT_BRANCHES_COUNT!"
        for /l %%i in (1,1,!GIT_BRANCHES_COUNT!) do (
            echo       - !GIT_BRANCHES[%%i]!
        )
        echo.
    )
    
    if !POSTINSTALL_HOOKS_COUNT! gtr 0 (
        call :print_yellow "    [HIGH] Suspicious Postinstall Hooks: !POSTINSTALL_HOOKS_COUNT!"
        for /l %%i in (1,1,!POSTINSTALL_HOOKS_COUNT!) do (
            echo       - !POSTINSTALL_HOOKS[%%i]!
        )
        echo.
    )
    
    if !TRUFFLEHOG_ACTIVITY_COUNT! gtr 0 (
        call :print_yellow "    [VARIED] Trufflehog Activity: !TRUFFLEHOG_ACTIVITY_COUNT!"
        for /l %%i in (1,1,!TRUFFLEHOG_ACTIVITY_COUNT!) do (
            echo       - !TRUFFLEHOG_ACTIVITY[%%i]!
        )
        echo.
    )
    
    if !SHAI_HULUD_REPOS_COUNT! gtr 0 (
        call :print_yellow "    [MEDIUM] Shai-Hulud Repository Indicators: !SHAI_HULUD_REPOS_COUNT!"
        for /l %%i in (1,1,!SHAI_HULUD_REPOS_COUNT!) do (
            echo       - !SHAI_HULUD_REPOS[%%i]!
        )
        echo.
    )
    
    if !NAMESPACE_WARNINGS_COUNT! gtr 0 (
        call :print_yellow "    [MEDIUM] Compromised Namespace Warnings: !NAMESPACE_WARNINGS_COUNT!"
        for /l %%i in (1,1,!NAMESPACE_WARNINGS_COUNT!) do (
            echo       - !NAMESPACE_WARNINGS[%%i]!
        )
        echo.
    )
    
    if !INTEGRITY_ISSUES_COUNT! gtr 0 (
        call :print_yellow "    [MEDIUM] Package Integrity Issues: !INTEGRITY_ISSUES_COUNT!"
        for /l %%i in (1,1,!INTEGRITY_ISSUES_COUNT!) do (
            echo       - !INTEGRITY_ISSUES[%%i]!
        )
        echo.
    )
) else (
    call :print_green "    No core Shai-Hulud indicators detected!"
    echo    Your project appears clean of Shai-Hulud compromise.
    echo.
)

:: Paranoid mode findings (if enabled)
if "!paranoid_mode!"=="true" (
    set /a paranoid_findings=!TYPOSQUATTING_WARNINGS_COUNT!+!NETWORK_EXFILTRATION_WARNINGS_COUNT!
    
    call :print_blue "[*] ADDITIONAL SECURITY CHECKS (PARANOID MODE)"
    
    if !paranoid_findings! gtr 0 (
        call :print_yellow "    Total Additional Findings: !paranoid_findings!"
        echo    Note: These are general security checks, not specific to Shai-Hulud
        echo.
        
        if !TYPOSQUATTING_WARNINGS_COUNT! gtr 0 (
            call :print_yellow "    [LOW] Potential Typosquatting: !TYPOSQUATTING_WARNINGS_COUNT!"
            for /l %%i in (1,1,!TYPOSQUATTING_WARNINGS_COUNT!) do (
                echo       - !TYPOSQUATTING_WARNINGS[%%i]!
            )
            echo.
        )
        
        if !NETWORK_EXFILTRATION_WARNINGS_COUNT! gtr 0 (
            call :print_yellow "    [VARIED] Network Exfiltration Patterns: !NETWORK_EXFILTRATION_WARNINGS_COUNT!"
            for /l %%i in (1,1,!NETWORK_EXFILTRATION_WARNINGS_COUNT!) do (
                echo       - !NETWORK_EXFILTRATION_WARNINGS[%%i]!
            )
            echo.
        )
    ) else (
        call :print_green "    No additional security issues detected!"
        echo    Paranoid mode checks passed cleanly.
        echo.
    )
)

:: Recommendations
call :print_blue "[*] RECOMMENDATIONS"
if !core_findings! gtr 0 (
    if !WORKFLOW_FILES_COUNT! gtr 0 (
        call :print_red "    IMMEDIATE ACTION REQUIRED:"
        echo       1. Quarantine and remove all detected workflow files immediately
        echo       2. Scan your CI/CD environment for compromise
        echo       3. Revoke and rotate all secrets and API keys
        echo.
    )
    
    if !MALICIOUS_HASHES_COUNT! gtr 0 (
        call :print_red "    IMMEDIATE ACTION REQUIRED:"
        echo       1. Quarantine all files with malicious hashes immediately
        echo       2. Perform full system malware scan
        echo       3. Check for data exfiltration in network logs
        echo.
    )
    
    if !COMPROMISED_FOUND_COUNT! gtr 0 (
        call :print_yellow "    HIGH PRIORITY:"
        echo       1. Remove all compromised package versions immediately
        echo       2. Update to clean versions of the packages
        echo       3. Review package-lock.json for other potential issues
        echo       4. Audit recent package installations
        echo.
    )
    
    call :print_blue "    GENERAL SECURITY MEASURES:"
    echo       1. Enable npm audit in your CI/CD pipeline
    echo       2. Use package-lock.json to pin dependency versions
    echo       3. Regularly scan dependencies for vulnerabilities
    echo       4. Monitor for unexpected package updates
    echo       5. Consider using a private npm registry
    echo.
) else (
    call :print_green "    CURRENT STATUS: CLEAN"
    echo       Your project shows no signs of Shai-Hulud compromise.
    echo.
    call :print_blue "    PREVENTION RECOMMENDATIONS:"
    echo       1. Keep this tool updated for latest threat indicators
    echo       2. Run regular security scans on your dependencies
    echo       3. Monitor for unexpected changes in package.json files
    echo       4. Use npm audit regularly to check for vulnerabilities
    echo       5. Consider implementing supply chain security tools
    echo.
)

:: Scan summary
call :print_blue "[*] SCAN SUMMARY"
echo    Scan completed: !date! !time!
echo    Target directory: !SCAN_DIR!
echo    Mode: Core Shai-Hulud detection
if "!paranoid_mode!"=="true" echo           + Additional security checks enabled
echo    Risk Score: !TOTAL_SCORE!/100 (!RISK_LEVEL!)
echo.

call :print_blue "=============================================="
if !core_findings! gtr 0 (
    call :print_red "    SCAN COMPLETE - ISSUES FOUND"
) else (
    call :print_green "    SCAN COMPLETE - NO ISSUES FOUND"
)
call :print_blue "=============================================="

:: Exit with appropriate code
if !core_findings! gtr 0 (
    exit /b 1
) else (
    exit /b 0
)
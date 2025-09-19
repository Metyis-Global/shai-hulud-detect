@echo off
setlocal enabledelayedexpansion
cls

:: Shai-Hulud NPM Supply Chain Attack Detection Script
:: Version: 4.0.0 - Full Feature Parity with Shell Script
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
set /a CRYPTO_PATTERNS_COUNT=0

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
call :print_blue "    Version 4.0.0 - Full Feature Parity"
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
call :check_crypto_theft_patterns "!SCAN_DIR!"
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
    echo    Analyzing package entries and filtering valid patterns...
    set /a temp_count=0
    set /a valid_entries=0
    set /a skipped_comments=0
    set /a skipped_empty=0
    
    :: Read file line by line with enhanced parsing
    for /f "usebackq delims=" %%a in ("!packages_file!") do (
        set "line=%%a"
        set /a temp_count+=1
        
        :: Skip empty lines and lines starting with #
        set "first_char=!line:~0,1!"
        if "!first_char!"=="#" (
            set /a skipped_comments+=1
        ) else if "!line!"=="" (
            set /a skipped_empty+=1
        ) else (
            :: Enhanced validation - check for proper package:version pattern
            set "test_line=!line!"
            set "test_line=!test_line::=COLON!"
            if not "!test_line!"=="!line!" (
                :: Further validate that it matches package name pattern
                echo "!line!" | findstr /r "^[a-zA-Z@][^:]*:[0-9][0-9]*\.[0-9][0-9]*\.[0-9]" >nul 2>&1
                if not errorlevel 1 (
                    :: Valid package line found
                    set /a valid_entries+=1
                    set "COMPROMISED_PACKAGES[!valid_entries!]=!line!"
                    
                    :: Show progress using progressive intervals like shell script
                    if !valid_entries! leq 20 (
                        set /a mod=!valid_entries!%%10
                        if !mod! equ 0 echo       [+] !valid_entries! packages loaded...
                    ) else (
                        if !valid_entries! leq 100 (
                            set /a mod=!valid_entries!%%20
                            if !mod! equ 0 echo       [+] !valid_entries! packages loaded...
                        ) else (
                            if !valid_entries! leq 500 (
                                set /a mod=!valid_entries!%%50
                                if !mod! equ 0 echo       [+] !valid_entries! packages loaded...
                            ) else (
                                set /a mod=!valid_entries!%%100
                                if !mod! equ 0 echo       [+] !valid_entries! packages loaded...
                            )
                        )
                    )
                )
        )
    )
    
    set /a COMPROMISED_PACKAGES_COUNT=!valid_entries!
    call :print_blue "[+] Loaded !COMPROMISED_PACKAGES_COUNT! compromised packages from compromised-packages.txt"
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
        
        :: Enhanced approach - check against full compromised package database
        :: Process all loaded compromised packages
        for /l %%p in (1,1,!COMPROMISED_PACKAGES_COUNT!) do (
            set "package_entry=!COMPROMISED_PACKAGES[%%p]!"
            
            :: Split package entry into name and version
            for /f "tokens=1,2 delims=:" %%x in ("!package_entry!") do (
                set "package_name=%%x"
                set "malicious_version=%%y"
                
                :: Check if package.json contains this package name
                findstr /c:"\"!package_name!\"" "!current_file!" >nul 2>&1
                if not errorlevel 1 (
                    :: Check for exact version match
                    findstr /c:"\"!package_name!\": \"!malicious_version!\"" "!current_file!" >nul 2>&1
                    if not errorlevel 1 (
                        set /a COMPROMISED_FOUND_COUNT+=1
                        set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:!package_name!@!malicious_version!"
                        echo       [!] FOUND compromised package: !package_name!@!malicious_version!
                    ) else (
                        :: Check for range patterns like "^4.1.0" or "~4.1.0"
                        findstr /c:"\"!package_name!\": \"^!malicious_version!\"" "!current_file!" >nul 2>&1
                        if not errorlevel 1 (
                            set /a COMPROMISED_FOUND_COUNT+=1
                            set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:!package_name!@^!malicious_version!"
                            echo       [!] FOUND compromised package range: !package_name!@^!malicious_version!
                        ) else (
                            findstr /c:"\"!package_name!\": \"~!malicious_version!\"" "!current_file!" >nul 2>&1
                            if not errorlevel 1 (
                                set /a COMPROMISED_FOUND_COUNT+=1
                                set "COMPROMISED_FOUND[!COMPROMISED_FOUND_COUNT!]=!current_file!:!package_name!@~!malicious_version!"
                                echo       [!] FOUND compromised package range: !package_name!@~!malicious_version!
                            )
                        )
                    )
                )
            )
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

:check_crypto_theft_patterns
set "scan_dir=%~1"
call :print_blue "[-] Checking for cryptocurrency theft patterns (Chalk/Debug Sept 8, 2025 attack)..."
echo    Analyzing files for wallet address replacement and crypto manipulation...

set /a crypto_files_scanned=0
set /a initial_crypto_count=!CRYPTO_PATTERNS_COUNT!

:: Change to scan directory
cd /d "!scan_dir!" 2>nul
if not errorlevel 1 (
    :: Use temp file to find JS/TS/JSON files for crypto pattern scanning
    set "temp_crypto_file=shai_hulud_crypto.tmp"
    dir /s /b *.js *.ts *.json 2>nul > "!temp_crypto_file!"
    
    if exist "!temp_crypto_file!" (
        for /f "usebackq delims=" %%f in ("!temp_crypto_file!") do (
            if exist "%%f" (
                set /a crypto_files_scanned+=1
                
                :: Check for Ethereum wallet address patterns (0x followed by 40 hex chars)
                findstr /r "0x[a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    :: Also check if file mentions ethereum, wallet, address, or crypto
                    findstr /i "ethereum wallet address crypto" "%%f" >nul 2>&1
                    if not errorlevel 1 (
                        set /a CRYPTO_PATTERNS_COUNT+=1
                        set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Ethereum wallet address patterns detected"
                        echo       [!] FOUND Ethereum wallet patterns in: %%f
                    )
                )
                
                :: Check for XMLHttpRequest hijacking
                findstr /c:"XMLHttpRequest.prototype.send" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:XMLHttpRequest prototype modification detected - HIGH RISK"
                    echo       [!] CRITICAL: XMLHttpRequest hijacking in: %%f
                )
                
                :: Check for specific malicious functions from chalk/debug attack
                findstr /i "checkethereumw runmask newdlocal _0x19ca67" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Known crypto theft function names detected - HIGH RISK"
                    echo       [!] CRITICAL: Known crypto theft functions in: %%f
                )
                
                :: Check for known attacker wallets (HIGH RISK)
                findstr /c:"0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Known attacker Ethereum wallet detected - HIGH RISK"
                    echo       [!] CRITICAL: Known attacker wallet in: %%f
                )
                
                findstr /c:"1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Known attacker Bitcoin wallet detected - HIGH RISK"
                    echo       [!] CRITICAL: Known attacker Bitcoin wallet in: %%f
                )
                
                findstr /c:"TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Known attacker Bitcoin testnet wallet detected - HIGH RISK"
                    echo       [!] CRITICAL: Known attacker testnet wallet in: %%f
                )
                
                :: Check for npmjs.help phishing domain
                findstr /c:"npmjs.help" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Phishing domain npmjs.help detected - HIGH RISK"
                    echo       [!] CRITICAL: Phishing domain npmjs.help in: %%f
                )
                
                :: Check for javascript obfuscation patterns
                findstr /c:"javascript-obfuscator" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:JavaScript obfuscation detected"
                    echo       [!] WARNING: JavaScript obfuscation in: %%f
                )
                
                :: Check for cryptocurrency address regex patterns
                findstr /r "ethereum.*0x\[a-fA-F0-9\]" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Cryptocurrency regex patterns detected"
                    echo       [!] WARNING: Crypto regex patterns in: %%f
                )
                
                :: Check for Bitcoin address patterns
                findstr /r "bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]" "%%f" >nul 2>&1
                if not errorlevel 1 (
                    set /a CRYPTO_PATTERNS_COUNT+=1
                    set "CRYPTO_PATTERNS[!CRYPTO_PATTERNS_COUNT!]=%%f:Bitcoin address regex patterns detected"
                    echo       [!] WARNING: Bitcoin regex patterns in: %%f
                )
            )
        )
        del "!temp_crypto_file!" 2>nul
    ) else (
        echo    No JavaScript/TypeScript/JSON files found for crypto pattern scanning
    )
)

:: Change back to script directory
cd /d "%~dp0"

set /a crypto_matches=!CRYPTO_PATTERNS_COUNT!-!initial_crypto_count!
echo    Scanned !crypto_files_scanned! files for cryptocurrency theft patterns

if !crypto_matches! gtr 0 (
    call :print_red "   [!] Found !crypto_matches! cryptocurrency theft pattern(s)!"
    echo    These patterns may indicate crypto wallet hijacking malware
) else (
    call :print_green "   [OK] No cryptocurrency theft patterns detected"
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
:: Enhanced helper function to determine file context for risk assessment
set "file_path=%~1"
set "file_context=unknown"

:: Check if file is in node_modules (highest priority for dependency context)
echo !file_path! | findstr /i "node_modules" >nul 2>&1
if not errorlevel 1 (
    set "file_context=node_modules"
    goto :eof
)

:: Check if file is documentation
echo !file_path! | findstr /i "\.md$ \.txt$ \.rst$ readme changelog license" >nul 2>&1
if not errorlevel 1 (
    set "file_context=documentation"
    goto :eof
)

:: Check if file is TypeScript definitions
echo !file_path! | findstr /i "\.d\.ts$" >nul 2>&1
if not errorlevel 1 (
    set "file_context=type_definitions"
    goto :eof
)

:: Check if file is in build/dist/public directories
echo !file_path! | findstr /i "\\dist\\ \\build\\ \\public\\ \\out\\ \\target\\" >nul 2>&1
if not errorlevel 1 (
    set "file_context=build_output"
    goto :eof
)

:: Check if file is in test directories
echo !file_path! | findstr /i "test spec \.test\. \.spec\. __test__ __spec__ \\tests\\ \\test\\" >nul 2>&1
if not errorlevel 1 (
    set "file_context=test"
    goto :eof
)

:: Check if it's a config file
for %%f in ("!file_path!") do set "filename=%%~nxf"
echo !filename! | findstr /i "config webpack rollup vite babel eslint" >nul 2>&1
if not errorlevel 1 (
    set "file_context=configuration"
    goto :eof
)

:: Check for package.json or other package files
echo !filename! | findstr /i "package\.json package-lock\.json yarn\.lock" >nul 2>&1
if not errorlevel 1 (
    set "file_context=package_manifest"
    goto :eof
)

:: Check if file is a security/audit tool
echo !file_path! | findstr /i "security scanner audit scan detect trufflehog" >nul 2>&1
if not errorlevel 1 (
    :: Check file content for legitimate security tool patterns (if file exists and readable)
    if exist "!file_path!" (
        findstr /i "security.*tool legitimate.*scan audit.*report" "!file_path!" >nul 2>&1
        if not errorlevel 1 (
            set "file_context=security_tool"
            goto :eof
        )
    )
    set "file_context=potential_security_tool"
    goto :eof
)

:: Check if file is vendor/third-party code
echo !file_path! | findstr /i "vendor third-party libs library libraries" >nul 2>&1
if not errorlevel 1 (
    set "file_context=vendor"
    goto :eof
)

:: Default to source code
set "file_context=source_code"
goto :eof

:: Helper function to check for legitimate patterns (enhanced)
:is_legitimate_pattern
set "file_path=%~1"
set "content_sample=%~2"
set "is_legitimate=0"

:: Vue.js development patterns
echo !content_sample! | findstr /i "process\.env\.NODE_ENV.*production" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Common framework patterns
echo !content_sample! | findstr /i "createApp Vue React Angular" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Package manager and build tool patterns
echo !content_sample! | findstr /i "webpack vite rollup parcel esbuild" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Testing framework patterns
echo !content_sample! | findstr /i "jest mocha jasmine cypress playwright" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Development server patterns
echo !content_sample! | findstr /i "webpack-dev-server vite.*dev next.*dev" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Environment configuration patterns
echo !content_sample! | findstr /i "dotenv config.*env DefinePlugin" >nul 2>&1
if not errorlevel 1 (
    set "is_legitimate=1"
    goto :eof
)

:: Default to potentially suspicious
set "is_legitimate=0"
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
        
        :: Check for trufflehog references with enhanced context analysis
        findstr /i "trufflehog TruffleHog" "%%f" >nul 2>&1
        if not errorlevel 1 (
            call :get_file_context "%%f"
            
            :: Get content sample for pattern analysis
            set "content_sample="
            if exist "%%f" (
                for /f "usebackq delims=" %%l in ('"%%f"') do (
                    set "content_sample=!content_sample! %%l"
                    goto :break_content_loop
                )
                :break_content_loop
            )
            
            if "!file_context!"=="documentation" (
                :: Documentation mentioning trufflehog is usually legitimate
                rem Skip - not a security risk
            ) else if "!file_context!"=="node_modules" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Contains trufflehog references in node_modules"
            ) else if "!file_context!"=="type_definitions" (
                :: Type definitions mentioning trufflehog are usually legitimate
                rem Skip - not a security risk
            ) else if "!file_context!"=="build_output" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Trufflehog references in build output"
            ) else if "!file_context!"=="security_tool" (
                set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:LOW:Legitimate security tool"
            ) else if "!file_context!"=="test" (
                :: Skip test files - usually legitimate
                rem Test files are not a security risk
            ) else (
                :: Source code with trufflehog references needs investigation
                echo !content_sample! | findstr /i "subprocess.*curl https\.request" >nul 2>&1
                if not errorlevel 1 (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:HIGH:Suspicious trufflehog execution pattern"
                    echo       [!] CRITICAL: Trufflehog with execution patterns: %%f
                ) else (
                    set /a TRUFFLEHOG_ACTIVITY_COUNT+=1
                    set "TRUFFLEHOG_ACTIVITY[!TRUFFLEHOG_ACTIVITY_COUNT!]=%%f:MEDIUM:Contains trufflehog references in source code"
                    echo       [!] WARNING: Trufflehog reference in source: %%f
                )
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

echo    Analyzing package names for advanced typosquatting patterns...
echo    Checking for homoglyph attacks, character substitutions, and namespace confusion...
echo    Comparing against popular packages for typosquatting attempts...

set /a packages_checked=0

:: Popular packages commonly targeted for typosquatting (expanded list)
set "popular[1]=react"
set "popular[2]=vue"
set "popular[3]=angular"
set "popular[4]=express"
set "popular[5]=lodash"
set "popular[6]=axios"
set "popular[7]=typescript"
set "popular[8]=webpack"
set "popular[9]=babel"
set "popular[10]=eslint"
set "popular[11]=jest"
set "popular[12]=mocha"
set "popular[13]=chalk"
set "popular[14]=debug"
set "popular[15]=commander"
set "popular[16]=inquirer"
set "popular[17]=yargs"
set "popular[18]=request"
set "popular[19]=moment"
set "popular[20]=underscore"
set "popular[21]=jquery"
set "popular[22]=bootstrap"
set "popular[23]=redis"
set "popular[24]=mongoose"
set "popular[25]=passport"
set /a popular_count=25

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
            echo    Scanning: %%~nxf for typosquatting patterns...
            
            :: Extract package names from dependencies sections using enhanced approach
            call :extract_and_check_packages "%%f"
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
    echo    Advanced pattern analysis completed on !packages_checked! package.json files
) else (
    call :print_green "   [OK] No typosquatting patterns detected"
    echo    Advanced analysis completed on !packages_checked! package.json files
)
goto :eof

:extract_and_check_packages
set "package_file=%~1"

:: Use temp file to extract just the package names
set "temp_pkg_names=shai_hulud_pkg_names.tmp"
findstr /r "^[[:space:]]*\"[^\"]*\"[[:space:]]*:" "!package_file!" > "!temp_pkg_names!" 2>nul

if exist "!temp_pkg_names!" (
    for /f "usebackq tokens=* delims=" %%p in ("!temp_pkg_names!") do (
        set "line=%%p"
        :: Extract package name between quotes
        for /f "tokens=2 delims=:" %%n in ("!line!") do (
            set "raw_name=%%n"
            :: Remove quotes and spaces
            set "package_name=!raw_name:"=!"
            set "package_name=!package_name: =!"
            
            :: Only process if it looks like a package name
            if not "!package_name!"=="" (
                call :check_package_for_typosquatting "!package_file!" "!package_name!"
            )
        )
    )
    del "!temp_pkg_names!" 2>nul
)
goto :eof

:check_package_for_typosquatting
set "file_path=%~1"
set "package_name=%~2"

:: Skip if package name is too short or contains no letters
call :strlen pkg_len "!package_name!"
if !pkg_len! lss 2 goto :eof

:: Check for Unicode/non-ASCII characters (simplified detection)
echo !package_name! | findstr /r "[^a-zA-Z0-9@/._-]" >nul 2>&1
if not errorlevel 1 (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential Unicode/homoglyph characters in package: !package_name!"
)

:: Check for confusable character patterns
call :check_confusables_in_package "!file_path!" "!package_name!"

:: Check against popular packages for similarity
for /l %%i in (1,1,!popular_count!) do (
    call :check_similarity "!file_path!" "!package_name!" "!popular[%%i]!"
)

:: Check for namespace confusion (scoped packages)
echo !package_name! | findstr /r "^@" >nul 2>&1
if not errorlevel 1 (
    call :check_namespace_confusion "!file_path!" "!package_name!"
)

goto :eof

:check_confusables_in_package
set "file_path=%~1"
set "package_name=%~2"

:: Check for rn->m confusion
set "test_name=!package_name:rn=m!"
if not "!test_name!"=="!package_name!" (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential confusable characters (rn->m) in package: !package_name!"
)

:: Check for vv->w confusion
set "test_name=!package_name:vv=w!"
if not "!test_name!"=="!package_name!" (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential confusable characters (vv->w) in package: !package_name!"
)

:: Check for cl->d confusion
set "test_name=!package_name:cl=d!"
if not "!test_name!"=="!package_name!" (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential confusable characters (cl->d) in package: !package_name!"
)

:: Check for l->1 confusion
set "test_name=!package_name:l=1!"
if not "!test_name!"=="!package_name!" (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential confusable characters (l->1) in package: !package_name!"
)

:: Check for 0->o confusion
set "test_name=!package_name:0=o!"
if not "!test_name!"=="!package_name!" (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential confusable characters (0->o) in package: !package_name!"
)

goto :eof

:check_similarity
set "file_path=%~1"
set "package_name=%~2"
set "popular_name=%~3"

:: Skip exact matches
if "!package_name!"=="!popular_name!" goto :eof

:: Skip common legitimate variations
if "!package_name!"=="test" goto :eof
if "!package_name!"=="tests" goto :eof
if "!package_name!"=="testing" goto :eof
if "!package_name!"=="types" goto :eof
if "!package_name!"=="util" goto :eof
if "!package_name!"=="utils" goto :eof
if "!package_name!"=="core" goto :eof
if "!package_name!"=="lib" goto :eof
if "!package_name!"=="libs" goto :eof
if "!package_name!"=="common" goto :eof
if "!package_name!"=="shared" goto :eof

:: Get string lengths
call :strlen pkg_len "!package_name!"
call :strlen pop_len "!popular_name!"

:: Check for single character difference (only for packages > 4 chars)
if !pkg_len! equ !pop_len! if !pkg_len! gtr 4 (
    call :check_one_char_diff "!package_name!" "!popular_name!"
    if !char_diff! equ 1 (
        :: Additional check - avoid flagging if it contains common variations
        echo !package_name! | findstr /r ".*-.*" >nul 2>&1
        if errorlevel 1 (
            echo !popular_name! | findstr /r ".*-.*" >nul 2>&1
            if errorlevel 1 (
                set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential typosquatting of '!popular_name!': !package_name! (1 character difference)"
            )
        )
    )
)

:: Check for missing character
set /a missing_len=!pop_len!-1
if !pkg_len! equ !missing_len! (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential typosquatting of '!popular_name!': !package_name! (missing character)"
)

:: Check for extra character
set /a extra_len=!pop_len!+1
if !pkg_len! equ !extra_len! (
    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Potential typosquatting of '!popular_name!': !package_name! (extra character)"
)

goto :eof

:check_namespace_confusion
set "file_path=%~1"
set "scoped_package=%~2"

:: Extract namespace and package parts
for /f "tokens=1 delims=/" %%n in ("!scoped_package!") do set "namespace=%%n"
for /f "tokens=2 delims=/" %%p in ("!scoped_package!/dummy") do set "package_part=%%p"

:: Common namespaces that are often targeted
set "suspicious_ns[1]=@types"
set "suspicious_ns[2]=@angular"
set "suspicious_ns[3]=@typescript"
set "suspicious_ns[4]=@react"
set "suspicious_ns[5]=@vue"
set "suspicious_ns[6]=@babel"
set /a suspicious_ns_count=6

for /l %%i in (1,1,!suspicious_ns_count!) do (
    if not "!namespace!"=="!suspicious_ns[%%i]!" (
        :: Check if namespace is similar to a legitimate one
        echo !namespace! | findstr /i "!suspicious_ns[%%i]:@=!" >nul 2>&1
        if not errorlevel 1 (
            call :strlen ns_len "!namespace!"
            call :strlen sus_len "!suspicious_ns[%%i]!"
            if !ns_len! equ !sus_len! (
                call :check_one_char_diff "!namespace!" "!suspicious_ns[%%i]!"
                if !char_diff! geq 1 if !char_diff! leq 2 (
                    set /a TYPOSQUATTING_WARNINGS_COUNT+=1
                    set "TYPOSQUATTING_WARNINGS[!TYPOSQUATTING_WARNINGS_COUNT!]=!file_path!:Suspicious namespace variation: !namespace! (similar to !suspicious_ns[%%i]!)"
                )
            )
        )
    )
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

:: Change to scan directory and use temp file approach  
cd /d "!scan_dir!" 2>nul
if errorlevel 1 goto :skip_network_exfiltration

:: Use temp file to find JS/TS/JSON files
set "temp_network_file=shai_hulud_network.tmp"
dir /s /b *.js *.ts *.json *.mjs 2>nul > "!temp_network_file!"

if exist "!temp_network_file!" (
    for /f "usebackq delims=" %%f in ("!temp_network_file!") do (
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
    del "!temp_network_file!" 2>nul
) else (
    echo    No JavaScript/TypeScript/JSON files found
)

:: Change back to script directory
cd /d "%~dp0"

:skip_network_exfiltration
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
        call :show_file_preview "!WORKFLOW_FILES[%%i]!"
        set /a high_risk+=1
    )
    call :print_yellow "   NOTE: 'shai-hulud-workflow.yml' files are used by the malware to automate propagation."
    call :print_yellow "   These files should be immediately removed from your repository."
    echo.
)

:: Report malicious file hashes
if !MALICIOUS_HASHES_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Files with known malicious hashes:"
    for /l %%i in (1,1,!MALICIOUS_HASHES_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!MALICIOUS_HASHES[%%i]!") do (
            echo    - %%a
            echo      Hash: %%b
            call :show_file_preview "%%a"
        )
        set /a high_risk+=1
    )
    call :print_yellow "   NOTE: These files match known malicious signatures from the Shai-Hulud attack."
    call :print_yellow "   Delete these files immediately and scan for additional compromised files."
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

:: Report cryptocurrency theft patterns
if !CRYPTO_PATTERNS_COUNT! gtr 0 (
    :: Separate HIGH RISK and MEDIUM RISK crypto patterns
    set /a crypto_high_count=0
    set /a crypto_medium_count=0
    
    for /l %%i in (1,1,!CRYPTO_PATTERNS_COUNT!) do (
        echo !CRYPTO_PATTERNS[%%i]! | findstr /i "HIGH RISK XMLHttpRequest Known.*attacker npmjs.help" >nul 2>&1
        if not errorlevel 1 (
            set /a crypto_high_count+=1
            set "CRYPTO_HIGH[!crypto_high_count!]=!CRYPTO_PATTERNS[%%i]!"
        ) else (
            set /a crypto_medium_count+=1
            set "CRYPTO_MEDIUM[!crypto_medium_count!]=!CRYPTO_PATTERNS[%%i]!"
        )
    )
    
    :: Report HIGH RISK crypto patterns
    if !crypto_high_count! gtr 0 (
        call :print_red "[!] HIGH RISK: Cryptocurrency theft patterns detected:"
        for /l %%i in (1,1,!crypto_high_count!) do (
            for /f "tokens=1,2 delims=:" %%a in ("!CRYPTO_HIGH[%%i]!") do (
                echo    - %%b
                echo      Found in: %%a
            )
            set /a high_risk+=1
        )
        call :print_red "   NOTE: These patterns strongly indicate crypto theft malware from the September 8 attack."
        call :print_red "   Immediate investigation and remediation required."
        echo.
    )
    
    :: Report MEDIUM RISK crypto patterns
    if !crypto_medium_count! gtr 0 (
        call :print_yellow "[!] MEDIUM RISK: Potential cryptocurrency manipulation patterns:"
        for /l %%i in (1,1,!crypto_medium_count!) do (
            for /f "tokens=1,2 delims=:" %%a in ("!CRYPTO_MEDIUM[%%i]!") do (
                echo    - %%b
                echo      Found in: %%a
            )
            set /a medium_risk+=1
        )
        call :print_yellow "   NOTE: These may be legitimate crypto tools or framework code."
        call :print_yellow "   Manual review recommended to determine if they are malicious."
        echo.
    )
)

:: Report git branches
if !GIT_BRANCHES_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK: Suspicious git branches:"
    for /l %%i in (1,1,!GIT_BRANCHES_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!GIT_BRANCHES[%%i]!") do (
            echo    - Repository: %%a
            echo      %%b
            echo      +- Git Investigation Commands:
            echo      ^|  cd "%%a"
            echo      ^|  git log --oneline -10 shai-hulud
            echo      ^|  git show shai-hulud
            echo      ^|  git diff main...shai-hulud
            echo      +-
            echo.
        )
        set /a medium_risk+=1
    )
    call :print_yellow "   NOTE: 'shai-hulud' branches may indicate compromise."
    echo    Use the commands above to investigate each branch.
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

:: Report Trufflehog activity by risk level
set /a trufflehog_high_count=0
set /a trufflehog_medium_count=0
set /a trufflehog_low_count=0

:: Categorize Trufflehog findings by risk level
for /l %%i in (1,1,!TRUFFLEHOG_ACTIVITY_COUNT!) do (
    for /f "tokens=1,2,3 delims=:" %%a in ("!TRUFFLEHOG_ACTIVITY[%%i]!") do (
        if "%%b"=="HIGH" (
            set /a trufflehog_high_count+=1
            set "TRUFFLEHOG_HIGH[!trufflehog_high_count!]=%%a:%%c"
        )
        if "%%b"=="MEDIUM" (
            set /a trufflehog_medium_count+=1
            set "TRUFFLEHOG_MEDIUM[!trufflehog_medium_count!]=%%a:%%c"
        )
        if "%%b"=="LOW" (
            set /a trufflehog_low_count+=1
            set "TRUFFLEHOG_LOW[!trufflehog_low_count!]=%%a:%%c"
        )
    )
)

:: Report HIGH RISK Trufflehog activity
if !trufflehog_high_count! gtr 0 (
    call :print_red "[!] HIGH RISK: Trufflehog/secret scanning activity detected:"
    for /l %%i in (1,1,!trufflehog_high_count!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!TRUFFLEHOG_HIGH[%%i]!") do (
            echo    - Activity: %%b
            echo      Found in: %%a
        )
        set /a high_risk+=1
    )
    echo    NOTE: These patterns indicate likely malicious credential harvesting.
    echo    Immediate investigation and remediation required.
    echo.
)

:: Report MEDIUM RISK Trufflehog activity
if !trufflehog_medium_count! gtr 0 (
    call :print_yellow "[!] MEDIUM RISK: Potentially suspicious secret scanning patterns:"
    for /l %%i in (1,1,!trufflehog_medium_count!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!TRUFFLEHOG_MEDIUM[%%i]!") do (
            echo    - Pattern: %%b
            echo      Found in: %%a
        )
        set /a medium_risk+=1
    )
    echo    NOTE: These may be legitimate security tools or framework code.
    echo    Manual review recommended to determine if they are malicious.
    echo.
)

:: Store LOW RISK findings for optional reporting
for /l %%i in (1,1,!trufflehog_low_count!) do (
    for /f "tokens=1,2 delims=:" %%a in ("!TRUFFLEHOG_LOW[%%i]!") do (
        set /a LOW_RISK_FINDINGS_COUNT+=1
        set "LOW_RISK_FINDINGS[!LOW_RISK_FINDINGS_COUNT!]=Trufflehog pattern: %%a:%%b"
    )
)

:: Report Shai-Hulud repositories
if !SHAI_HULUD_REPOS_COUNT! gtr 0 (
    call :print_red "[!] HIGH RISK: Shai-Hulud repositories detected:"
    for /l %%i in (1,1,!SHAI_HULUD_REPOS_COUNT!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!SHAI_HULUD_REPOS[%%i]!") do (
            echo    - Repository: %%a
            echo      %%b
            echo      +- Repository Investigation Commands:
            echo      ^|  cd "%%a"
            echo      ^|  git log --oneline -10
            echo      ^|  git remote -v
            echo      ^|  dir /a
            echo      +-
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
    call :print_yellow "   NOTE: These namespaces were compromised in the Shai-Hulud attack."
    call :print_yellow "   Not all packages in these namespaces are malicious, but they require review."
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
    call :print_yellow "   NOTE: Lockfile modifications may indicate unauthorized package changes."
    call :print_yellow "   Review your package-lock.json and yarn.lock files for unexpected modifications."
    echo.
)

:: Report typosquatting warnings (only in paranoid mode)
if "!paranoid_mode!"=="true" if !TYPOSQUATTING_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK (PARANOID): Potential typosquatting attacks detected:"
    set /a max_show=5
    if !TYPOSQUATTING_WARNINGS_COUNT! lss !max_show! set /a max_show=!TYPOSQUATTING_WARNINGS_COUNT!
    
    for /l %%i in (1,1,!max_show!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!TYPOSQUATTING_WARNINGS[%%i]!") do (
            echo    - Warning: %%b
            echo      Found in: %%a
        )
    )
    
    set /a remaining=!TYPOSQUATTING_WARNINGS_COUNT!-!max_show!
    if !remaining! gtr 0 (
        echo    ...and !remaining! more typosquatting warnings
    )
    
    set /a medium_risk=!medium_risk!+!TYPOSQUATTING_WARNINGS_COUNT!
    echo.
)

:: Report network exfiltration warnings (only in paranoid mode)
if "!paranoid_mode!"=="true" if !NETWORK_EXFILTRATION_WARNINGS_COUNT! gtr 0 (
    call :print_yellow "[!]  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
    set /a max_show=5
    if !NETWORK_EXFILTRATION_WARNINGS_COUNT! lss !max_show! set /a max_show=!NETWORK_EXFILTRATION_WARNINGS_COUNT!
    
    for /l %%i in (1,1,!max_show!) do (
        for /f "tokens=1,2 delims=:" %%a in ("!NETWORK_EXFILTRATION_WARNINGS[%%i]!") do (
            echo    - Warning: %%b
            echo      Found in: %%a
        )
    )
    
    set /a remaining=!NETWORK_EXFILTRATION_WARNINGS_COUNT!-!max_show!
    if !remaining! gtr 0 (
        echo    ...and !remaining! more network exfiltration warnings
    )
    
    set /a medium_risk=!medium_risk!+!NETWORK_EXFILTRATION_WARNINGS_COUNT!
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


:check_shai_hulud_repos
set "scan_dir=%~1"
call :print_blue "[-] Checking for Shai-Hulud repositories and migration patterns..."

set /a initial_repos_count=!SHAI_HULUD_REPOS_COUNT!

:: Look for .git directories using temp file approach
cd /d "!scan_dir!" 2>nul
if not errorlevel 1 (
    set "temp_git_file=shai_hulud_git.tmp"
    dir /s /b /a:d .git 2>nul > "!temp_git_file!"
    
    if exist "!temp_git_file!" (
        for /f "usebackq delims=" %%d in ("!temp_git_file!") do (
            set "git_dir=%%d"
            for %%p in ("!git_dir!\..") do set "repo_dir=%%~fp"
            
            :: Get repository name
            for %%r in ("!repo_dir!\.") do set "repo_name=%%~nr"
            
            :: Check if repository name contains shai-hulud
            echo !repo_name! | findstr /i "shai-hulud" >nul 2>&1
            if not errorlevel 1 (
                set /a SHAI_HULUD_REPOS_COUNT+=1
                set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Repository name contains 'Shai-Hulud'"
                echo       [!] FOUND Shai-Hulud repository: !repo_dir!
            )
            
            :: Check for migration pattern
            echo !repo_name! | findstr /i "migration" >nul 2>&1
            if not errorlevel 1 (
                set /a SHAI_HULUD_REPOS_COUNT+=1
                set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Repository name contains migration pattern"
                echo       [!] FOUND migration pattern repository: !repo_dir!
            )
            
            :: Check git config for shai-hulud remotes
            if exist "!git_dir!\config" (
                findstr /i "shai-hulud" "!git_dir!\config" >nul 2>&1
                if not errorlevel 1 (
                    set /a SHAI_HULUD_REPOS_COUNT+=1
                    set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Git remote contains 'Shai-Hulud'"
                    echo       [!] FOUND Shai-Hulud git remote in: !repo_dir!
                )
            )
            
            :: Check for suspicious data.json
            if exist "!repo_dir!\data.json" (
                findstr /c:"eyJ" "!repo_dir!\data.json" >nul 2>&1
                if not errorlevel 1 (
                    findstr /c:"==" "!repo_dir!\data.json" >nul 2>&1
                    if not errorlevel 1 (
                        set /a SHAI_HULUD_REPOS_COUNT+=1
                        set "SHAI_HULUD_REPOS[!SHAI_HULUD_REPOS_COUNT!]=!repo_dir!:Contains suspicious data.json (possible base64-encoded credentials)"
                        echo       [!] FOUND suspicious data.json in: !repo_dir!
                    )
                )
            )
        )
        del "!temp_git_file!" 2>nul
    )
)
cd /d "%~dp0"

set /a repo_matches=!SHAI_HULUD_REPOS_COUNT!-!initial_repos_count!
if !repo_matches! gtr 0 (
    call :print_yellow "   [FOUND] !repo_matches! suspicious repository pattern(s) detected!"
) else (
    call :print_green "   [OK] No suspicious repository patterns detected"
)
goto :eof
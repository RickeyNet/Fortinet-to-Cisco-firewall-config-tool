@echo off
REM =========================================================================
REM  Build FortiGate Firewall Migration Tool as a standalone Windows .exe
REM =========================================================================
REM  Usage:
REM    build.bat              - builds using the version in gui_app.py
REM    build.bat 1.2.3        - sets the version to 1.2.3, then builds
REM
REM  Prerequisites:
REM    - Python 3.14 (via py launcher)
REM    - Internet access (first run only, to install dependencies)
REM
REM  Output:
REM    dist\Firewall-Migration-Tool.exe
REM =========================================================================

echo.
echo ============================================================
echo   FortiGate Firewall Migration Tool - Build Script
echo ============================================================
echo.

REM ---------- Resolve version ----------
REM Always read the current version from gui_app.py first, so a command-line
REM override can be restored after the build (mirrors build_profile.py).
set "ORIG_VERSION="
for /f "tokens=3 delims= " %%A in ('findstr /R "^APP_VERSION" "%~dp0gui_app.py"') do (
    set "ORIG_VERSION=%%~A"
)

set "APP_VERSION="
set "VERSION_PATCHED="
if not "%~1"=="" (
    set "APP_VERSION=%~1"
)

REM If a version was supplied on the command line, patch gui_app.py
if defined APP_VERSION (
    echo [0/3] Temporarily setting version to %APP_VERSION% ...
    powershell -Command "(Get-Content '%~dp0gui_app.py') -replace 'APP_VERSION = \"[^\"]*\"', 'APP_VERSION = \"%APP_VERSION%\"' | Set-Content '%~dp0gui_app.py'"
    set "VERSION_PATCHED=1"
    echo       Done.
    echo.
) else (
    set "APP_VERSION=%ORIG_VERSION%"
)

echo       Building version: %APP_VERSION%
echo.

REM Install dependencies if needed
echo [1/3] Installing dependencies (Python 3.14)...
py -3.14 -m pip install pyyaml requests urllib3 pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [WARN] pip install had warnings - continuing anyway...
)
echo       Done.
echo.

REM Stay in repo root where gui_app.py lives
cd /d "%~dp0"

REM ---------- Generate version-info file for Windows exe metadata ----------
REM Normalize the version to a 4-part integer tuple for filevers/prodvers
REM (mirrors build_profile.py version_tuple: leading digits per token else 0,
REM pad with zeros to 4 parts, truncate past 4).
set "FILEVERS="
for /f "usebackq delims=" %%V in (`powershell -NoProfile -Command "$p = '%APP_VERSION%'.Split('.') | ForEach-Object { if ($_ -match '^\d+') { [int]$Matches[0] } else { 0 } }; $p = @($p); while ($p.Count -lt 4) { $p += 0 }; ($p[0..3] -join ', ')"`) do set "FILEVERS=%%V"
if not defined FILEVERS set "FILEVERS=0, 0, 0, 0"

(
echo VSVersionInfo^(
echo   ffi=FixedFileInfo^(
echo     filevers=^(%FILEVERS%^),
echo     prodvers=^(%FILEVERS%^),
echo     mask=0x3f,
echo     flags=0x0,
echo     OS=0x40004,
echo     fileType=0x1,
echo     subtype=0x0,
echo     date=^(0, 0^)
echo   ^),
echo   kids=[
echo     StringFileInfo^(
echo       [
echo         StringTable^(
echo           u'040904B0',
echo           [
echo             StringStruct^(u'CompanyName', u''^),
echo             StringStruct^(u'FileDescription', u'Firewall Migration Tool'^),
echo             StringStruct^(u'FileVersion', u'%APP_VERSION%'^),
echo             StringStruct^(u'InternalName', u'Firewall-Migration-Tool'^),
echo             StringStruct^(u'OriginalFilename', u'Firewall-Migration-Tool.exe'^),
echo             StringStruct^(u'ProductName', u'Firewall Migration Tool'^),
echo             StringStruct^(u'ProductVersion', u'%APP_VERSION%'^),
echo           ]
echo         ^)
echo       ]
echo     ^),
echo     VarFileInfo^([VarStruct^(u'Translation', [1033, 1200]^)]^)
echo   ]
echo ^)
) > version_info.txt

echo [2/3] Building executable with PyInstaller...
echo       This may take a minute...
echo.

py -3.14 -m PyInstaller --onefile --windowed ^
    --name "Firewall-Migration-Tool-v%APP_VERSION%" ^
    --icon "app_icon.ico" ^
    --add-data "app_icon.ico;." ^
    --paths "FortiGateToFTDTool" ^
    --paths "FortiGateToPaloAltoTool" ^
    --paths "CiscoASAToPaloAltoTool" ^
    --paths "PaloAltoToFortiGateTool" ^
    --paths "CiscoFTDToFortiGateTool" ^
    --version-file "version_info.txt" ^
    --hidden-import yaml ^
    --hidden-import requests ^
    --hidden-import urllib3 ^
    --hidden-import xml.etree.ElementTree ^
    --hidden-import address_converter ^
    --hidden-import address_group_converter ^
    --hidden-import service_converter ^
    --hidden-import service_group_converter ^
    --hidden-import policy_converter ^
    --hidden-import route_converter ^
    --hidden-import interface_converter ^
    --hidden-import common ^
    --hidden-import concurrency_utils ^
    --hidden-import ftd_api_base ^
    --hidden-import platform_profiles ^
    --hidden-import fortigate_converter ^
    --hidden-import ftd_api_importer ^
    --hidden-import ftd_api_cleanup ^
    --hidden-import ftd_snmp_config ^
    --hidden-import pa_common ^
    --hidden-import pa_converter ^
    --hidden-import pa_address_converter ^
    --hidden-import pa_address_group_converter ^
    --hidden-import pa_service_converter ^
    --hidden-import pa_service_group_converter ^
    --hidden-import pa_policy_converter ^
    --hidden-import pa_route_converter ^
    --hidden-import pa_interface_converter ^
    --hidden-import panos_api_base ^
    --hidden-import panos_api_importer ^
    --hidden-import panos_api_cleanup ^
    --hidden-import asa_converter ^
    --hidden-import asa_parser ^
    --hidden-import fg_common ^
    --hidden-import fg_converter ^
    --hidden-import fg_pa_parser ^
    --hidden-import fg_address_converter ^
    --hidden-import fg_address_group_converter ^
    --hidden-import fg_service_converter ^
    --hidden-import fg_service_group_converter ^
    --hidden-import fg_policy_converter ^
    --hidden-import fg_route_converter ^
    --hidden-import fg_interface_converter ^
    --hidden-import ftd_reader ^
    --hidden-import ftd_file_reader ^
    --hidden-import fg_ftd_converter ^
    --hidden-import cleanup_auth ^
    --clean ^
    gui_app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed! Check the output above for details.
    echo.
    del /q version_info.txt 2>nul
    call :restore_version
    pause
    exit /b 1
)

REM Clean up temp version file
del /q version_info.txt 2>nul

REM Restore the original APP_VERSION if it was patched for this build
call :restore_version

echo.
echo ============================================================
echo   BUILD COMPLETE  -  v%APP_VERSION%
echo ============================================================
echo.
echo   Executable:  Firewall-Migration-Tool-v%APP_VERSION%.exe
echo   Location:    %~dp0dist\Firewall-Migration-Tool-v%APP_VERSION%.exe
echo.
echo   You can distribute this single .exe file to users.
echo   No Python installation required on the target machine.
echo.
echo   NOTE: If Windows Defender flags the .exe, you may need
echo   to add an exclusion or sign the executable.
echo ============================================================
echo.
pause
exit /b 0

REM ---------- Subroutines ----------
:restore_version
REM Put back the APP_VERSION that gui_app.py had before this build patched it
REM (mirrors the finally-block restore in build_profile.py).
if defined VERSION_PATCHED if defined ORIG_VERSION (
    echo Restoring gui_app.py APP_VERSION to %ORIG_VERSION% ...
    powershell -Command "(Get-Content '%~dp0gui_app.py') -replace 'APP_VERSION = \"[^\"]*\"', 'APP_VERSION = \"%ORIG_VERSION%\"' | Set-Content '%~dp0gui_app.py'"
)
goto :eof

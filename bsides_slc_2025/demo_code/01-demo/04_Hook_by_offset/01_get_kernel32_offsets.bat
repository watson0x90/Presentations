@echo off
setlocal EnableDelayedExpansion

echo Extracting offsets for CreateFileW and WriteFile from kernel32.dll...

:: Path to kernel32.dll (adjust if needed for 32-bit vs 64-bit)
set "DLL_PATH=C:\Windows\System32\kernel32.dll"

:: Check if dumpbin is available
where dumpbin >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: dumpbin not found. Ensure Visual Studio is installed and dumpbin is in your PATH.
    echo You may need to run this from a Visual Studio Developer Command Prompt.
    goto :end
)

:: Check if kernel32.dll exists
if not exist "%DLL_PATH%" (
    echo ERROR: %DLL_PATH% not found. Adjust DLL_PATH in the script.
    goto :end
)

:: Run dumpbin and filter for CreateFileW and WriteFile
echo Running dumpbin...
for /f "tokens=3,4" %%a in ('dumpbin /exports "%DLL_PATH%" ^| findstr /C:"CreateFileW" /C:"WriteFile"') do (
    set "RVA=%%a"
    set "NAME=%%b"
    echo !NAME! offset: 0x!RVA!
    
)

:end

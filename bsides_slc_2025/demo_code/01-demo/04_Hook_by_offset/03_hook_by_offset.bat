@echo off
setlocal EnableDelayedExpansion

echo Searching for notepad.exe PID...

:: Show raw tasklist output for debugging
echo Raw tasklist output:
tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH
echo.

:: Extract PID from CSV output
for /f "tokens=2 delims=," %%i in ('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH') do (
    set "PID=%%i"
    :: Remove quotes from PID
    set "PID=!PID:"=!"
    goto :found
)

:found
:: Check if PID was found
if defined PID (
    echo Notepad.exe is running with PID: !PID!
    echo !PID! | clip
    echo PID has been copied to the clipboard.
    echo.

    :: Run frida-trace with the PID
    echo Running frida...
    frida -l hook_by_offset.js !PID!
) else (
    echo Notepad.exe is not running or PID could not be found.
    echo Please start Notepad and try again.
)

echo.
pause
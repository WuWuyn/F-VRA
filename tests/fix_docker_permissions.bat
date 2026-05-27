@echo off
setlocal

REM === Fix WSL2 vhdx "Access is denied" after moving Docker data to D: ===
REM Right-click this file -> Run as administrator

echo.
echo === Step 1: Verify admin privileges ===
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Must run as Administrator. Right-click -^> Run as administrator.
    pause
    exit /b 1
)
echo OK

set "DST=D:\DockerData"

echo.
echo === Step 2: Stop Docker / WSL ===
taskkill /F /IM "Docker Desktop.exe" /T 2>nul
taskkill /F /IM "com.docker.backend.exe" /T 2>nul
wsl --shutdown
timeout /t 5 /nobreak >nul

echo.
echo === Step 3: Clear read-only attribute on all files ===
attrib -R "%DST%\*" /S /D

echo.
echo === Step 4: Take ownership of the whole folder tree ===
takeown /F "%DST%" /R /D Y

echo.
echo === Step 5: Reset ACLs and grant full control ===
icacls "%DST%" /reset /T /C
icacls "%DST%" /grant "%USERNAME%:(OI)(CI)F" /T /C
icacls "%DST%" /grant "SYSTEM:(OI)(CI)F" /T /C
icacls "%DST%" /grant "Administrators:(OI)(CI)F" /T /C

echo.
echo === Step 6: Verify ACLs on the vhdx files ===
icacls "%DST%\wsl\main\ext4.vhdx"
icacls "%DST%\wsl\disk\docker_data.vhdx"

echo.
echo ============================================
echo DONE. Now start Docker Desktop manually.
echo ============================================
pause

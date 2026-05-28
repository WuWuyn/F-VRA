@echo off
setlocal

REM === Move Docker Desktop WSL data from C: to D: ===
REM Right-click this file -> Run as administrator

echo.
echo === Step 1: Verify admin privileges ===
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] This script must be run as Administrator.
    echo Right-click the file and choose "Run as administrator".
    pause
    exit /b 1
)
echo OK

echo.
echo === Step 2: Stop Docker Desktop processes ===
taskkill /F /IM "Docker Desktop.exe" /T 2>nul
taskkill /F /IM "com.docker.backend.exe" /T 2>nul
taskkill /F /IM "com.docker.dev-envs.exe" /T 2>nul
taskkill /F /IM "com.docker.service" /T 2>nul
taskkill /F /IM dockerd.exe /T 2>nul
sc stop "com.docker.service" 2>nul
sc stop "Docker Desktop Service" 2>nul

echo.
echo === Step 3: Shutdown WSL (releases vhdx locks) ===
wsl --shutdown
echo Waiting 10 seconds for locks to release...
timeout /t 10 /nobreak >nul

echo.
echo === Step 4: Create destination on D: ===
if not exist "D:\DockerData" mkdir "D:\DockerData"

set "SRC=%LOCALAPPDATA%\Docker\wsl"
set "DST=D:\DockerData\wsl"

echo.
echo === Step 5: Sanity check source ===
if not exist "%SRC%" (
    echo [ERROR] Source not found: %SRC%
    pause
    exit /b 1
)
echo Source:      %SRC%
echo Destination: %DST%

echo.
echo === Step 6: Move data with robocopy (this takes 5-15 minutes for 33GB) ===
robocopy "%SRC%" "%DST%" /E /MOVE /R:3 /W:5 /NFL /NDL /NJH /NJS /NC /NS
if errorlevel 8 (
    echo [ERROR] Robocopy reported failures. Check the output above.
    pause
    exit /b 1
)

echo.
echo === Step 7: Remove leftover empty source folder if it still exists ===
if exist "%SRC%" rmdir "%SRC%" 2>nul

echo.
echo === Step 8: Create directory junction so Docker still finds its data ===
mklink /J "%SRC%" "%DST%"
if errorlevel 1 (
    echo [ERROR] mklink failed. Data is at %DST% but Docker cannot find it.
    pause
    exit /b 1
)

echo.
echo === Step 9: Verify ===
dir "%SRC%"
echo.
echo ============================================
echo SUCCESS! Docker data moved to D:\DockerData.
echo You can now start Docker Desktop manually.
echo ============================================
pause

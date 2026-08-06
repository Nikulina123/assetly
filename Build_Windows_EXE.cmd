@echo off
echo ============================================================
echo  Assetly Inventory Agent - EXE Builder
echo ============================================================
echo.

echo [1/3] Installing ps2exe module (if not already installed)...
powershell -ExecutionPolicy Bypass -Command ^
    "if (-not (Get-Module ps2exe -ListAvailable)) { Install-Module ps2exe -Force -Scope CurrentUser -Repository PSGallery }"

if %errorlevel% neq 0 (
    echo ERROR: Failed to install ps2exe. Check internet connection or run as admin.
    pause
    exit /b 1
)

echo.
echo [2/3] Compiling AssetlyAgent_Windows.ps1 to EXE...
powershell -ExecutionPolicy Bypass -Command ^
    "Invoke-ps2exe" ^
    "-InputFile '%~dp0AssetlyAgent_Windows.ps1'" ^
    "-OutputFile '%~dp0AssetlyAgent_Windows.exe'" ^
    "-NoConsole" ^
    "-STA" ^
    "-Title 'Assetly Inventory Agent'" ^
    "-Description 'Assetly device inventory check-in agent'" ^
    "-Company 'Assetly'" ^
    "-Version '1.0.0.0'"

if %errorlevel% neq 0 (
    echo ERROR: Compilation failed. See errors above.
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo.
echo   Output: %~dp0AssetlyAgent_Windows.exe
echo.
echo   Distribute AssetlyAgent_Windows.exe to employees.
echo   The EXE contains no readable source code or passwords.
echo.
pause

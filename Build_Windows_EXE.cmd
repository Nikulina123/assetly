@echo off
REM Double-clickable wrapper around Build_Windows_EXE.ps1, which holds the
REM actual build so that this and the GitHub Actions workflow cannot drift.
echo ============================================================
echo  Assetly Inventory Agent - EXE Builder
echo ============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build_Windows_EXE.ps1"

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Build failed. See the output above.
    pause
    exit /b 1
)

echo.
echo   Commit the EXE to the repository - the admin portal reads it from
echo   backend\static\ and Vercel bundles it into the deployed function.
echo.
echo   Do NOT hand this EXE to employees directly: it is generic and carries no
echo   company configuration. "Download for Windows" in the admin portal appends
echo   that company's check-in URL and enrollment token and returns a single,
echo   ready-to-run EXE.
echo.
echo   Rebuild whenever AssetlyAgent_Windows.ps1 changes. Pushing that script to
echo   main rebuilds and commits it automatically (.github/workflows).
echo.
pause

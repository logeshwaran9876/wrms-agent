@echo off
title WRMS Enterprise Endpoint Agent - Website, Application & USB Storage Control
echo =====================================================================
echo  Starting WRMS Enterprise Agent (Website + App + USB Control)...
echo =====================================================================
cd /d "%~dp0"

if exist "bin\Release\net9.0-windows\WRMS.Agent.exe" (
    echo [WRMS] Launching updated Release Agent binary...
    "bin\Release\net9.0-windows\WRMS.Agent.exe"
) else if exist "bin\Debug\net9.0-windows\WRMS.Agent.exe" (
    echo [WRMS] Launching Debug Agent binary...
    "bin\Debug\net9.0-windows\WRMS.Agent.exe"
) else (
    echo [WRMS] Running via dotnet run...
    dotnet run -c Release --no-restore
)
pause

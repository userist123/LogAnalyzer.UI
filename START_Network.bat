@echo off
title LogAnalyzer - Editie Network (Conectat / SOC)
echo ====================================================
echo  Lansare LogAnalyzer Network (Conectat la Retea / Cloud / SIEM)
echo ====================================================
cd /d "%~dp0"
if exist "bin\Network\Debug\net10.0-windows\LogAnalyzer.Network.exe" (
    start "" "bin\Network\Debug\net10.0-windows\LogAnalyzer.Network.exe"
) else (
    dotnet run --project LogAnalyzer.Network.csproj
)

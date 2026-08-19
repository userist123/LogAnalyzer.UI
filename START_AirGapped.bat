@echo off
title LogAnalyzer - Editie AirGapped (Offline)
echo ====================================================
echo  Lansare LogAnalyzer AirGapped (Statie Izolata / Fara Retea)
echo ====================================================
cd /d "%~dp0"
if exist "bin\AirGapped\Debug\net10.0-windows\LogAnalyzer.AirGapped.exe" (
    start "" "bin\AirGapped\Debug\net10.0-windows\LogAnalyzer.AirGapped.exe"
) else (
    dotnet run --project LogAnalyzer.AirGapped.csproj
)

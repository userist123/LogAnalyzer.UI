using System;
using System.Collections.Generic;
using System.Text;

namespace LogAnalyzer.Core.Services.Network
{
    public class RemoteEndpointTarget
    {
        public string HostnameOrIp { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string AdminUsername { get; set; } = string.Empty;
        public bool UseSsl { get; set; } = true;
    }

    public class RemoteTriageService
    {
        /// <summary>
        /// Generează un script PowerShell de colectare la distanță (WinRM / Invoke-Command) a artefactelor de securitate de pe un endpoint din rețea.
        /// </summary>
        public string GenerateWinRmCollectionScript(RemoteEndpointTarget target, string outputSharePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# Script Automat Colectare Triage la Distanță (WinRM) — Host: {target.HostnameOrIp}");
            sb.AppendLine($"# Generat de LogAnalyzer Network Edition");
            sb.AppendLine();
            sb.AppendLine($"$TargetHost = '{target.HostnameOrIp}'");
            sb.AppendLine($"$OutShare = '{outputSharePath.Replace("'", "''")}'");
            sb.AppendLine();
            sb.AppendLine("Invoke-Command -ComputerName $TargetHost -ScriptBlock {");
            sb.AppendLine("    param($share)");
            sb.AppendLine("    $triageDir = \"$env:TEMP\\DFIR_Triage_$env:COMPUTERNAME\"");
            sb.AppendLine("    New-Item -ItemType Directory -Path $triageDir -Force | Out-Null");
            sb.AppendLine();
            sb.AppendLine("    # 1. Export Security & Sysmon Event Logs");
            sb.AppendLine("    wevtutil epl Security \"$triageDir\\Security.evtx\"");
            sb.AppendLine("    wevtutil epl Microsoft-Windows-Sysmon/Operational \"$triageDir\\Sysmon.evtx\" 2>$null");
            sb.AppendLine();
            sb.AppendLine("    # 2. Export Active Network Sockets & Processes");
            sb.AppendLine("    Get-NetTCPConnection | Export-Csv -Path \"$triageDir\\NetSockets.csv\" -NoTypeInformation");
            sb.AppendLine("    Get-Process | Select-Object Id, ProcessName, Path, StartTime, Handles | Export-Csv -Path \"$triageDir\\Processes.csv\" -NoTypeInformation");
            sb.AppendLine();
            sb.AppendLine("    # 3. Copiere în directorul partajat de colectare");
            sb.AppendLine("    if ($share -and (Test-Path $share)) {");
            sb.AppendLine("        Copy-Item -Path \"$triageDir\\*.*\" -Destination $share -Force");
            sb.AppendLine("    }");
            sb.AppendLine("} -ArgumentList $OutShare");
            sb.AppendLine();
            sb.AppendLine("Write-Host \"[+] Colectare la distanță finalizată pentru $TargetHost.\" -ForegroundColor Green");

            return sb.ToString();
        }
    }
}

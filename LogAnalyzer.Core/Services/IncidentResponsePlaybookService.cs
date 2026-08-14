using System;
using System.IO;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public static class IncidentResponsePlaybookService
    {
        /// <summary>
        /// Generează un script PowerShell pentru izolarea completă a gazdei compromise din rețea.
        /// Permite opțional comunicarea doar cu un server SOC / management dedicat.
        /// </summary>
        public static string GenerateHostIsolationScript(string targetHostname, string? allowedSocIp = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ============================================================================");
            sb.AppendLine($"# Incident Response Playbook: IZOLARE REȚEA STAȚIE ({targetHostname})");
            sb.AppendLine($"# Generat automat de LogAnalyzer DFIR Command Center la: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ============================================================================");
            sb.AppendLine("# IMPORTANT: Rulați acest script ca Administrator (Elevated PowerShell)");
            sb.AppendLine();
            sb.AppendLine("$ErrorActionPreference = 'Stop'");
            sb.AppendLine("Write-Host '[+] Inițializare procedură de izolare rețea...' -ForegroundColor Cyan");
            sb.AppendLine();
            sb.AppendLine("# 1. Salvare backup reguli curente de firewall");
            sb.AppendLine("$backupPath = \"$env:TEMP\\Firewall_Backup_\" + (Get-Date -Format 'yyyyMMdd_HHmmss') + \".wfw\"");
            sb.AppendLine("netsh advfirewall export $backupPath");
            sb.AppendLine("Write-Host \"[+] Backup reguli salvat în: $backupPath\" -ForegroundColor Green");
            sb.AppendLine();
            sb.AppendLine("# 2. Activare blocare trafic Outbound și Inbound implicit");
            sb.AppendLine("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True");
            sb.AppendLine("Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block");
            sb.AppendLine();
            sb.AppendLine("# 3. Creare regulă de izolare DFIR");
            sb.AppendLine("New-NetFirewallRule -DisplayName 'DFIR_ISOLATION_BLOCK_ALL' -Direction Outbound -Action Block -Profile Any -Priority 1");
            sb.AppendLine();

            if (!string.IsNullOrWhiteSpace(allowedSocIp))
            {
                sb.AppendLine($"# 4. Permisiune exclusivă de comunicare către stația SOC ({allowedSocIp})");
                sb.AppendLine($"New-NetFirewallRule -DisplayName 'DFIR_SOC_ALLOW_OUT' -Direction Outbound -Action Allow -RemoteAddress '{allowedSocIp}' -Priority 1");
                sb.AppendLine($"New-NetFirewallRule -DisplayName 'DFIR_SOC_ALLOW_IN' -Direction Inbound -Action Allow -RemoteAddress '{allowedSocIp}' -Priority 1");
            }

            sb.AppendLine();
            sb.AppendLine("Write-Host '[SUCCESS] Stația a fost izolată complet de la rețea!' -ForegroundColor Yellow");
            sb.AppendLine("Write-Host 'Pentru restaurare rulați: netsh advfirewall import <cale_backup>' -ForegroundColor Gray");

            return sb.ToString();
        }

        /// <summary>
        /// Generează un script pentru terminarea forțată a unui arbore de procese malițios (Parent + Children).
        /// </summary>
        public static string GenerateKillProcessTreeScript(int pid, string processName)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ============================================================================");
            sb.AppendLine($"# Incident Response Playbook: TERMINARE ARBORE PROCESE (PID: {pid} - {processName})");
            sb.AppendLine($"# Generat automat de LogAnalyzer DFIR Command Center la: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ============================================================================");
            sb.AppendLine();
            sb.AppendLine($"Write-Host '[+] Căutare procese copil pentru PID: {pid} ({processName})...' -ForegroundColor Cyan");
            sb.AppendLine();
            sb.AppendLine($"function Kill-Tree([int]$targetPid) {{");
            sb.AppendLine($"    Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq $targetPid }} | ForEach-Object {{");
            sb.AppendLine($"        Kill-Tree $_.ProcessId");
            sb.AppendLine($"    }}");
            sb.AppendLine($"    try {{");
            sb.AppendLine($"        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue");
            sb.AppendLine($"        Write-Host \"[+] Proces terminat forțat: PID `$targetPid\" -ForegroundColor Green");
            sb.AppendLine($"    }} catch {{ }}");
            sb.AppendLine($"}}");
            sb.AppendLine();
            sb.AppendLine($"Kill-Tree {pid}");
            sb.AppendLine();
            sb.AppendLine("Write-Host '[SUCCESS] Arborele de procese a fost neutralizat!' -ForegroundColor Yellow");

            return sb.ToString();
        }

        /// <summary>
        /// Generează un script pentru blocarea unui cont compromis și invalidarea sesiunilor.
        /// </summary>
        public static string GenerateDisableAccountScript(string username)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ============================================================================");
            sb.AppendLine($"# Incident Response Playbook: BLOCARE CONT COMPROMIS ({username})");
            sb.AppendLine($"# Generat automat de LogAnalyzer DFIR Command Center la: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ============================================================================");
            sb.AppendLine();
            sb.AppendLine($"Write-Host '[+] Dezactivare cont local / domeniu: {username}...' -ForegroundColor Cyan");
            sb.AppendLine();
            sb.AppendLine($"try {{");
            sb.AppendLine($"    Disable-LocalUser -Name '{username}' -ErrorAction Stop");
            sb.AppendLine($"    Write-Host \"[+] Contul local '{username}' a fost dezactivat.\" -ForegroundColor Green");
            sb.AppendLine($"}} catch {{");
            sb.AppendLine($"    Write-Host \"[!] Nu s-a putut dezactiva local sau contul este în Active Directory. Încercare AD...\" -ForegroundColor Yellow");
            sb.AppendLine($"    try {{");
            sb.AppendLine($"        Disable-ADAccount -Identity '{username}' -ErrorAction Stop");
            sb.AppendLine($"        Write-Host \"[+] Contul AD '{username}' a fost dezactivat.\" -ForegroundColor Green");
            sb.AppendLine($"    }} catch {{ Write-Host \"[!] Eroare la dezactivare cont: `$($_.Exception.Message)\" -ForegroundColor Red }}");
            sb.AppendLine($"}}");
            sb.AppendLine();
            sb.AppendLine("# Revocare tichete Kerberos pe stație");
            sb.AppendLine("klist purge");
            sb.AppendLine("Write-Host '[+] Tichetele Kerberos au fost revocate.' -ForegroundColor Green");

            return sb.ToString();
        }

        /// <summary>
        /// Generează un script de eliminare automată a persistenței (Run keys, task-uri malițioase, servicii).
        /// </summary>
        public static string GenerateCleanPersistenceScript(string? keyPath = null, string? taskName = null, string? serviceName = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ============================================================================");
            sb.AppendLine($"# Incident Response Playbook: CURĂȚARE ARTEFACTE PERSISTENȚĂ");
            sb.AppendLine($"# Generat automat de LogAnalyzer DFIR Command Center la: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ============================================================================");
            sb.AppendLine();

            if (!string.IsNullOrWhiteSpace(keyPath))
            {
                sb.AppendLine($"Write-Host '[+] Ștergere cheie de registru suspectă: {keyPath}' -ForegroundColor Cyan");
                sb.AppendLine($"Remove-ItemProperty -Path '{keyPath}' -ErrorAction SilentlyContinue");
            }

            if (!string.IsNullOrWhiteSpace(taskName))
            {
                sb.AppendLine($"Write-Host '[+] Ștergere Scheduled Task: {taskName}' -ForegroundColor Cyan");
                sb.AppendLine($"Unregister-ScheduledTask -TaskName '{taskName}' -Confirm:$false -ErrorAction SilentlyContinue");
            }

            if (!string.IsNullOrWhiteSpace(serviceName))
            {
                sb.AppendLine($"Write-Host '[+] Oprire și ștergere serviciu suspect: {serviceName}' -ForegroundColor Cyan");
                sb.AppendLine($"Stop-Service -Name '{serviceName}' -Force -ErrorAction SilentlyContinue");
                sb.AppendLine($"sc.exe delete '{serviceName}'");
            }

            sb.AppendLine();
            sb.AppendLine("Write-Host '[SUCCESS] Curățare mecanisme de persistență finalizată!' -ForegroundColor Green");
            return sb.ToString();
        }
    }
}

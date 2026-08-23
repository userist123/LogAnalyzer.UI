using System;
using System.Collections.Generic;
using System.Text;

namespace LogAnalyzer.Core.Services
{
    public class AdRollbackScript
    {
        public string TargetObject { get; set; } = string.Empty;
        public string ActionDescription { get; set; } = string.Empty;
        public string GeneratedPowerShellScript { get; set; } = string.Empty;
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }

    public class AdSnapshotRollbackEngine
    {
        public AdRollbackScript GenerateRollbackForFinding(string attackType, string targetAccount)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ===========================================================================");
            sb.AppendLine($"# ADAUDIT PLUS - SCRIPT DE ROLLBACK AUTOMAT & RESTAURARE STARE");
            sb.AppendLine($"# Tip Incident: {attackType}");
            sb.AppendLine($"# Țintă: {targetAccount}");
            sb.AppendLine($"# Generat la: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine("# ===========================================================================");
            sb.AppendLine("Import-Module ActiveDirectory -ErrorAction SilentlyContinue");
            sb.AppendLine();

            if (attackType.Contains("Grup", StringComparison.OrdinalIgnoreCase) || attackType.Contains("Domain Admins", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"# 1. Eliminare membru neautorizat din grupul privilegiat");
                sb.AppendLine($"Remove-ADGroupMember -Identity '{targetAccount}' -Members 'CompromisedUser' -Confirm:$false");
                sb.AppendLine($"Write-Host 'Membru eliminat cu succes din {targetAccount}.'");
            }
            else if (attackType.Contains("Kerberoasting", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"# 1. Resetare SPN și forțare schimbare parolă cu criptare AES-256");
                sb.AppendLine($"Set-ADUser -Identity '{targetAccount}' -KerberosEncryptionType AES128,AES256");
                sb.AppendLine($"Set-ADAccountPassword -Identity '{targetAccount}' -Reset");
                sb.AppendLine($"Write-Host 'Criptare întărită și parolă resetată pentru {targetAccount}.'");
            }
            else if (attackType.Contains("Lockout", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"# 1. Deblocare cont utilizator");
                sb.AppendLine($"Unlock-ADAccount -Identity '{targetAccount}'");
                sb.AppendLine($"Write-Host 'Contul {targetAccount} a fost deblocat.'");
            }
            else if (attackType.Contains("LAPS", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"# 1. Forțare rotație parolă LAPS");
                sb.AppendLine($"Reset-LapsPassword -Identity '{targetAccount}'");
                sb.AppendLine($"Write-Host 'Parola LAPS a fost rotită de urgență pentru {targetAccount}.'");
            }
            else
            {
                sb.AppendLine($"# 1. Dezactivare de urgență a contului compromis");
                sb.AppendLine($"Disable-ADAccount -Identity '{targetAccount}'");
                sb.AppendLine($"Write-Host 'Contul {targetAccount} a fost dezactivat de urgență.'");
            }

            return new AdRollbackScript
            {
                TargetObject = targetAccount,
                ActionDescription = $"Rollback pentru {attackType}",
                GeneratedPowerShellScript = sb.ToString(),
                GeneratedAt = DateTime.UtcNow
            };
        }
    }
}

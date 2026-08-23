using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AdAuditReportService
    {
        public string GenerateCsvReport(AdAuditSummary summary, IEnumerable<KerberosAdFinding> findings, IEnumerable<UbaAnomalyItem> ubaAnomalies)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== RAPORT DE AUDIT ACTIVE DIRECTORY (ADAUDIT PLUS SUITE) ===");
            sb.AppendLine($"Data Generarii,{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Evenimente AD Totale,{summary.TotalAdEventsAnalyzed}");
            sb.AppendLine($"Conturi Create,{summary.UserAccountsCreated}");
            sb.AppendLine($"Conturi Modificate,{summary.UserAccountsModified}");
            sb.AppendLine($"Conturi Sterse,{summary.UserAccountsDeleted}");
            sb.AppendLine($"Resetari Parole,{summary.PasswordResets}");
            sb.AppendLine($"Blocari Conturi (Lockout),{summary.AccountLockouts}");
            sb.AppendLine($"Modificari Grupuri Privilegiate,{summary.PrivilegedGroupChanges}");
            sb.AppendLine($"Modificari Politici GPO,{summary.GpoPolicyChanges}");
            sb.AppendLine($"Atacuri Kerberos/AD Detectate,{summary.KerberosAttacksDetected}");
            sb.AppendLine();

            sb.AppendLine("=== DETECȚII ATACURI ACTIVE DIRECTORY & KERBEROS ===");
            sb.AppendLine("Categorie,Tip Atac,Severitate,Cont Tinta,MITRE ID,Sursa IP,Sumar Analiza,Recomandare Containment,Data Detectiei");

            if (findings != null)
            {
                foreach (var f in findings)
                {
                    sb.AppendLine($"\"{Escape(f.Category)}\",\"{Escape(f.AttackType)}\",\"{f.Severity}\",\"{Escape(f.TargetAccount)}\",\"{f.MitreTechniqueId}\",\"{Escape(f.ClientIp)}\",\"{Escape(f.Description)}\",\"{Escape(f.ContainmentActionRo)}\",\"{f.DetectedAt:yyyy-MM-dd HH:mm:ss}\"");
                }
            }
            sb.AppendLine();

            sb.AppendLine("=== ANALITICĂ COMPORTAMENTALĂ UTILIZATORI (UBA LOGON ANOMALIES) ===");
            sb.AppendLine("Utilizator,Tip Anomalie,Severitate,Scor Risc,Statie / Sursa,Descriere,Data Eveniment");

            if (ubaAnomalies != null)
            {
                foreach (var u in ubaAnomalies)
                {
                    sb.AppendLine($"\"{Escape(u.Username)}\",\"{Escape(u.AnomalyType)}\",\"{u.Severity}\",{u.RiskWeight},\"{Escape(u.Workstation)}\",\"{Escape(u.Description)}\",\"{u.Timestamp:yyyy-MM-dd HH:mm:ss}\"");
                }
            }

            return sb.ToString();
        }

        private static string Escape(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return input.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ");
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class DpapiCredentialFinding
    {
        public string AuditType { get; set; } = string.Empty; // ex: "Vault Credential Read (EID 5379)", "DPAPI Master Key Access", "LSA Secret Read"
        public string Severity { get; set; } = "High";
        public string TargetCredentialOrSchema { get; set; } = string.Empty;
        public string SubjectAccount { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1555.004";
        public string Description { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class DpapiLsassAuditor
    {
        /// <summary>
        /// Auditează evenimentele de securitate legate de extragerea credențialelor stocate în Windows Vault și protejate prin DPAPI.
        /// </summary>
        public List<DpapiCredentialFinding> AuditEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<DpapiCredentialFinding>();
            if (events == null) return findings;

            foreach (var ev in events)
            {
                string msg = ev.Message ?? string.Empty;
                string lowerMsg = msg.ToLowerInvariant();

                // 1. EID 5379: Citire credențial din Windows Credential Manager / Vault
                if (ev.EventId == 5379)
                {
                    findings.Add(new DpapiCredentialFinding
                    {
                        AuditType = "Citire Credențiale din Windows Vault (EID 5379)",
                        Severity = "High",
                        TargetCredentialOrSchema = "Windows Vault Schema / Web Credentials",
                        SubjectAccount = ev.MachineName ?? "Local User",
                        MitreTechniqueId = "T1555.004",
                        Description = $"Detectată interogarea unui secret din Windows Vault (Credential Manager). Atacatorii folosesc unelte precum Mimikatz sau SharpDPAPI pentru a citi parolele salvate în browsere și servicii RDP.",
                        DetectedAt = ev.TimeCreated
                    });
                }

                // 2. Detecție comenzi / unelte specifice DPAPI (SharpDPAPI, mimikatz dpapi, vaultcmd)
                if (ev.EventId == 4688 || ev.EventId == 1)
                {
                    if (lowerMsg.Contains("sharpdpapi") || lowerMsg.Contains("sekurlsa::dpapi") || lowerMsg.Contains("vaultcmd /list") || lowerMsg.Contains("vaultcmd.exe /list"))
                    {
                        findings.Add(new DpapiCredentialFinding
                        {
                            AuditType = "Execuție Unealtă Extragere Secrete DPAPI / Vault",
                            Severity = "Critical",
                            TargetCredentialOrSchema = "DPAPI Master Keys / LSA Secrets",
                            SubjectAccount = ev.MachineName ?? "Local Administrator",
                            MitreTechniqueId = "T1555.004",
                            Description = $"Detectată comanda de dumping credențiale '{msg.Trim()}' pe hostul [{ev.MachineName}].",
                            DetectedAt = ev.TimeCreated
                        });
                    }
                }
            }

            return findings;
        }
    }
}

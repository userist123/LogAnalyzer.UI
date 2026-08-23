using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AzureAdFinding
    {
        public string ActivityType { get; set; } = string.Empty; // "Impossible Travel Sign-In", "Global Admin Role Activated", "Conditional Access Policy Disabled", "Password Hash Sync Tampering"
        public string UserPrincipalName { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string SourceLocationOrIp { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1078.004";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class AzureAdAuditEngine
    {
        public List<AzureAdFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<AzureAdFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            // Detectare evenimente legate de Azure AD / Entra ID / ADFS / AAD Connect
            var azureEvents = list.Where(e => (e.ProviderName != null && (e.ProviderName.Contains("Azure", StringComparison.OrdinalIgnoreCase) || e.ProviderName.Contains("AD FS", StringComparison.OrdinalIgnoreCase) || e.ProviderName.Contains("Entra", StringComparison.OrdinalIgnoreCase))) ||
                                              (e.Message != null && (e.Message.Contains("AzureAD", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Entra ID", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Global Administrator", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Conditional Access", StringComparison.OrdinalIgnoreCase)))).ToList();

            foreach (var e in azureEvents)
            {
                string msg = e.Message ?? string.Empty;
                if (msg.Contains("Global Administrator", StringComparison.OrdinalIgnoreCase) || msg.Contains("Privileged Role", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new AzureAdFinding
                    {
                        ActivityType = "Azure AD: Activare Rol Privilegiat (Global Administrator / PIM)",
                        UserPrincipalName = "admin@domain.onmicrosoft.com",
                        Severity = "Critical",
                        SourceLocationOrIp = "Cloud Identity / Entra ID",
                        MitreTechniqueId = "T1098.003",
                        Description = "Detectată atribuirea sau activarea rolului de Global Administrator în tenantul Entra ID. Acces deplin asupra tuturor resurselor Microsoft 365 și Azure Cloud.",
                        RemediationActionRo = "1. Verificați dacă activarea a fost efectuată prin fluxul aprobat Privileged Identity Management (PIM).\n2. Auditați dacă sesiunea a utilizat MFA rezistent la phishing (FIDO2 / WHfB).",
                        Timestamp = e.TimeCreated
                    });
                }

                if (msg.Contains("Impossible Travel", StringComparison.OrdinalIgnoreCase) || msg.Contains("Risky Sign-in", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new AzureAdFinding
                    {
                        ActivityType = "Azure AD: Autentificare cu Risc Ridicat (Impossible Travel / Anon IP)",
                        UserPrincipalName = "user@domain.onmicrosoft.com",
                        Severity = "High",
                        SourceLocationOrIp = "Multiple Geolocation IPs",
                        MitreTechniqueId = "T1078.004",
                        Description = "Detectată autentificare din două locații geografice diferite într-un interval fizic imposibil de parcurs. Semnal cert de token theft sau sesiune compromisă.",
                        RemediationActionRo = "1. Revocați imediat toate sesiunile active (Revoke-AzureADUserAllRefreshToken).\n2. Blocați temporar accesul contului până la resetarea parolei și MFA.",
                        Timestamp = e.TimeCreated
                    });
                }
            }

            return findings;
        }
    }
}

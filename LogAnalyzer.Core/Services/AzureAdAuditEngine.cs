using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AzureAdAuditEngine
    {
        public List<AzureAdFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<AzureAdFinding>();
            if (events == null) return findings;

            var list = events.ToList();

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
                        Description = "DetectatÄƒ atribuirea sau activarea rolului de Global Administrator Ã®n tenantul Entra ID. Acces deplin asupra tuturor resurselor Microsoft 365 È™i Azure Cloud.",
                        RemediationActionRo = "1. VerificaÈ›i dacÄƒ activarea a fost efectuatÄƒ prin fluxul aprobat Privileged Identity Management (PIM).\n2. AuditaÈ›i dacÄƒ sesiunea a utilizat MFA rezistent la phishing (FIDO2 / WHfB).",
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
                        Description = "DetectatÄƒ autentificare din douÄƒ locaÈ›ii geografice diferite Ã®ntr-un interval fizic imposibil de parcurs. Semnal cert de token theft sau sesiune compromisÄƒ.",
                        RemediationActionRo = "1. RevocaÈ›i imediat toate sesiunile active (Revoke-AzureADUserAllRefreshToken).\n2. BlocaÈ›i temporar accesul contului pÃ¢nÄƒ la resetarea parolei È™i MFA.",
                        Timestamp = e.TimeCreated
                    });
                }
            }

            return findings;
        }
    }
}

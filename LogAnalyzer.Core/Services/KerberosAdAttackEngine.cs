using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class KerberosAdAttackEngine
    {
        public AdAuditSummary GetSummary(IEnumerable<ParsedEvent> events)
        {
            var summary = new AdAuditSummary();
            if (events == null) return summary;

            var list = events.ToList();
            summary.TotalAdEventsAnalyzed = list.Count(e => (e.EventId >= 4720 && e.EventId <= 4780) || e.EventId == 5136 || e.EventId == 5137);
            summary.UserAccountsCreated = list.Count(e => e.EventId == 4720);
            summary.UserAccountsModified = list.Count(e => e.EventId == 4738);
            summary.UserAccountsDeleted = list.Count(e => e.EventId == 4726);
            summary.PasswordResets = list.Count(e => e.EventId == 4724);
            summary.AccountLockouts = list.Count(e => e.EventId == 4740);
            summary.PrivilegedGroupChanges = list.Count(e => e.EventId == 4728 || e.EventId == 4732 || e.EventId == 4756);
            summary.GpoPolicyChanges = list.Count(e => e.EventId == 5136 || e.EventId == 5137 || e.EventId == 4739);
            summary.KerberosAttacksDetected = list.Count(e => (e.EventId == 4769 && e.Message != null && e.Message.Contains("0x17")) || (e.EventId == 4768 && e.Message != null && e.Message.Contains("0x12")));

            return summary;
        }

        public AdAuditSummary GetAuditSummary(IEnumerable<ParsedEvent> events) => GetSummary(events);

        public List<KerberosAdFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<KerberosAdFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            foreach (var e in list)
            {
                string msg = e.Message ?? string.Empty;

                if (e.EventId == 4769 && msg.Contains("0x17", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new KerberosAdFinding
                    {
                        Category = "Kerberos Attack",
                        AttackType = "Kerberoasting (TGS Request RC4-HMAC)",
                        Severity = "Critical",
                        TargetAccount = ExtractField(msg, "Service Name:") ?? "SPN Service",
                        ClientIp = ExtractField(msg, "Client Address:") ?? "Unknown",
                        MitreTechniqueId = "T1558.003",
                        Description = "Detectată solicitare de tichet TGS cu cifru slab (RC4-HMAC 0x17). Indicator de atac Kerberoasting pentru spargere offline a parolei.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 4768 && (msg.Contains("0x12", StringComparison.OrdinalIgnoreCase) || msg.Contains("Pre-Authentication Type: 0", StringComparison.OrdinalIgnoreCase) || msg.Contains("Pre-Authentication failed", StringComparison.OrdinalIgnoreCase)))
                {
                    findings.Add(new KerberosAdFinding
                    {
                        Category = "Kerberos Attack",
                        AttackType = "AS-REP Roasting",
                        Severity = "High",
                        TargetAccount = ExtractField(msg, "Account Name:") ?? "Target User",
                        ClientIp = ExtractField(msg, "Client Address:") ?? "Unknown",
                        MitreTechniqueId = "T1558.004",
                        Description = "Detectată autentificare AS-REQ fără pre-autentificare Kerberos (DONT_REQ_PREAUTH setat).",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 4662 && (msg.Contains("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", StringComparison.OrdinalIgnoreCase) || msg.Contains("DS-Replication-Get-Changes-All", StringComparison.OrdinalIgnoreCase)))
                {
                    findings.Add(new KerberosAdFinding
                    {
                        Category = "AD Replication Exploitation",
                        AttackType = "DCSync Attack (DS-Replication Abuse)",
                        Severity = "Critical",
                        TargetAccount = ExtractField(msg, "Subject: Account Name:") ?? "Attacker",
                        ClientIp = e.MachineName ?? "DomainController",
                        MitreTechniqueId = "T1003.006",
                        Description = "Detectată solicitare de replicare a datelor secrete AD (drepturi DS-Replication-Get-Changes-All) de la un cont non-DC.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 4728 || e.EventId == 4732 || e.EventId == 4756)
                {
                    if (msg.Contains("Domain Admins", StringComparison.OrdinalIgnoreCase) || msg.Contains("Enterprise Admins", StringComparison.OrdinalIgnoreCase) || msg.Contains("Schema Admins", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new KerberosAdFinding
                        {
                            Category = "Privilege Escalation",
                            AttackType = "Domain Admins Member Escalation",
                            Severity = "Critical",
                            TargetAccount = ExtractField(msg, "Member Name:") ?? "Added User",
                            ClientIp = ExtractField(msg, "Subject: Account Name:") ?? "Admin",
                            MitreTechniqueId = "T1098",
                            Description = "Adăugare neautorizată de utilizator într-un grup privilegiat de domeniu (Domain Admins / Enterprise Admins).",
                            Timestamp = e.TimeCreated
                        });
                    }
                }
            }

            return findings;
        }

        public List<KerberosAdFinding> AnalyzeEvents(IEnumerable<ParsedEvent> events) => Analyze(events);

        private static string? ExtractField(string text, string fieldLabel)
        {
            if (string.IsNullOrEmpty(text)) return null;
            int idx = text.IndexOf(fieldLabel, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            int start = idx + fieldLabel.Length;
            int end = text.IndexOf('\n', start);
            if (end < 0) end = text.Length;

            var val = text.Substring(start, end - start).Trim();
            return string.IsNullOrEmpty(val) ? null : val;
        }
    }
}

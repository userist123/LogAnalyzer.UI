using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class StandaloneSamAuditEngine
    {
        private static readonly HashSet<string> IgnoredAccounts = new(StringComparer.OrdinalIgnoreCase)
        {
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
            "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2"
        };

        public StandaloneSamSummary GetSummary(IEnumerable<ParsedEvent> events)
        {
            var summary = new StandaloneSamSummary();
            if (events == null) return summary;

            var list = events.ToList();
            summary.LocalAccountsCreated = list.Count(e => e.EventId == 4720);
            summary.LocalAccountsDeleted = list.Count(e => e.EventId == 4726);
            summary.LocalAdminGroupModifications = list.Count(e => (e.EventId == 4732 || e.EventId == 4733) && e.Message != null && e.Message.Contains("Administrators", StringComparison.OrdinalIgnoreCase));
            summary.AuditPolicyTamperingCount = list.Count(e => e.EventId == 4719 || e.EventId == 1102);
            summary.UsbStorageEventsCount = list.Count(e => e.EventId == 20001 || e.EventId == 20003 || e.EventId == 6416 || (e.Message != null && e.Message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)));
            
            // Numărare privilegii SeDebug doar pentru conturi non-SYSTEM
            summary.HighPrivilegeAssignmentsCount = list.Count(e => e.EventId == 4672 && e.Message != null && 
                (e.Message.Contains("SeDebugPrivilege") || e.Message.Contains("SeTcbPrivilege")) && 
                !IsSystemAccount(e.Message));

            return summary;
        }

        public List<StandaloneSamFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<StandaloneSamFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            // 1. Modificări BUILTIN\Administrators (Grupate pe Cont Țintă)
            var adminEvents = list.Where(e => (e.EventId == 4732 || e.EventId == 4733) && e.Message != null && e.Message.Contains("Administrators", StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (var g in adminEvents.GroupBy(e => ExtractField(e.Message, "Member Name:") ?? ExtractField(e.Message, "Account Name:") ?? "User"))
            {
                var first = g.Min(e => e.TimeCreated);
                var last = g.Max(e => e.TimeCreated);
                findings.Add(new StandaloneSamFinding
                {
                    Category = "Local Privilege Escalation",
                    FindingType = "Modificare Membri Grupul Local Administrators",
                    Severity = "Critical",
                    TargetAccountOrResource = $"BUILTIN\\Administrators ({g.Key})",
                    MitreTechniqueId = "T1078.003",
                    SourceProcessOrDevice = g.FirstOrDefault()?.MachineName ?? "Localhost",
                    Description = $"Înregistrate {g.Count()} modificări de apartenență pentru contul '{g.Key}' între {first:HH:mm:ss} și {last:HH:mm:ss}.",
                    RemediationActionRo = "Verificați dacă modificarea are ordin de serviciu aprobat; eliminați contul dacă este neautorizat.",
                    Timestamp = last
                });
            }

            // 2. Modificare Politică de Audit (Grupate per Stație)
            var auditpolEvents = list.Where(e => e.EventId == 4719).ToList();
            if (auditpolEvents.Count > 0)
            {
                var first = auditpolEvents.Min(e => e.TimeCreated);
                var last = auditpolEvents.Max(e => e.TimeCreated);
                findings.Add(new StandaloneSamFinding
                {
                    Category = "Defense Evasion",
                    FindingType = "Modificare Politică Locală de Auditare (auditpol)",
                    Severity = "High",
                    TargetAccountOrResource = "Audit Policy Subcategories",
                    MitreTechniqueId = "T1562.002",
                    SourceProcessOrDevice = "auditpol.exe / Local Security Authority",
                    Description = $"Detectate {auditpolEvents.Count} modificări ale politicilor de auditare Windows pe stație (interval {first:yyyy-MM-dd HH:mm} - {last:yyyy-MM-dd HH:mm}). Posibilă tentativă de dezactivare a generării jurnalelor.",
                    RemediationActionRo = "Restaurați politica de audit standard din baseline securitate HG 585.",
                    Timestamp = last
                });
            }

            // 3. Golire Jurnal Securitate EID 1102 (Fiecare eveniment distinct)
            var logClearEvents = list.Where(e => e.EventId == 1102).ToList();
            foreach (var e in logClearEvents)
            {
                findings.Add(new StandaloneSamFinding
                {
                    Category = "Defense Evasion",
                    FindingType = "Golire Jurnal Securitate (Security Log Cleared)",
                    Severity = "Critical",
                    TargetAccountOrResource = "Security.evtx",
                    MitreTechniqueId = "T1070.001",
                    SourceProcessOrDevice = "wevtutil.exe / EventLog Service",
                    Description = "Jurnalul de securitate a fost golit complet. Indicator cert de activitate anti-forensică.",
                    RemediationActionRo = "Izolați stația pentru investigație pe disc fizic și recuperare jurnale din VSS.",
                    Timestamp = e.TimeCreated
                });
            }

            // 4. Medii USB Removabile (Deduplicate per Device / Serie Hardware)
            var usbEvents = list.Where(e => e.EventId == 20001 || e.EventId == 20003 || e.EventId == 6416 || (e.Message != null && e.Message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))).ToList();
            foreach (var g in usbEvents.GroupBy(e => ExtractUsbDeviceId(e.Message)))
            {
                var first = g.Min(e => e.TimeCreated);
                var last = g.Max(e => e.TimeCreated);
                findings.Add(new StandaloneSamFinding
                {
                    Category = "Removable Media",
                    FindingType = "Conectare Mediu Stocare USB Removabil",
                    Severity = "High",
                    TargetAccountOrResource = g.Key,
                    MitreTechniqueId = "T1052.001",
                    SourceProcessOrDevice = "USBSTOR.SYS / PnP Manager",
                    Description = $"Dispozitiv USB detectat ({g.Count()} evenimente I/O). Primul acces: {first:yyyy-MM-dd HH:mm:ss}, Ultimul: {last:yyyy-MM-dd HH:mm:ss}.",
                    RemediationActionRo = "Verificați conformitatea cu Registrul de Medii de Stocare și seria fizică a stick-ului USB autorizat.",
                    Timestamp = last
                });
            }

            // 5. SeDebugPrivilege (Agregat per Cont Utilizator - Fără zgomot SYSTEM)
            var debugPrivEvents = list.Where(e => e.EventId == 4672 && e.Message != null && 
                (e.Message.Contains("SeDebugPrivilege") || e.Message.Contains("SeTcbPrivilege")) && 
                !IsSystemAccount(e.Message)).ToList();

            foreach (var g in debugPrivEvents.GroupBy(e => ExtractUserFromMessage(e.Message)))
            {
                var first = g.Min(e => e.TimeCreated);
                var last = g.Max(e => e.TimeCreated);
                findings.Add(new StandaloneSamFinding
                {
                    Category = "Privilege Escalation",
                    FindingType = "Atribuire Drepturi de Debug Memorie (SeDebugPrivilege)",
                    Severity = "High",
                    TargetAccountOrResource = $"Cont Utilizator: {g.Key}",
                    MitreTechniqueId = "T1003.001",
                    SourceProcessOrDevice = "Local Logon Session",
                    Description = $"Contul '{g.Key}' a solicitat SeDebugPrivilege de {g.Count()} ori (interval {first:HH:mm:ss} - {last:HH:mm:ss}). Permite acces direct în memoria proceselor de sistem (lsass.exe).",
                    RemediationActionRo = "Restricționați SeDebugPrivilege exclusiv pentru contul Local SYSTEM prin politica locală de securitate.",
                    Timestamp = last
                });
            }

            return findings;
        }

        private static bool IsSystemAccount(string? msg)
        {
            if (string.IsNullOrEmpty(msg)) return true;
            string u = ExtractUserFromMessage(msg);
            if (string.IsNullOrEmpty(u)) return true;
            if (u.EndsWith("$") || IgnoredAccounts.Contains(u)) return true;
            return false;
        }

        private static string ExtractUserFromMessage(string? message)
        {
            if (string.IsNullOrEmpty(message)) return string.Empty;
            var lines = message.Split('\n');
            foreach (var line in lines)
            {
                if (line.Contains("Account Name:", StringComparison.OrdinalIgnoreCase) || line.Contains("TargetUserName:", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(':');
                    if (parts.Length > 1)
                    {
                        var user = parts[1].Trim();
                        if (!string.IsNullOrEmpty(user) && !user.Equals("-"))
                        {
                            return user;
                        }
                    }
                }
            }
            return string.Empty;
        }

        private static string ExtractUsbDeviceId(string? msg)
        {
            if (string.IsNullOrEmpty(msg)) return "Dispozitiv USB";
            int idx = msg.IndexOf("USBSTOR\\", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int end = msg.IndexOfAny(new[] { '\n', '\r', '#', '&' }, idx + 8);
                if (end < 0) end = Math.Min(msg.Length, idx + 40);
                return msg.Substring(idx, end - idx).Trim();
            }
            return "Dispozitiv USB Removabil";
        }

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

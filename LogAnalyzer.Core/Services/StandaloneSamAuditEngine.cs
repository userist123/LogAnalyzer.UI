using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class StandaloneSamAuditEngine
    {
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
            summary.HighPrivilegeAssignmentsCount = list.Count(e => e.EventId == 4672 && e.Message != null && (e.Message.Contains("SeDebugPrivilege") || e.Message.Contains("SeTcbPrivilege")));

            return summary;
        }

        public List<StandaloneSamFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<StandaloneSamFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            foreach (var e in list)
            {
                string msg = e.Message ?? string.Empty;

                if (e.EventId == 4732 && msg.Contains("Administrators", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new StandaloneSamFinding
                    {
                        Category = "Local Privilege Escalation",
                        FindingType = "AdÄƒugare Membru Ã®n Grupul Local Administrators",
                        Severity = "Critical",
                        TargetAccountOrResource = "BUILTIN\\Administrators",
                        MitreTechniqueId = "T1078.003",
                        SourceProcessOrDevice = e.MachineName ?? "Localhost",
                        Description = "Un cont de utilizator local a fost promovat Ã®n grupul local de administratori. Risc major de preluare control staÈ›ie izolatÄƒ.",
                        RemediationActionRo = "VerificaÈ›i dacÄƒ adÄƒugarea are ordin de serviciu aprobat; eliminaÈ›i contul dacÄƒ modificarea este neautorizatÄƒ.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 4719)
                {
                    findings.Add(new StandaloneSamFinding
                    {
                        Category = "Defense Evasion",
                        FindingType = "Modificare PoliticÄƒ LocalÄƒ de Auditare (auditpol)",
                        Severity = "High",
                        TargetAccountOrResource = "Audit Policy",
                        MitreTechniqueId = "T1562.002",
                        SourceProcessOrDevice = "auditpol.exe / Local Security Authority",
                        Description = "Categoriile de auditare Windows au fost modificate pe staÈ›ie. PosibilÄƒ tentativÄƒ de dezactivare a generÄƒrii jurnalelor de securitate.",
                        RemediationActionRo = "RestauraÈ›i politica de audit standard din baseline GPO / script de securitate HG 585.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 1102)
                {
                    findings.Add(new StandaloneSamFinding
                    {
                        Category = "Defense Evasion",
                        FindingType = "Golire Jurnal Securitate (Security Log Cleared)",
                        Severity = "Critical",
                        TargetAccountOrResource = "Security.evtx",
                        MitreTechniqueId = "T1070.001",
                        SourceProcessOrDevice = "wevtutil.exe / EventLog Service",
                        Description = "Jurnalul de securitate a fost golit complet. Indicator cert de activitate anti-forensicÄƒ.",
                        RemediationActionRo = "IzolaÈ›i imediat staÈ›ia pentru investigaÈ›ie forensicÄƒ pe disc fizic È™i recuperare jurnale din snapshot VSS.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 20001 || msg.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new StandaloneSamFinding
                    {
                        Category = "Removable Media",
                        FindingType = "Conectare Mediu Stocare USB Removabil",
                        Severity = "High",
                        TargetAccountOrResource = "USB Storage Device",
                        MitreTechniqueId = "T1052.001",
                        SourceProcessOrDevice = "USBSTOR.SYS / PnP Manager",
                        Description = "A fost conectat un mediu extern de stocare USB. Risc de exfiltrare date sau introducere de payload offline pe staÈ›ie izolatÄƒ.",
                        RemediationActionRo = "VerificaÈ›i conformitatea cu Registrul de Medii de Stocare È™i seria fizicÄƒ a stick-ului USB autorizat.",
                        Timestamp = e.TimeCreated
                    });
                }
                else if (e.EventId == 4672 && msg.Contains("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new StandaloneSamFinding
                    {
                        Category = "Privilege Escalation",
                        FindingType = "Atribuire Drepturi de Debug Memorie (SeDebugPrivilege)",
                        Severity = "High",
                        TargetAccountOrResource = "LSASS / System Processes",
                        MitreTechniqueId = "T1003.001",
                        SourceProcessOrDevice = "Local Logon Session",
                        Description = "Sesiunea de logon a solicitat SeDebugPrivilege, permiÈ›Ã¢nd citirea memoriei proceselor de sistem (inclusiv extragere hash-uri din lsass.exe).",
                        RemediationActionRo = "RestricÈ›ionaÈ›i SeDebugPrivilege exclusiv pentru contul Local SYSTEM prin politica localÄƒ de securitate.",
                        Timestamp = e.TimeCreated
                    });
                }
            }

            return findings;
        }
    }
}

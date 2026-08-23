using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class StandaloneSamFinding
    {
        public string FindingType { get; set; } = string.Empty; // ex: "Local Admin Group Tampering", "Audit Policy Disabled", "USB Media Connected", "Local Password Guessing"
        public string Category { get; set; } = "Local Endpoint Security"; // "Local SAM", "Security Policy", "Hardware/USB", "Privilege Abuse", "Logon Audit"
        public string Severity { get; set; } = "High";
        public string Description { get; set; } = string.Empty;
        public string TargetAccountOrResource { get; set; } = string.Empty;
        public string SourceProcessOrDevice { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class StandaloneSamSummary
    {
        public int TotalLocalSecurityEvents { get; set; }
        public int LocalAccountsCreated { get; set; }
        public int LocalAccountsDeleted { get; set; }
        public int LocalAdminGroupModifications { get; set; }
        public int AuditPolicyTamperingCount { get; set; }
        public int LocalAccountLockouts { get; set; }
        public int UsbStorageEventsCount { get; set; }
        public int HighPrivilegeAssignmentsCount { get; set; }
    }

    public class StandaloneSamAuditEngine
    {
        public StandaloneSamSummary GetSummary(IEnumerable<ParsedEvent> events)
        {
            var summary = new StandaloneSamSummary();
            if (events == null) return summary;

            var list = events.ToList();
            summary.TotalLocalSecurityEvents = list.Count(e => (e.EventId >= 4720 && e.EventId <= 4740) || e.EventId == 4719 || e.EventId == 4672 || e.EventId == 4624 || e.EventId == 4625 || e.EventId == 20001 || e.EventId == 6416);
            summary.LocalAccountsCreated = list.Count(e => e.EventId == 4720);
            summary.LocalAccountsDeleted = list.Count(e => e.EventId == 4726);
            summary.LocalAdminGroupModifications = list.Count(e => e.EventId == 4732 || e.EventId == 4733);
            summary.AuditPolicyTamperingCount = list.Count(e => e.EventId == 4719 || (e.EventId == 1102)); // 1102 = Audit Log Cleared
            summary.LocalAccountLockouts = list.Count(e => e.EventId == 4740 || (e.EventId == 4625 && e.Message != null && e.Message.Contains("0xC0000072")));
            summary.UsbStorageEventsCount = list.Count(e => e.EventId == 20001 || e.EventId == 20003 || e.EventId == 6416 || (e.Message != null && e.Message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)));
            summary.HighPrivilegeAssignmentsCount = list.Count(e => e.EventId == 4672 && e.Message != null && (e.Message.Contains("SeDebugPrivilege") || e.Message.Contains("SeTakeOwnershipPrivilege")));

            return summary;
        }

        public List<StandaloneSamFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<StandaloneSamFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            // 1. Modificare Grup Administratori Locali (EID 4732 - Membru Adăugat în BUILTIN\Administrators)
            var adminGroupEvents = list.Where(e => e.EventId == 4732).ToList();
            if (adminGroupEvents.Count > 0)
            {
                findings.Add(new StandaloneSamFinding
                {
                    FindingType = "ADAudit Standalone: Adăugare Membru în Grupul Local Administrators",
                    Category = "Local Privilege Escalation",
                    Severity = "Critical",
                    Description = $"Detectată adăugarea unui utilizator în grupul local BUILTIN\\Administrators ({adminGroupEvents.Count} evenimente). Pe o stație standalone/air-gapped, aceasta acordă acces complet asupra fișierelor criptate și a registrilor de sistem.",
                    TargetAccountOrResource = "BUILTIN\\Administrators",
                    SourceProcessOrDevice = "Local SAM / net localgroup",
                    MitreTechniqueId = "T1078.003",
                    RemediationActionRo = "1. Auditați contul de utilizator adăugat prin 'net localgroup administrators'.\n2. Eliminați contul dacă nu este un administrator autorizat.\n3. Verificați jurnalul de activitate al contului creator.",
                    Timestamp = adminGroupEvents.Max(e => e.TimeCreated)
                });
            }

            // 2. Dezactivare sau Modificare Politică de Auditare (EID 4719 sau EID 1102 - Ștergere Jurnal)
            var policyEvents = list.Where(e => e.EventId == 4719 || e.EventId == 1102).ToList();
            if (policyEvents.Count > 0)
            {
                findings.Add(new StandaloneSamFinding
                {
                    FindingType = "ADAudit Standalone: Modificare Politică Auditare / Ștergere Jurnal Securitate",
                    Category = "Defense Evasion",
                    Severity = "Critical",
                    Description = "Detectată modificarea politicii de audit a sistemului de operare (EID 4719) sau golirea deliberată a jurnalului de securitate (EID 1102). Tehnica este folosită de atacatori pentru a elimina urmele de execuție și persistență.",
                    TargetAccountOrResource = "System Audit Policy / Security Log",
                    SourceProcessOrDevice = "auditpol.exe / wevtutil",
                    MitreTechniqueId = "T1562.002",
                    RemediationActionRo = "1. Reinițializați politica de auditare la nivelul 'Success and Failure' pentru toate categoriile.\n2. Rulați un triage de memorie și MFT pe stație pentru a recupera activitățile șterse.",
                    Timestamp = policyEvents.Max(e => e.TimeCreated)
                });
            }

            // 3. Conectare Dispozitive de Stocare USB / Medii Removabile pe Stație Standalone
            var usbEvents = list.Where(e => e.EventId == 20001 || e.EventId == 20003 || e.EventId == 6416 || (e.Message != null && e.Message.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase))).ToList();
            if (usbEvents.Count > 0)
            {
                findings.Add(new StandaloneSamFinding
                {
                    FindingType = "ADAudit Standalone: Detectare Conectare Mediu de Stocare USB / Removabil",
                    Category = "Removable Media / Air-Gap Bridge",
                    Severity = "High",
                    Description = $"Înregistrate {usbEvents.Count} evenimente de inserare mediu de stocare USB (USBSTOR/PnP). Pe sistemele air-gapped / clasificate, introducerea unui mediu extern reprezintă un risc major de infecție sau exfiltrare de date.",
                    TargetAccountOrResource = "USB Storage Device / PnP",
                    SourceProcessOrDevice = "Windows Driver Manager",
                    MitreTechniqueId = "T1091",
                    RemediationActionRo = "1. Verificați seria fizică a stick-ului USB în Registrul de Transferuri.\n2. Efectuați scanarea antimalware offline a mediului înainte de citirea datelor.",
                    Timestamp = usbEvents.Max(e => e.TimeCreated)
                });
            }

            // 4. Utilizare Privilegii Critice de Sistem (SeDebugPrivilege / SeTakeOwnership)
            var debugPrivEvents = list.Where(e => e.EventId == 4672 && e.Message != null && e.Message.Contains("SeDebugPrivilege")).ToList();
            if (debugPrivEvents.Count > 0)
            {
                findings.Add(new StandaloneSamFinding
                {
                    FindingType = "ADAudit Standalone: Atribuire Privilegiu SeDebugPrivilege (Memory Dumping)",
                    Category = "Privilege Abuse",
                    Severity = "High",
                    Description = "Detectată autentificare cu SeDebugPrivilege. Acest drept permite citirea memoriei procesului lsass.exe (Mimikatz / ProcDump) pentru extragerea parolelor în clar din memoria RAM.",
                    TargetAccountOrResource = "LSASS Process Memory",
                    SourceProcessOrDevice = "Local Security Authority",
                    MitreTechniqueId = "T1003.001",
                    RemediationActionRo = "1. Verificați ce proces a fost lansat imediat după acordarea privilegiului.\n2. Restricționați SeDebugPrivilege exclusiv pentru conturile de mentenanță autorizate.",
                    Timestamp = debugPrivEvents.Max(e => e.TimeCreated)
                });
            }

            // 5. Tentative Repetate de Ghicire Parolă Cont Local (Brute Force / Password Guessing)
            var localLogonFails = list.Where(e => e.EventId == 4625 && (e.Message == null || (!e.Message.Contains("Domain:", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("WORKGROUP", StringComparison.OrdinalIgnoreCase)))).ToList();
            if (localLogonFails.Count >= 5)
            {
                findings.Add(new StandaloneSamFinding
                {
                    FindingType = "ADAudit Standalone: Tentative Multiple Eșuate de Autentificare Locală (Brute Force)",
                    Category = "Credential Access",
                    Severity = "Medium",
                    Description = $"Detectate {localLogonFails.Count} eșecuri de autentificare locală. Posibil atac de forță brută pe contul de Administrator local sau utilizator de stație.",
                    TargetAccountOrResource = "Local User Account",
                    SourceProcessOrDevice = "Local Logon Screen / NTLM",
                    MitreTechniqueId = "T1110.001",
                    RemediationActionRo = "1. Verificați contul țintă și asigurați-vă că politica de blocare a contului (Account Lockout Threshold) este activă.",
                    Timestamp = localLogonFails.Max(e => e.TimeCreated)
                });
            }

            return findings;
        }
    }
}

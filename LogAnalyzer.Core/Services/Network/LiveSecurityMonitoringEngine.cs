using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services.Network
{
    public class LiveSecurityMonitoringEngine
    {
        private readonly List<string> _failedLogonHistory = new();
        private DateTime _lastCleanupUtc = DateTime.UtcNow;

        /// <summary>
        /// Evaluează în memorie un eveniment nou sosit în timp real și returnează o alertă dacă se detectează un atac.
        /// </summary>
        public DetectedIssue? EvaluateLiveEvent(ParsedEvent ev)
        {
            if (ev == null) return null;

            string msg = (ev.Message ?? string.Empty).ToLowerInvariant();

            // 1. Ransomware & Shadow Copy Deletion (EID 4688 / Sysmon 1)
            if ((ev.EventId == 4688 || ev.EventId == 1) &&
                (msg.Contains("vssadmin") && msg.Contains("delete") && msg.Contains("shadows") ||
                 msg.Contains("bcdedit") && msg.Contains("recoveryenabled") && msg.Contains("no") ||
                 msg.Contains("wbadmin") && msg.Contains("delete") && msg.Contains("catalog")))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Tentativă Distrugere Shadow Copies (Ransomware)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1490",
                    MitreTacticName = "Impact",
                    Explanation = $"Detectată execuția comenzii de distrugere a copiilor de rezervă pe hostul [{ev.MachineName}]. Tehnica este caracteristică etapelor premergătoare criptării de către grupările de Ransomware (LockBit, BlackCat, Akira).",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 2. PowerShell Codificat / Obfuscat / Bypass (EID 4104 / EID 4688 / Sysmon 1)
            if ((ev.EventId == 4104 || ev.EventId == 4688 || ev.EventId == 1) &&
                (msg.Contains("-enc") || msg.Contains("-encodedcommand") || msg.Contains("downloadstring") || 
                 msg.Contains("iex(") || msg.Contains("bypass -nop -w hidden")))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ MARE: Execuție PowerShell Codificat / Download Cradle",
                    Severity = "High",
                    MitreTechniqueId = "T1059.001",
                    MitreTacticName = "Execution",
                    Explanation = $"A fost interceptată o execuție suspectă de script PowerShell ascuns pe [{ev.MachineName}]. Comanda încearcă descărcarea de payload direct în memorie sau eludarea politicilor de execuție.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 3. Acces Memorie LSASS / Mimikatz (Sysmon EID 10 / Security EID 4656 / 4663)
            if ((ev.EventId == 10 || ev.EventId == 4656 || ev.EventId == 4663) &&
                msg.Contains("lsass.exe") &&
                (msg.Contains("0x1010") || msg.Contains("0x1fffff")))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Tentativă Extragere Credențiale LSASS (Mimikatz / Dump)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1003.001",
                    MitreTacticName = "Credential Access",
                    Explanation = $"Un proces a solicitat drepturi de acces la memoria procesului de autentificare LSASS (GrantedAccess: 0x1010 / 0x1FFFFF) pe [{ev.MachineName}]. Indicator puternic de atac cu unelte de tip Mimikatz sau Procdump.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 4. Creare Cont Administrator Nou (EID 4720 + EID 4732)
            if (ev.EventId == 4720 || ev.EventId == 4732)
            {
                return new DetectedIssue
                {
                    Title = "⚠️ ALERTĂ MEDIE: Creare / Modificare Cont Utilizator sau Grup Privilegiat",
                    Severity = "Medium",
                    MitreTechniqueId = "T1136.001",
                    MitreTacticName = "Persistence",
                    Explanation = $"A fost creat un cont local nou sau a fost adăugat un membru într-un grup administrativ pe [{ev.MachineName}]. Verificați dacă acțiunea a fost autorizată.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 5. Curățare Jurnal de Securitate (Anti-Forensics EID 1102 / 104)
            if (ev.EventId == 1102 || ev.EventId == 104)
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Jurnal de Securitate Șters Intenționat (Anti-Forensics)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1070.001",
                    MitreTacticName = "Defense Evasion",
                    Explanation = $"Jurnalul Security a fost curățat intenționat (wevtutil cl / Event Log Cleared) pe [{ev.MachineName}]. Tehnică standard de acoperire a urmelor după compromitere.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 6. Instalare Serviciu Nou / Lateral Movement (EID 7045)
            if (ev.EventId == 7045)
            {
                bool isPsExec = msg.Contains("psexec") || msg.Contains("psexesvc");
                return new DetectedIssue
                {
                    Title = isPsExec ? "🚨 ALERTĂ MARE: Serviciu de Execuție la Distanță (PsExec / Lateral Movement)" : "⚠️ NOTIFICARE: Serviciu Nou Instalat în Sistem",
                    Severity = isPsExec ? "High" : "Low",
                    MitreTechniqueId = "T1543.003",
                    MitreTacticName = "Persistence",
                    Explanation = $"A fost înregistrat un nou serviciu de sistem pe [{ev.MachineName}]. {ev.Message}",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 7. Eșecuri Repetate de Autentificare / Brute Force (EID 4625)
            if (ev.EventId == 4625)
            {
                TrackFailedLogon(ev.MachineName ?? "Unknown");
                if (_failedLogonHistory.Count >= 5)
                {
                    return new DetectedIssue
                    {
                        Title = "🚨 ALERTĂ MARE: Atac de Tip Brute Force / Password Spraying Detectat",
                        Severity = "High",
                        MitreTechniqueId = "T1110.001",
                        MitreTacticName = "Credential Access",
                        Explanation = $"Au fost interceptate {_failedLogonHistory.Count} autentificări eșuate consecutive într-un interval scurt pe [{ev.MachineName}].",
                        CreatedAt = DateTime.UtcNow,
                        RelatedEvents = new List<ParsedEvent> { ev }
                    };
                }
            }

            return null;
        }

        private void TrackFailedLogon(string machineName)
        {
            if ((DateTime.UtcNow - _lastCleanupUtc).TotalMinutes > 2)
            {
                _failedLogonHistory.Clear();
                _lastCleanupUtc = DateTime.UtcNow;
            }
            _failedLogonHistory.Add(machineName);
        }
    }
}

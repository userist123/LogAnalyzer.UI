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
        /// Evaluează în memorie un eveniment nou sosit în timp real și returnează o alertă dacă se detectează un atac sau anomalie.
        /// </summary>
        public DetectedIssue? EvaluateLiveEvent(ParsedEvent ev)
        {
            if (ev == null) return null;

            string msg = (ev.Message ?? string.Empty).ToLowerInvariant();
            string provider = (ev.ProviderName ?? string.Empty).ToLowerInvariant();

            // 1. Ransomware & Shadow Copy Deletion (EID 4688 / Sysmon 1 / PowerShell 4104)
            if (msg.Contains("vssadmin") && (msg.Contains("delete") || msg.Contains("shadows")) ||
                msg.Contains("bcdedit") && msg.Contains("recoveryenabled") ||
                msg.Contains("wbadmin") && msg.Contains("delete") && msg.Contains("catalog"))
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

            // 2. PowerShell Codificat / Obfuscat / Download Cradle / Bypass (EID 4104 / EID 4688 / Sysmon 1 / Engine 400)
            if (msg.Contains("-enc") || msg.Contains("-encodedcommand") || msg.Contains("downloadstring") || 
                msg.Contains("iex(") || msg.Contains("bypass") || msg.Contains("downloadfile") ||
                msg.Contains("invoke-webrequest") || msg.Contains("invoke-expression") || msg.Contains("w hidden") ||
                (provider.Contains("powershell") && (msg.Contains("scriptblock") && msg.Contains("-enc"))))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ MARE: Execuție PowerShell Codificat / Download Cradle",
                    Severity = "High",
                    MitreTechniqueId = "T1059.001",
                    MitreTacticName = "Execution",
                    Explanation = $"A fost interceptată o execuție suspectă de script PowerShell ascuns/obfuscat pe [{ev.MachineName}]. Comanda încearcă descărcarea de payload direct în memorie sau eludarea politicilor de execuție.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 3. Acces Memorie LSASS / Mimikatz / Procdump
            if (msg.Contains("lsass.exe") && (msg.Contains("0x1010") || msg.Contains("0x1fffff") || msg.Contains("mimikatz") || msg.Contains("sekurlsa") || msg.Contains("logonpasswords")))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Tentativă Extragere Credențiale LSASS (Mimikatz / Dump)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1003.001",
                    MitreTacticName = "Credential Access",
                    Explanation = $"Un proces a solicitat drepturi de acces la memoria procesului de autentificare LSASS pe [{ev.MachineName}]. Indicator puternic de atac cu unelte de tip Mimikatz sau Procdump.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 4. Recunoaștere Privilegii / Utilizatori (whoami /priv, net user, net localgroup administrators)
            if (msg.Contains("whoami") && (msg.Contains("/priv") || msg.Contains("/all") || msg.Contains("/groups")) ||
                msg.Contains("net localgroup") && msg.Contains("administrators") ||
                msg.Contains("net group \"domain admins\""))
            {
                return new DetectedIssue
                {
                    Title = "⚠️ ALERTĂ MEDIE: Activitate de Recunoaștere & Enumerare Privilegii (Discovery)",
                    Severity = "Medium",
                    MitreTechniqueId = "T1033",
                    MitreTacticName = "Discovery",
                    Explanation = $"Comandă de enumerare a privilegiilor utilizatorului sau a membrilor grupurilor de administratori executată pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 5. Creare Cont Administrator Nou (EID 4720 + EID 4732)
            if (ev.EventId == 4720 || ev.EventId == 4732 || (msg.Contains("net user") && msg.Contains("/add")))
            {
                return new DetectedIssue
                {
                    Title = "⚠️ ALERTĂ MEDIE: Creare / Modificare Cont Utilizator sau Grup Privilegiat",
                    Severity = "Medium",
                    MitreTechniqueId = "T1136.001",
                    MitreTacticName = "Persistence",
                    Explanation = $"A fost creat un cont local nou sau a fost adăugat un membru într-un grup administrativ pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 6. Curățare Jurnal de Securitate (Anti-Forensics EID 1102 / 104)
            if (ev.EventId == 1102 || ev.EventId == 104 || (msg.Contains("wevtutil") && (msg.Contains("cl") || msg.Contains("clear-log"))))
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

            // 7. Instalare Serviciu Nou / Lateral Movement (EID 7045)
            if (ev.EventId == 7045 || msg.Contains("psexec") || msg.Contains("psexesvc"))
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

            // 8. Eșecuri Repetate de Autentificare / Brute Force (EID 4625)
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

            // 9. Comenzi de Test / Simulare
            if (msg.Contains("simulare dfir") || msg.Contains("test alert"))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ LIVE (TEST SIMULAT): Detecție Semnătură Activă",
                    Severity = "High",
                    MitreTechniqueId = "T1059.001",
                    MitreTacticName = "Execution",
                    Explanation = $"A fost interceptată o simulare de alertă de securitate live pe [{ev.MachineName}]. Pipeline-ul de detecție și toast pop-up funcționează perfect.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
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

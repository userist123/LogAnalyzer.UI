using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure.Engines;

namespace LogAnalyzer.Infrastructure
{
    public class AnalysisEngine : IAnalysisEngine
    {
        private readonly SigmaRuleEngine _sigmaEngine = new();
        private readonly YaraRuleEngine _yaraEngine = new();
        private readonly AnomalyDetectionEngine _anomalyEngine = new();

        public SigmaRuleEngine SigmaEngine => _sigmaEngine;
        public YaraRuleEngine YaraEngine => _yaraEngine;
        public AnomalyDetectionEngine AnomalyEngine => _anomalyEngine;

        public IEnumerable<DetectedIssue> AnalyzeEvents(IEnumerable<ParsedEvent> events)
        {
            var issues = new List<DetectedIssue>();
            var eventList = events as IList<ParsedEvent> ?? events.ToList();

            foreach (var ev in eventList)
            {
                if (ev == null) continue;

                // Regula 1: Autentificări Eșuate (Brute Force)
                if (ev.EventId == 4625)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Tentativă eșuată de autentificare (Brute Force)",
                        Severity = "High",
                        Explanation = $"Eveniment de securitate (EID 4625) detectat pe mașina [{ev.MachineName}]. Indică o posibilă tentativă de tip Brute Force sau scanare parole.",
                        ComplianceTag = "ISO 27001 - A.12.4.1",
                        MitreTechniqueId = "T1110",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 2: Ștergerea Jurnalelor de Securitate (Evaziune)
                else if (ev.EventId == 1102 || ev.EventId == 104)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Jurnal de securitate curățat / șters",
                        Severity = "Critical",
                        Explanation = $"Jurnalul de evenimente a fost curățat manual pe mașina [{ev.MachineName}] (EID {ev.EventId}). Acesta este un indicator puternic de ascundere a urmelor (Defense Evasion).",
                        ComplianceTag = "HG 585/2002 - Audit Securitate",
                        MitreTechniqueId = "T1070.001",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 3: Creare cont utilizator local (Persistență)
                else if (ev.EventId == 4720)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Cont utilizator local nou creat",
                        Severity = "High",
                        Explanation = $"Un cont de utilizator local nou a fost creat pe mașina [{ev.MachineName}] (EID 4720). Necesar audit de conformitate pentru a confirma validitatea creării.",
                        ComplianceTag = "ISO 27001 - A.9.2.1",
                        MitreTechniqueId = "T1136.001",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 4: Adăugare în grup administrativ (Privilege Escalation)
                else if (ev.EventId == 4732 || ev.EventId == 4728)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Utilizator adăugat în grup privilegiat",
                        Severity = "High",
                        Explanation = $"Un utilizator a fost adăugat într-un grup privilegiat local sau de domeniu pe mașina [{ev.MachineName}] (EID {ev.EventId}). Indică o posibilă escaladare de privilegii.",
                        ComplianceTag = "CIS Benchmark - Domain Admin Control",
                        MitreTechniqueId = "T1098",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 5: Serviciu nou instalat (Persistență / Execuție)
                else if (ev.EventId == 7045 || ev.EventId == 4697)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Serviciu de sistem nou instalat",
                        Severity = "Medium",
                        Explanation = $"Un serviciu nou a fost înregistrat în Windows pe mașina [{ev.MachineName}] (EID {ev.EventId}). Serviciile sunt utilizate frecvent pentru persistență de tip System Privilege.",
                        ComplianceTag = "NIST SP 800-53 - SI-4",
                        MitreTechniqueId = "T1543.003",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 6: Execuție proces suspect (T1059)
                else if (ev.EventId == 4688)
                {
                    string msg = ev.Message?.ToLowerInvariant() ?? string.Empty;
                    if (msg.Contains("powershell") && (msg.Contains("-enc") || msg.Contains("-encodedcommand") || msg.Contains("bypass") || msg.Contains("downloadstring")))
                    {
                        issues.Add(new DetectedIssue
                        {
                            Title = "Execuție PowerShell suspectă (Encoded/Bypass)",
                            Severity = "Critical",
                            Explanation = $"Comandă PowerShell suspectă detectată pe mașina [{ev.MachineName}]. Folosește tehnici de bypass ale politicilor de execuție sau codificări Base64.",
                            ComplianceTag = "NIST SP 800-53 - CM-7",
                            MitreTechniqueId = "T1059.001",
                            Status = AlertStatus.Nouă
                        });
                    }
                    else if (msg.Contains("vssadmin") && msg.Contains("delete") && msg.Contains("shadows"))
                    {
                        issues.Add(new DetectedIssue
                        {
                            Title = "Ștergere volume Shadow Copy (Ransomware)",
                            Severity = "Critical",
                            Explanation = $"Comandă de ștergere a copiilor de rezervă (vssadmin delete shadows) detectată pe mașina [{ev.MachineName}]. Comportament specific atacurilor de tip Ransomware.",
                            ComplianceTag = "ISO 27001 - A.12.3.1 (Backup)",
                            MitreTechniqueId = "T1490",
                            Status = AlertStatus.Nouă
                        });
                    }
                }
                // Regula Triage 1: Driver Kernel Nesemnat (Rootkit / BYOVD)
                else if (ev.EventId == 20102 && ev.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Driver Kernel Nesemnat Detectat (Rootkit / BYOVD)",
                        Severity = "Critical",
                        Explanation = $"Driver de kernel nesemnat sau cu certificat invalid identificat pe [{ev.MachineName}]. Reprezintă un risc major de securitate (Ring 0 exploit / rootkit).",
                        ComplianceTag = "CIS Benchmark - Kernel Integrity",
                        MitreTechniqueId = "T1068",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula Triage 2: Excludere Defender (Defense Evasion)
                else if (ev.EventId == 20105)
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Excludere Antivirus Windows Defender (Defense Evasion)",
                        Severity = "Critical",
                        Explanation = $"Excludere de cale sau proces configurată în Windows Defender pe [{ev.MachineName}]. Programele rău-intenționate folosesc excluderi pentru a ocoli detecția.",
                        ComplianceTag = "NIST SP 800-53 - SI-3",
                        MitreTechniqueId = "T1562.001",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula Triage 3: Scheduled Task Suspect
                else if (ev.EventId == 20103 && ev.Level.Equals("High", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Sarcină Programată Suspectă (Persistence)",
                        Severity = "High",
                        Explanation = $"Sarcină programată ce apelează scripturi din directoare temporare (%TEMP% / %APPDATA%) identificată pe [{ev.MachineName}].",
                        ComplianceTag = "ISO 27001 - A.12.5.1",
                        MitreTechniqueId = "T1053.005",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula Triage 4: DNS Cache către domeniu suspect
                else if (ev.EventId == 20101 && ev.Level.Equals("Warning", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Interogare DNS către Domeniu Suspect (C2 Communication)",
                        Severity = "High",
                        Explanation = $"Rezoluție DNS recentă către un domeniu cu reputație suspectă sau dynamic DNS identificată pe [{ev.MachineName}].",
                        ComplianceTag = "NIST SP 800-53 - SC-7",
                        MitreTechniqueId = "T1071.004",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula Triage 5: PowerShell History Suspect (EID 20109)
                else if (ev.EventId == 20109 && ev.Level.Equals("High", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Comandă Suspectă Identificată în Istoricul PowerShell",
                        Severity = "High",
                        Explanation = $"Comandă din istoricul utilizatorului conține indicatori de recunoaștere sau descărcare automată: {ev.Message}",
                        ComplianceTag = "MITRE ATT&CK - Command and Scripting Interpreter",
                        MitreTechniqueId = "T1059.001",
                        Status = AlertStatus.Nouă
                    });
                }
            }

            // 1. Evaluare dinamică a regulilor Sigma
            var sigmaIssues = _sigmaEngine.EvaluateEvents(eventList);
            foreach (var sIssue in sigmaIssues)
            {
                if (!issues.Any(i => i.MitreTechniqueId == sIssue.MitreTechniqueId))
                {
                    issues.Add(sIssue);
                }
            }

            // 2. Evaluare Semnături YARA
            var yaraIssues = _yaraEngine.Evaluate(eventList);
            foreach (var yIssue in yaraIssues)
            {
                issues.Add(yIssue);
            }

            // 3. Evaluare Anomalii & Entropie
            var anomalyIssues = _anomalyEngine.DetectAnomalies(eventList);
            foreach (var aIssue in anomalyIssues)
            {
                issues.Add(aIssue);
            }

            return issues;
        }

        public IEnumerable<DetectedIssue> AnalyzeRegistry(IEnumerable<RegistryArtifact> artifacts)
        {
            var issues = new List<DetectedIssue>();

            foreach (var reg in artifacts)
            {
                if (reg == null) continue;

                string key = reg.KeyPath?.ToLowerInvariant() ?? string.Empty;
                string value = reg.ValueName?.ToLowerInvariant() ?? string.Empty;
                string data = reg.ValueData?.ToLowerInvariant() ?? string.Empty;

                // Regula 1: Autostart Suspect (Persistence)
                if (key.Contains("\\run") || key.Contains("\\runonce"))
                {
                    if (data.Contains("powershell") || data.Contains("cmd.exe") || data.Contains("wscript") || data.Contains("mshta") || data.Contains("temp\\"))
                    {
                        issues.Add(new DetectedIssue
                        {
                            Title = "Execuție suspectă la pornire sistem (Registry Run)",
                            Severity = "High",
                            Explanation = $"Program suspect înregistrat la pornirea automată în registrul [{reg.KeyPath}]. Rularea scripturilor din foldere temporare indică persistență malware.",
                            ComplianceTag = "ISO 27001 - A.12.5.1",
                            MitreTechniqueId = "T1547.001",
                            Status = AlertStatus.Nouă
                        });
                    }
                }
                // Regula 2: WDigest Cleartext Credential Caching enabled (Credential Access)
                else if (key.Contains("wdigest") && value.Contains("uselogoncredential") && data.Contains("1"))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "WDigest Credential Caching activat (Parole în clar)",
                        Severity = "High",
                        Explanation = $"Setarea WDigest 'UseLogonCredential' este activată în [{reg.KeyPath}]. Aceasta forțează LSASS să stocheze parolele în clar în memorie, facilitând dumping-ul.",
                        ComplianceTag = "NIST SP 800-53 - IA-2",
                        MitreTechniqueId = "T1003.001",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 3: Windows Defender Disabled (Defenses Impaired)
                else if (key.Contains("windows defender") && value.Contains("disableantispyware") && data.Contains("1"))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Antivirus Windows Defender dezactivat prin Registry GPO",
                        Severity = "Critical",
                        Explanation = $"Valoarea 'DisableAntiSpyware' este activată în [{reg.KeyPath}]. Protecția antivirus integrată a mașinii a fost oprită prin politici de grup administrative.",
                        ComplianceTag = "NIST SP 800-53 - SI-3",
                        MitreTechniqueId = "T1562.001",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 4: User Account Control (UAC) Disabled (Privilege Escalation Bypass)
                else if (key.Contains("policies\\system") && value.Contains("enablelua") && data.Equals("0"))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Control cont utilizator (UAC) dezactivat",
                        Severity = "High",
                        Explanation = $"Valoarea UAC 'EnableLUA' este setată pe 0 în [{reg.KeyPath}]. Aceasta permite proceselor administrative să ruleze automat fără aprobarea manuală a utilizatorului.",
                        ComplianceTag = "CIS Benchmark - User Account Control",
                        MitreTechniqueId = "T1548.002",
                        Status = AlertStatus.Nouă
                    });
                }
                // Regula 5: NLA RDP Disabled (External Remote Access)
                else if (key.Contains("terminal server\\winstations\\rdp-tcp") && value.Contains("userauthentication") && data.Equals("0"))
                {
                    issues.Add(new DetectedIssue
                    {
                        Title = "Autentificare la nivel de rețea (NLA) dezactivată pentru RDP",
                        Severity = "Medium",
                        Explanation = $"Network Level Authentication (NLA) este dezactivată în [{reg.KeyPath}]. Permite conexiuni RDP fără validarea preliminară a credențialelor, facilitând atacurile BlueKeep sau brute force.",
                        ComplianceTag = "ISO 27001 - A.13.1.1",
                        MitreTechniqueId = "T1133",
                        Status = AlertStatus.Nouă
                    });
                }
            }

            return issues;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Engines
{
    public class YaraRule
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string MitreId { get; set; } = "T1059";
        public List<string> StringPatterns { get; set; } = new();
        public List<string> RegexPatterns { get; set; } = new();
        public int MatchCount { get; set; }
    }

    public class YaraRuleEngine
    {
        public List<YaraRule> Rules { get; } = new();

        public YaraRuleEngine()
        {
            InitializeDefaultRules();
        }

        private void InitializeDefaultRules()
        {
            Rules.Add(new YaraRule
            {
                Name = "Webshell_PHP_JSP_Generic",
                Description = "Detectează tipare specifice de Web Shell (eval, passthru, base64_decode, Runtime.getRuntime)",
                Severity = "Critical",
                MitreId = "T1505.003",
                StringPatterns = new List<string> { "eval(base64_decode", "passthru($_POST", "shell_exec($_GET", "Runtime.getRuntime().exec(" }
            });

            Rules.Add(new YaraRule
            {
                Name = "Mimikatz_Credential_Dumper_Strings",
                Description = "Detectează comenzi și string-uri asociate utilitarului Mimikatz (sekurlsa, logonpasswords, lsadump)",
                Severity = "Critical",
                MitreId = "T1003.001",
                StringPatterns = new List<string> { "sekurlsa::logonpasswords", "lsadump::sam", "sekurlsa::wdigest", "privilege::debug", "token::elevate" }
            });

            Rules.Add(new YaraRule
            {
                Name = "CobaltStrike_NamedPipe_Default",
                Description = "Detectează tipare de Named Pipes folosite de Cobalt Strike Beacons",
                Severity = "Critical",
                MitreId = "T1071",
                RegexPatterns = new List<string> { @"\\pipe\\msse-[0-9a-f]{4}-server", @"\\pipe\\status_[0-9a-f]{4}", @"\\pipe\\postex_[0-9a-f]{4}" }
            });

            Rules.Add(new YaraRule
            {
                Name = "PowerShell_DownloadCradle_Suspicious",
                Description = "Detectează metode avansate de descărcare și execuție în memorie fără salvare pe disc (IEX WebClient)",
                Severity = "High",
                MitreId = "T1059.001",
                StringPatterns = new List<string> { "DownloadString(", "DownloadData(", "Net.WebClient).DownloadFile", "BitConverter.ToString([System.Security.Cryptography" }
            });

            Rules.Add(new YaraRule
            {
                Name = "Ransomware_ShadowCopy_InhibitRecovery",
                Description = "Detectează comenzi agresive de ștergere a punctelor de restaurare și jurnalelor USN (vssadmin, wbadmin, bcdedit)",
                Severity = "Critical",
                MitreId = "T1490",
                StringPatterns = new List<string> { "bcdedit /set {default} bootstatuspolicy ignoreallfailures", "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog -quiet" }
            });
        }

        public List<DetectedIssue> Evaluate(IEnumerable<ParsedEvent> events)
        {
            var issues = new List<DetectedIssue>();

            foreach (var rule in Rules)
            {
                rule.MatchCount = 0;
            }

            foreach (var ev in events)
            {
                string text = $"{ev.Message} {ev.XmlData}";
                if (string.IsNullOrWhiteSpace(text)) continue;

                foreach (var rule in Rules)
                {
                    bool matched = false;

                    foreach (var sp in rule.StringPatterns)
                    {
                        if (text.Contains(sp, StringComparison.OrdinalIgnoreCase))
                        {
                            matched = true;
                            break;
                        }
                    }

                    if (!matched)
                    {
                        foreach (var rp in rule.RegexPatterns)
                        {
                            if (Regex.IsMatch(text, rp, RegexOptions.IgnoreCase))
                            {
                                matched = true;
                                break;
                            }
                        }
                    }

                    if (matched)
                    {
                        rule.MatchCount++;
                        issues.Add(new DetectedIssue
                        {
                            Title = $"Potrivire Regulă YARA: {rule.Name}",
                            Severity = rule.Severity,
                            Explanation = $"{rule.Description}\n\nSursă: EID {ev.EventId} pe {ev.MachineName} la {ev.TimeCreated:yyyy-MM-dd HH:mm:ss}.\nText extras: {Truncate(text, 250)}",
                            ComplianceTag = $"YARA Signature - {rule.Name}",
                            MitreTechniqueId = rule.MitreId,
                            MitreTacticName = "Threat Detection",
                            Status = AlertStatus.Nouă,
                            RelatedEvents = new List<ParsedEvent> { ev }
                        });
                    }
                }
            }

            return issues;
        }

        private static string Truncate(string str, int maxLen)
        {
            if (string.IsNullOrEmpty(str)) return string.Empty;
            return str.Length <= maxLen ? str : str.Substring(0, maxLen) + "...";
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Engines
{
    public class SigmaRuleDefinition
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string MitreTechnique { get; set; } = string.Empty;
        public string ComplianceTag { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string YamlContent { get; set; } = string.Empty;
        public int MatchCount { get; set; } = 0;
        public Func<ParsedEvent, bool> MatchPredicate { get; set; } = _ => false;
    }

    public class SigmaRuleEngine
    {
        private readonly List<SigmaRuleDefinition> _rules = new();

        public SigmaRuleEngine()
        {
            InitializeDefaultRules();
        }

        public IReadOnlyList<SigmaRuleDefinition> Rules => _rules;

        public IEnumerable<DetectedIssue> EvaluateEvents(IEnumerable<ParsedEvent> events)
        {
            var issues = new List<DetectedIssue>();
            var eventList = events.ToList();

            // Reset match counts
            foreach (var r in _rules) r.MatchCount = 0;

            foreach (var rule in _rules)
            {
                var matchingEvents = eventList.Where(rule.MatchPredicate).ToList();
                rule.MatchCount = matchingEvents.Count;

                if (matchingEvents.Count > 0)
                {
                    var firstMatch = matchingEvents.First();
                    issues.Add(new DetectedIssue
                    {
                        Title = $"[Sigma] {rule.Title}",
                        Severity = rule.Severity,
                        Explanation = $"{rule.Description} (Total detecții: {matchingEvents.Count}, prima pe mașina [{firstMatch.MachineName}]).",
                        ComplianceTag = rule.ComplianceTag,
                        MitreTechniqueId = rule.MitreTechnique,
                        Status = AlertStatus.Nouă
                    });
                }
            }

            return issues;
        }

        private void InitializeDefaultRules()
        {
            _rules.Add(new SigmaRuleDefinition
            {
                Id = "f3a8d9a2-94a2-4a0b-bf3e-ff2b32c59562",
                Title = "Suspicious PowerShell Encoded Command",
                Severity = "Critical",
                MitreTechnique = "T1059.001",
                ComplianceTag = "NIST SP 800-53 - CM-7",
                FilePath = "rules/powershell_encoded.yml",
                Description = "Detectează comenzi codificate Base64 sau parametri de bypass ai politicilor de execuție transmiși către PowerShell.",
                YamlContent = @"title: Suspicious PowerShell Encoded Command
id: f3a8d9a2-94a2-4a0b-bf3e-ff2b32c59562
status: stable
description: Detects base64 encoded commands and execution policy bypass passed to PowerShell
logsource:
    product: windows
    service: security / sysmon
detection:
    selection:
        EventID: [4688, 1, 4104]
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'bypass'
            - 'downloadstring'
            - 'iex'
    condition: selection
level: critical",
                MatchPredicate = ev =>
                {
                    if (ev.EventId == 4688 || ev.EventId == 4104 || ev.EventId == 1)
                    {
                        string msg = (ev.Message + " " + ev.XmlData).ToLowerInvariant();
                        return (msg.Contains("powershell") || msg.Contains("pwsh")) &&
                               (msg.Contains("-enc") || msg.Contains("-encodedcommand") || msg.Contains("bypass") || msg.Contains("downloadstring") || msg.Contains("iex("));
                    }
                    return false;
                }
            });

            _rules.Add(new SigmaRuleDefinition
            {
                Id = "a2b8d9c2-9014-41e9-9fa6-c00bb24e392a",
                Title = "Volume Shadow Copy Deletion via VSSAdmin",
                Severity = "Critical",
                MitreTechnique = "T1490",
                ComplianceTag = "ISO 27001 - A.12.3.1",
                FilePath = "rules/vssadmin_delete.yml",
                Description = "Detectează comportament specific atacurilor Ransomware ce încearcă ștergerea copiilor de rezervă (Volume Shadow Copies).",
                YamlContent = @"title: Volume Shadow Copy Deletion via VSSAdmin
id: a2b8d9c2-9014-41e9-9fa6-c00bb24e392a
status: stable
description: Detects ransomware behavior deleting system backup shadow copies
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
    condition: selection
level: critical",
                MatchPredicate = ev =>
                {
                    string msg = (ev.Message + " " + ev.XmlData).ToLowerInvariant();
                    return msg.Contains("vssadmin") && msg.Contains("delete") && msg.Contains("shadows");
                }
            });

            _rules.Add(new SigmaRuleDefinition
            {
                Id = "c102a8e1-512a-4318-912f-874b2190ee01",
                Title = "Windows Event Log Cleared (Indicator Removal)",
                Severity = "Critical",
                MitreTechnique = "T1070.001",
                ComplianceTag = "HG 585/2002 - Securitate Jurnale",
                FilePath = "rules/eventlog_cleared.yml",
                Description = "Detectează golirea intenționată a jurnalelor de evenimente Security sau System în scopul evaziunii forenzice.",
                YamlContent = @"title: Windows Event Log Cleared
id: c102a8e1-512a-4318-912f-874b2190ee01
status: stable
description: Detects clearing of Windows event logs to conceal unauthorized activities
logsource:
    product: windows
    service: security / system
detection:
    selection:
        EventID: [1102, 104]
    condition: selection
level: critical",
                MatchPredicate = ev => ev.EventId == 1102 || ev.EventId == 104
            });

            _rules.Add(new SigmaRuleDefinition
            {
                Id = "d77b219a-412e-48f1-8842-10f82190cc11",
                Title = "Unsigned Kernel Driver Detection (Rootkit / BYOVD)",
                Severity = "Critical",
                MitreTechnique = "T1068",
                ComplianceTag = "CIS Benchmark - Kernel Integrity",
                FilePath = "rules/unsigned_kernel_driver.yml",
                Description = "Detectează drivere kernel fără semnătură digitală Authenticode validă pe sistemul auditat.",
                YamlContent = @"title: Unsigned Kernel Driver Detection
id: d77b219a-412e-48f1-8842-10f82190cc11
status: experimental
description: Detects unsigned kernel-mode drivers potentially carrying rootkit payloads
logsource:
    product: windows
    service: triage_drivers
detection:
    selection:
        EventID: 20102
        Level: 'Critical'
    condition: selection
level: critical",
                MatchPredicate = ev => ev.EventId == 20102 && ev.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase)
            });

            _rules.Add(new SigmaRuleDefinition
            {
                Id = "e8812a77-3310-4bc2-8172-bb91204011fa",
                Title = "Antivirus Defender Exclusion Added (Defense Evasion)",
                Severity = "Critical",
                MitreTechnique = "T1562.001",
                ComplianceTag = "NIST SP 800-53 - SI-3",
                FilePath = "rules/defender_exclusion_added.yml",
                Description = "Detectează excluderea deliberată a unor foldere sau executabile din scanarea în timp real a Windows Defender.",
                YamlContent = @"title: Antivirus Defender Exclusion Added
id: e8812a77-3310-4bc2-8172-bb91204011fa
status: stable
description: Detects path or process exclusions configured in Windows Defender
logsource:
    product: windows
    service: triage_defender
detection:
    selection:
        EventID: 20105
    condition: selection
level: critical",
                MatchPredicate = ev => ev.EventId == 20105
            });

            _rules.Add(new SigmaRuleDefinition
            {
                Id = "df3a8081-a7b2-4f32-bc81-c77673a38212",
                Title = "Credential Dumping via LSASS Memory Access",
                Severity = "Critical",
                MitreTechnique = "T1003.001",
                ComplianceTag = "NIST SP 800-53 - IA-2",
                FilePath = "rules/lsass_credential_dumping.yml",
                Description = "Detectează tentative de deschidere a procesului LSASS pentru extragerea credențialelor din memorie.",
                YamlContent = @"title: Credential Dumping via LSASS Memory Access
id: df3a8081-a7b2-4f32-bc81-c77673a38212
status: experimental
description: Detects access requests to LSASS process memory for dumping credentials
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: [4656, 4663, 10]
        ObjectName|endswith: '\lsass.exe'
    condition: selection
level: critical",
                MatchPredicate = ev =>
                {
                    if (ev.EventId == 4656 || ev.EventId == 4663 || ev.EventId == 10)
                    {
                        string msg = (ev.Message + " " + ev.XmlData).ToLowerInvariant();
                        return msg.Contains("lsass.exe");
                    }
                    return false;
                }
            });
        }
    }
}

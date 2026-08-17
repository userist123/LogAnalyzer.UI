using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AttackStorylineEngine
    {
        public AttackStoryline GenerateStoryline(IEnumerable<DetectedIssue> issues)
        {
            var storyline = new AttackStoryline();
            var issueList = issues?.ToList() ?? new List<DetectedIssue>();

            if (issueList.Count == 0)
            {
                storyline.IncidentTitle = "Niciun atac activ corelat";
                storyline.OverallSummary = "Jurnalele analizate nu conțin suficiente corelări pentru a construi un vector de atac multi-stadiu.";
                storyline.RiskLevel = "SCĂZUT (Normal)";
                storyline.ThreatSeverityScore = 10;
                return storyline;
            }

            var nodes = new List<AttackStorylineNode>();
            int stageIndex = 1;

            // 1. Initial Access
            var initialAccess = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1190") || i.MitreTechniqueId.StartsWith("T1110") || i.MitreTechniqueId.StartsWith("T1133"))) ||
                i.Title.Contains("Brute Force") || i.Title.Contains("Autentificare"));
            if (initialAccess != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "1. Acces Inițial (Initial Access)",
                    StageIcon = "🚪",
                    TechniqueId = initialAccess.MitreTechniqueId ?? "T1110",
                    Title = initialAccess.Title,
                    Description = initialAccess.Explanation,
                    Severity = initialAccess.Severity,
                    SeverityColor = GetSeverityColor(initialAccess.Severity),
                    Timestamp = initialAccess.CreatedAt,
                    ConfidenceScore = 90
                });
            }

            // 2. Execution
            var execution = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1059") || i.MitreTechniqueId.StartsWith("T1204") || i.MitreTechniqueId.StartsWith("T1047"))) ||
                i.Title.Contains("PowerShell") || i.Title.Contains("Execuție") || i.Title.Contains("Entropie"));
            if (execution != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "2. Execuție Payload (Execution)",
                    StageIcon = "⚡",
                    TechniqueId = execution.MitreTechniqueId ?? "T1059.001",
                    Title = execution.Title,
                    Description = execution.Explanation,
                    Severity = execution.Severity,
                    SeverityColor = GetSeverityColor(execution.Severity),
                    Timestamp = execution.CreatedAt,
                    ConfidenceScore = 95
                });
            }

            // 3. Persistence
            var persistence = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1547") || i.MitreTechniqueId.StartsWith("T1053") || i.MitreTechniqueId.StartsWith("T1136") || i.MitreTechniqueId.StartsWith("T1543"))) ||
                i.Title.Contains("Persistență") || i.Title.Contains("Run") || i.Title.Contains("Serviciu") || i.Title.Contains("Sarcină"));
            if (persistence != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "3. Mecanisme Persistență (Persistence)",
                    StageIcon = "⚓",
                    TechniqueId = persistence.MitreTechniqueId ?? "T1547.001",
                    Title = persistence.Title,
                    Description = persistence.Explanation,
                    Severity = persistence.Severity,
                    SeverityColor = GetSeverityColor(persistence.Severity),
                    Timestamp = persistence.CreatedAt,
                    ConfidenceScore = 88
                });
            }

            // 4. Privilege Escalation / Masquerading
            var privEsc = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1548") || i.MitreTechniqueId.StartsWith("T1068") || i.MitreTechniqueId.StartsWith("T1098"))) ||
                i.Title.Contains("Privilegii") || i.Title.Contains("Masquerading") || i.Title.Contains("UAC") || i.Title.Contains("Kernel"));
            if (privEsc != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "4. Escaladare Privilegii (Privilege Escalation)",
                    StageIcon = "👑",
                    TechniqueId = privEsc.MitreTechniqueId ?? "T1548.002",
                    Title = privEsc.Title,
                    Description = privEsc.Explanation,
                    Severity = privEsc.Severity,
                    SeverityColor = GetSeverityColor(privEsc.Severity),
                    Timestamp = privEsc.CreatedAt,
                    ConfidenceScore = 92
                });
            }

            // 5. Defense Evasion
            var defenseEvasion = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1070") || i.MitreTechniqueId.StartsWith("T1562") || i.MitreTechniqueId.StartsWith("T1036"))) ||
                i.Title.Contains("șters") || i.Title.Contains("Defender") || i.Title.Contains("Evaziune") || i.Title.Contains("Excludere"));
            if (defenseEvasion != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "5. Evaziune Defensivă (Defense Evasion)",
                    StageIcon = "🛡️",
                    TechniqueId = defenseEvasion.MitreTechniqueId ?? "T1070.001",
                    Title = defenseEvasion.Title,
                    Description = defenseEvasion.Explanation,
                    Severity = defenseEvasion.Severity,
                    SeverityColor = GetSeverityColor(defenseEvasion.Severity),
                    Timestamp = defenseEvasion.CreatedAt,
                    ConfidenceScore = 95
                });
            }

            // 6. Credential Access
            var credAccess = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1003") || i.MitreTechniqueId.StartsWith("T1555"))) ||
                i.Title.Contains("Mimikatz") || i.Title.Contains("WDigest") || i.Title.Contains("Parole") || i.Title.Contains("LSASS"));
            if (credAccess != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "6. Acces Credențiale (Credential Access)",
                    StageIcon = "🔑",
                    TechniqueId = credAccess.MitreTechniqueId ?? "T1003.001",
                    Title = credAccess.Title,
                    Description = credAccess.Explanation,
                    Severity = credAccess.Severity,
                    SeverityColor = GetSeverityColor(credAccess.Severity),
                    Timestamp = credAccess.CreatedAt,
                    ConfidenceScore = 96
                });
            }

            // 7. Impact / Lateral Movement / Ransomware
            var impact = issueList.FirstOrDefault(i => 
                (i.MitreTechniqueId != null && (i.MitreTechniqueId.StartsWith("T1490") || i.MitreTechniqueId.StartsWith("T1486") || i.MitreTechniqueId.StartsWith("T1071"))) ||
                i.Title.Contains("Ransomware") || i.Title.Contains("Shadow") || i.Title.Contains("C2") || i.Title.Contains("Cobalt"));
            if (impact != null)
            {
                nodes.Add(new AttackStorylineNode
                {
                    StageIndex = stageIndex++,
                    StageName = "7. Impact & C2 (Command and Control / Impact)",
                    StageIcon = "💥",
                    TechniqueId = impact.MitreTechniqueId ?? "T1490",
                    Title = impact.Title,
                    Description = impact.Explanation,
                    Severity = impact.Severity,
                    SeverityColor = GetSeverityColor(impact.Severity),
                    Timestamp = impact.CreatedAt,
                    ConfidenceScore = 98
                });
            }

            storyline.Nodes = nodes;
            storyline.TotalStagesDetected = nodes.Count;

            // Generate overall executive narrative
            var sb = new StringBuilder();
            sb.AppendLine($"Atacatorul a parcurs cu succes {nodes.Count} stadii critice din lanțul cibernetic (Cyber Kill Chain).");
            if (initialAccess != null) sb.AppendLine($"• Punct de intrare: {initialAccess.Title}.");
            if (execution != null) sb.AppendLine($"• Execuție inițială: {execution.Title}.");
            if (persistence != null) sb.AppendLine($"• Ancorare în sistem (Persistență): {persistence.Title}.");
            if (defenseEvasion != null) sb.AppendLine($"• Neutralizare mecanisme de apărare: {defenseEvasion.Title}.");
            if (impact != null) sb.AppendLine($"• Obiectiv final malițios: {impact.Title}.");

            storyline.OverallSummary = sb.ToString();
            storyline.ThreatSeverityScore = Math.Min(99, 45 + nodes.Count * 12);
            storyline.RiskLevel = storyline.ThreatSeverityScore >= 80 ? "CRITIC" : storyline.ThreatSeverityScore >= 50 ? "RIDICAT" : "MODERAT";

            return storyline;
        }

        private string GetSeverityColor(string severity) => severity switch
        {
            "Critical" => "#ef4444",
            "High" => "#f97316",
            "Medium" => "#f59e0b",
            _ => "#38bdf8"
        };
    }
}

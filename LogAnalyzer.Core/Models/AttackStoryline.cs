using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    public class AttackStorylineNode
    {
        public int StageIndex { get; set; }
        public string StageName { get; set; } = string.Empty; // ex: "Initial Access", "Execution", "Persistence"
        public string StageIcon { get; set; } = "🎯";
        public string TechniqueId { get; set; } = string.Empty; // ex: "T1110"
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string TargetHost { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string SeverityColor { get; set; } = "#f97316";
        public DateTime Timestamp { get; set; }
        public double ConfidenceScore { get; set; } = 85.0; // 0-100%
    }

    public class AttackStoryline
    {
        public string IncidentTitle { get; set; } = "Campanie de Atac Detectată (Multi-Stage Kill Chain)";
        public string OverallSummary { get; set; } = string.Empty;
        public int TotalStagesDetected { get; set; }
        public double ThreatSeverityScore { get; set; } // 0-100
        public string RiskLevel { get; set; } = "CRITIC";
        public List<AttackStorylineNode> Nodes { get; set; } = new();
    }
}

using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    /// <summary>
    /// Rezultat investigație generat de AI Copilot DFIR Assistant.
    /// </summary>
    public class CopilotInvestigationResult
    {
        public string Title { get; set; } = string.Empty;
        public string ExecutiveSummaryRo { get; set; } = string.Empty;
        public string MitreKillChainMapping { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = "High";
        public List<string> ForensicEvidenceBullets { get; set; } = new();
        public List<string> RecommendedContainmentSteps { get; set; } = new();
        public string RegulatoryImpactRo { get; set; } = string.Empty;
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }
}

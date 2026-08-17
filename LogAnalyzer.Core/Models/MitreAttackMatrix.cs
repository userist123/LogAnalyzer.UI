using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    public class MitreTechniqueCell
    {
        public string TacticId { get; set; } = string.Empty;
        public string TacticName { get; set; } = string.Empty;
        public string TechniqueId { get; set; } = string.Empty;
        public string TechniqueName { get; set; } = string.Empty;
        public int DetectedCount { get; set; } = 0;
        public bool IsDetected => DetectedCount > 0;
        public bool IsCoveredByRules { get; set; } = true;
        public string StatusColor => IsDetected ? "#ef4444" : IsCoveredByRules ? "#1e293b" : "#0f172a";
        public string TooltipText => $"{TechniqueId}: {TechniqueName}\nDetecții în sesiune: {DetectedCount}\nAcoperire Sigma/YARA: {(IsCoveredByRules ? "Da" : "Nu")}";
    }

    public class MitreTacticColumn
    {
        public string TacticId { get; set; } = string.Empty;
        public string TacticName { get; set; } = string.Empty;
        public int TotalTechniques { get; set; }
        public int DetectedTechniquesCount { get; set; }
        public double CoveragePercentage { get; set; } = 85.0;
        public List<MitreTechniqueCell> Techniques { get; set; } = new();
    }

    public class MitreMatrixHeatmap
    {
        public List<MitreTacticColumn> Columns { get; set; } = new();
        public int TotalObservedTechniques { get; set; }
        public double OverallVisibilityCoverage { get; set; } = 78.5; // DeTT&CT Model
    }
}

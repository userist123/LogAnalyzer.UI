using System;

namespace LogAnalyzer.Core.Models
{
    public class TimelineItem
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string? Severity { get; set; } = "Informativ";
        public string? MitreTags { get; set; }
        public string UserOrHost { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string SeverityColor => Severity?.ToLowerInvariant() switch
        {
            "critic" or "critical" or "high" => "#ef4444",
            "avertizare" or "warning" or "medium" => "#fbbf24",
            _ => "#22ff88"
        };
        public string DotColor => SeverityColor;
    }
}
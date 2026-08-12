using System;

namespace LogAnalyzer.Core.Models
{
    public class TimelineItem
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string? Severity { get; set; }
        public string? MitreTags { get; set; }
        public string UserOrHost { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
}
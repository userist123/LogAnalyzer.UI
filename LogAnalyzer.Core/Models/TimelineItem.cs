using System;

namespace LogAnalyzer.Core.Models;

public class TimelineItem
{
    public string Source { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string UserOrHost { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

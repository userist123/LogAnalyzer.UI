using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models;

public class ParsedEvent
{
    public long EventId { get; set; }
    public DateTime TimeCreated { get; set; }
    public string ProviderName { get; set; } = string.Empty;
    public string Level { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string RawData { get; set; } = string.Empty;
    public string? OfficialDescription { get; set; }
    public string? TacticalExample { get; set; }
    public string? ReferenceUrl { get; set; }
    public string? PotentialCriticality { get; set; }
    public List<string> Tags { get; set; } = new();
}

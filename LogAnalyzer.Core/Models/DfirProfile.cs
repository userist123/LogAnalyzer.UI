using System.Collections.Generic;

namespace LogAnalyzer.Core.Models;

public class DfirProfile
{
    public string Name { get; set; } = string.Empty;
    public List<long> TargetEventIds { get; set; } = new();
}

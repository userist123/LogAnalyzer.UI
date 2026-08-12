namespace LogAnalyzer.Core.Models;

public class KnowledgeBaseEntry
{
    public int EventId { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string HumanTitle { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
    public string RemediationTemplate { get; set; } = string.Empty;
    public int ThresholdForAlert { get; set; }
}
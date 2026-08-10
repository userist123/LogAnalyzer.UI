namespace LogAnalyzer.Core.Models;

public class RegistryArtifact
{
    public string Category { get; set; } = string.Empty;
    public string KeyPath { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string ValueData { get; set; } = string.Empty;
}

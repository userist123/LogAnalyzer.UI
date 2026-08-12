namespace LogAnalyzer.Core.Models
{
    public class RegistryArtifact
    {
        public string? Category { get; set; }
        public string? KeyPath { get; set; }
        public string? ValueName { get; set; }
        public string? ValueData { get; set; }
        public string? HiveType { get; set; }
        public string? SuspicionLevel { get; set; }
    }
}
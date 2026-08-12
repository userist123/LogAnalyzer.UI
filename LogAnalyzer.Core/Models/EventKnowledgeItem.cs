using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    public class EventKnowledgeItem
    {
        public string Category { get; set; } = string.Empty;
        public string SubCategory { get; set; } = string.Empty;
        public string EventID { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public string Channel { get; set; } = string.Empty;
        public string Provider { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new List<string>();
        public string MitreTTP { get; set; } = string.Empty;

        // Câmpuri noi extrase din CSV
        public string ExtendedDescription { get; set; } = string.Empty;
        public string EventExample { get; set; } = string.Empty;
        public string ReferenceUrl { get; set; } = string.Empty;
        public string PotentialCriticality { get; set; } = string.Empty;
    }
}
using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    /// <summary>
    /// Nod într-un arbore genealogic de procese corelate părinte-copil.
    /// </summary>
    public class CorrelatedProcessNode
    {
        public string ProcessId { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public string ParentProcessId { get; set; } = string.Empty;
        public string ParentProcessName { get; set; } = string.Empty;
        public string User { get; set; } = "SYSTEM";
        public DateTime ExecutionTime { get; set; } = DateTime.UtcNow;
        public bool IsSuspicious { get; set; } = false;
        public string AnomalyReason { get; set; } = string.Empty;
        public List<CorrelatedProcessNode> Children { get; set; } = new();
    }
}

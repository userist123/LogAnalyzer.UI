using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure;

public sealed class AnalysisEngine : IAnalysisEngine
{
    public IEnumerable<DetectedIssue> AnalyzeEvents(List<ParsedEvent> events)
    {
        var issues = new List<DetectedIssue>();

        var bruteForce = events.Where(e => e.EventId == 4625).ToList();
        if (bruteForce.Count >= 5)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Posibil atac de forță brută ({bruteForce.Count} autentificări eșuate)",
                Severity = "High",
                Explanation = "Detectate multiple evenimente EID 4625 (autentificare eșuată) pe aceeași stație.",
                MitreTechniqueId = "T1110",
                ComplianceTag = "HG585 Art. 282"
            });
        }

        var logClearing = events.Where(e => e.EventId == 1102 || e.EventId == 104).ToList();
        foreach (var evt in logClearing)
        {
            issues.Add(new DetectedIssue
            {
                Title = "Ștergere jurnal de evenimente detectată",
                Severity = "Critical",
                Explanation = $"Evenimentul EID {evt.EventId} indică o posibilă tentativă de evaziune prin ștergerea jurnalelor.",
                MitreTechniqueId = "T1070.001",
                ComplianceTag = "HG585 Art. 312"
            });
        }

        return issues;
    }
}

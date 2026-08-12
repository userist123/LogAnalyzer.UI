using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IAnalysisEngine
    {
        IEnumerable<DetectedIssue> AnalyzeEvents(IEnumerable<ParsedEvent> events);
        IEnumerable<DetectedIssue> AnalyzeRegistry(IEnumerable<RegistryArtifact> artifacts);
    }
}
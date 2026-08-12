using System.Collections.Generic;
using System.Threading;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IArtifactParser
    {
        string ParserName { get; }
        string SupportedFileExtension { get; }
        
        // Returnăm datele asincron, rând cu rând, pentru a nu bloca niciodată interfața
        IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(string filePath, CancellationToken cancellationToken);
    }
}
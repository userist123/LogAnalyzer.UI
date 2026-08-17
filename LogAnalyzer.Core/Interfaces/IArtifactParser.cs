using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IArtifactParser
    {
        string ParserName { get; }
        string SupportedFileExtension { get; }
        IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(string filePath, CancellationToken cancellationToken);
    }

    public interface IForensicArtifactParser
    {
        string ArtifactCategory { get; }
        string SupportedExtension { get; }
        bool CanParse(string filePath);
        Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default);
    }
}
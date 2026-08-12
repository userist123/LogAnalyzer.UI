using System.Collections.Generic;
using System.Threading;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public interface IPluginParser
    {
        string SupportedFileExtension { get; }
        IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(string filePath, CancellationToken token);
    }

    public class PluginManagerService
    {
        public List<IPluginParser> LoadedParsers { get; } = new();

        public PluginManagerService()
        {
            // Aici se vor încărca dinamic DLL-urile terțe folosind Reflection în etapele următoare
        }
    }
}
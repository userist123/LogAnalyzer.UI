using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Interfaces;

namespace LogAnalyzer.Plugins.AdvancedForensics
{
    public class ShimcacheParserPlugin : IArtifactParser
    {
        public string ParserName => "AppCompatCache / Shimcache Trace Analyzer";
        public string SupportedFileExtension => ".reg";

        public async IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(
            string filePath, 
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (!File.Exists(filePath)) yield break;

            int entriesFound = 0;
            
            foreach (var line in File.ReadLines(filePath))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (line.Contains("AppCompatCache", StringComparison.OrdinalIgnoreCase) || 
                    line.Contains("ControlSet", StringComparison.OrdinalIgnoreCase))
                {
                    entriesFound++;
                    
                    var parsedEvt = new ParsedEvent
                    {
                        EventId = 30003,
                        TimeCreated = DateTime.UtcNow,
                        ProviderName = "Forensics-Shimcache-Core",
                        Level = "Evidence",
                        MachineName = "Host-Extracted",
                        Message = $"[+] Urmă Shimcache detectată în registru: {line.Trim()}",
                        XmlData = $"Sursă fișier: {filePath}"
                    };

                    yield return parsedEvt;
                }
            }

            if (entriesFound == 0)
            {
                yield return new ParsedEvent
                {
                    EventId = 30004,
                    TimeCreated = DateTime.UtcNow,
                    ProviderName = "Forensics-Shimcache-Core",
                    Level = "Informativ",
                    MachineName = "Host-Extracted",
                    Message = "[i] Fișierul reg analizat nu conține structuri AppCompatCache vizibile.",
                    XmlData = filePath
                };
            }

            await Task.Yield();
        }
    }
}
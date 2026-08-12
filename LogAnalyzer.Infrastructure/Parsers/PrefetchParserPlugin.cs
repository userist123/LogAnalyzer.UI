using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Plugins.AdvancedForensics
{
    public class PrefetchParserPlugin : IArtifactParser
    {
        public string ParserName => "Windows Prefetch Execution Analyzer";
        public string SupportedFileExtension => ".pf";

        public async IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(
            string filePath, 
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (!File.Exists(filePath)) yield break;

            FileInfo fileInfo = new FileInfo(filePath);
            string executableName = Path.GetFileNameWithoutExtension(filePath);
            string details = "Analiză structurală Prefetch finalizată.";

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new BinaryReader(fs);

                if (fs.Length > 8)
                {
                    uint magic = reader.ReadUInt32();
                    if (magic == 0x4D414D04) 
                    {
                        uint decompressedSize = reader.ReadUInt32();
                        details = $"[Comprimat MAM] Dimensiune uncompressed estimată: {decompressedSize} bytes.";
                    }
                    else
                    {
                        details = "[Standard] Fișier Prefetch necomprimat.";
                    }
                }
            }
            catch (Exception ex)
            {
                details = $"Eroare la parsarea binară Prefetch: {ex.Message}";
            }

            var parsedEvt = new ParsedEvent
            {
                EventId = 40004,
                TimeCreated = fileInfo.LastWriteTimeUtc,
                ProviderName = "Forensics-Prefetch-Analyzer",
                Level = "Evidence",
                MachineName = "Host-Extracted",
                Message = $"[+] Execuție înregistrată în Prefetch: {executableName}\n{details}",
                XmlData = $"Cale fișier probă: {filePath}"
            };

            yield return parsedEvt;
            await Task.Yield();
        }
    }
}
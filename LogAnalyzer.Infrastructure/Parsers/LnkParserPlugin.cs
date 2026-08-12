using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Plugins.AdvancedForensics
{
    public class LnkParserPlugin : IArtifactParser
    {
        public string ParserName => "Windows Shell LNK Link Parser";
        public string SupportedFileExtension => ".lnk";

        public async IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(
            string filePath, 
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (!File.Exists(filePath)) yield break;

            FileInfo fileInfo = new FileInfo(filePath);
            string targetPath = "Necunoscut (Cale binară parsată parțial)";
            string machineInfo = "Local Host";

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new BinaryReader(fs);

                if (fs.Length >= 76)
                {
                    uint headerSize = reader.ReadUInt32();
                    if (headerSize == 0x0000004C)
                    {
                        fs.Seek(20, SeekOrigin.Current);
                        uint fileAttributes = reader.ReadUInt32();
                        
                        DateTime creationTime = DateTime.FromFileTimeUtc(reader.ReadInt64());
                        DateTime accessTime = DateTime.FromFileTimeUtc(reader.ReadInt64());
                        DateTime writeTime = DateTime.FromFileTimeUtc(reader.ReadInt64());

                        targetPath = $"Creat: {creationTime:yyyy-MM-dd HH:mm:ss} | Modificat: {writeTime:yyyy-MM-dd HH:mm:ss}";
                    }
                }
            }
            catch 
            {
                targetPath = "Eroare la citirea structurii interne a shortcut-ului.";
            }

            var parsedEvt = new ParsedEvent
            {
                EventId = 20002,
                TimeCreated = fileInfo.LastWriteTimeUtc,
                ProviderName = "Forensics-LNK-Analyzer",
                Level = "Evidence",
                MachineName = machineInfo,
                Message = $"[+] Scurtătură accesată / detectată: {Path.GetFileName(filePath)}\nDetalii țintă: {targetPath}",
                XmlData = $"Cale completă pe disc: {filePath}"
            };

            yield return parsedEvt;
            await Task.Yield();
        }
    }
}
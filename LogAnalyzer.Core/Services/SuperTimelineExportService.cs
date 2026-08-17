using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class SuperTimelineExportService
    {
        public void ExportPlasoCsv(
            string outputPath,
            IEnumerable<ParsedEvent> events,
            IEnumerable<ForensicArtifact> artifacts,
            IEnumerable<RegistryArtifact> registryEntries)
        {
            var sb = new StringBuilder();
            
            // Header standard Plaso / Timesketch / Eric Zimmerman Timeline Explorer
            sb.AppendLine("Date,Time,Timezone,MACB,Source,SourceType,Type,User,Host,Short,Desc,Version,Filename,Inode,Notes,Format,Extra");

            if (events != null)
            {
                foreach (var ev in events)
                {
                    string dateStr = ev.TimeCreated.ToString("MM/dd/yyyy");
                    string timeStr = ev.TimeCreated.ToString("HH:mm:ss");
                    string macb = "M..."; // Event log recorded timestamp
                    string source = "EVTX";
                    string sourceType = ev.ProviderName ?? "Windows Event Log";
                    string type = $"EID {ev.EventId}";
                    string user = ev.MachineName ?? "-";
                    string host = ev.MachineName ?? "-";
                    string shortDesc = EscapeCsv(ev.Level ?? "Info");
                    string desc = EscapeCsv(ev.Message ?? string.Empty);
                    string filename = "Security.evtx";

                    sb.AppendLine($"{dateStr},{timeStr},UTC,{macb},{source},{sourceType},{type},{user},{host},{shortDesc},{desc},2,{filename},-,-,LogAnalyzer EVTX Engine,-");
                }
            }

            if (artifacts != null)
            {
                foreach (var art in artifacts)
                {
                    string dateStr = art.Timestamp.ToString("MM/dd/yyyy");
                    string timeStr = art.Timestamp.ToString("HH:mm:ss");
                    string macb = art.TimestampSemantics switch
                    {
                        TimeSemantics.Created => "..B.",
                        TimeSemantics.LastExecution => ".A..",
                        TimeSemantics.Modified => "M...",
                        _ => "M..."
                    };
                    string source = art.ArtifactType;
                    string sourceType = art.Strength.ToString();
                    string type = "Forensic Artifact";
                    string user = "-";
                    string host = art.HostId ?? "-";
                    string shortDesc = EscapeCsv(art.Name);
                    string desc = EscapeCsv(art.Summary);
                    string filename = EscapeCsv(Path.GetFileName(art.SourceFilePath));

                    sb.AppendLine($"{dateStr},{timeStr},UTC,{macb},{source},{sourceType},{type},{user},{host},{shortDesc},{desc},2,{filename},-,-,LogAnalyzer Artifact Engine,-");
                }
            }

            if (registryEntries != null)
            {
                foreach (var reg in registryEntries)
                {
                    string dateStr = DateTime.UtcNow.ToString("MM/dd/yyyy");
                    string timeStr = DateTime.UtcNow.ToString("HH:mm:ss");
                    string macb = "M...";
                    string source = "Registry";
                    string sourceType = reg.Category ?? "Registry Key";
                    string type = "REG_KEY";
                    string user = "-";
                    string host = "-";
                    string shortDesc = EscapeCsv(reg.ValueName ?? string.Empty);
                    string desc = EscapeCsv($"{reg.KeyPath} -> {reg.ValueData}");
                    string filename = reg.HiveType ?? "Hive";

                    sb.AppendLine($"{dateStr},{timeStr},UTC,{macb},{source},{sourceType},{type},{user},{host},{shortDesc},{desc},2,{filename},-,-,LogAnalyzer Registry Engine,-");
                }
            }

            File.WriteAllText(outputPath, sb.ToString(), Encoding.UTF8);
        }

        private static string EscapeCsv(string field)
        {
            if (string.IsNullOrEmpty(field)) return "\"\"";
            string clean = field.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ");
            return $"\"{clean}\"";
        }
    }
}

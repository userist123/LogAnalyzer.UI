using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.Infrastructure
{
    public class EvtxParser : IEventParser
    {
        public IEnumerable<ParsedEvent> ParseEvtxFile(string filePath)
        {
            if (!File.Exists(filePath)) yield break;

            // Suprimăm avertismentul CA1416 care indică faptul că librăria e doar pentru Windows
            #pragma warning disable CA1416 
            using var reader = new EventLogReader(filePath, PathType.FilePath);
            EventRecord record;
            
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    string msg = $"Event ID {record.Id}";
                    try 
                    { 
                        msg = record.FormatDescription() ?? msg; 
                    } 
                    catch { /* Fallback dacă descrierea nu poate fi rezolvată nativ */ }

                    string level = "Info";
                    try { level = record.LevelDisplayName ?? "Info"; } catch { }

                    string xml = string.Empty;
                    try { xml = record.ToXml() ?? string.Empty; } catch { }

                    var ev = new ParsedEvent
                    {
                        EventId = (int)record.Id,
                        TimeCreated = record.TimeCreated ?? DateTime.Now,
                        ProviderName = record.ProviderName ?? "Windows",
                        Level = level,
                        MachineName = record.MachineName ?? "Local",
                        Message = msg,
                        XmlData = xml
                    };

                    var assessment = ForensicEventKnowledgeService.GetAssessment(ev);
                    ev.OfficialDescription = assessment.ThreatScenarioRo;
                    ev.TacticalExample = assessment.ContainmentPlaybookRo;
                    ev.PotentialCriticality = assessment.MitreTtpRo;

                    yield return ev;
                }
            }
            #pragma warning restore CA1416
        }
    }
}
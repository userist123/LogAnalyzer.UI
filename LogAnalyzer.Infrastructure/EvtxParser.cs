using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure;

public sealed class EvtxParser : IEventParser
{
    public IEnumerable<ParsedEvent> ParseEvtxFile(string filePath)
    {
        var results = new List<ParsedEvent>();
        EventLogReader? reader = null;
        try
        {
            var logQuery = new EventLogQuery(filePath, PathType.FilePath);
            reader = new EventLogReader(logQuery);
        }
        catch (EventLogException)
        {
            return results;
        }

        using (reader)
        {
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    string message;
                    try { message = record.FormatDescription() ?? string.Empty; }
                    catch (EventLogException) { message = string.Empty; }

                    results.Add(new ParsedEvent
                    {
                        EventId = record.Id,
                        TimeCreated = record.TimeCreated ?? DateTime.MinValue,
                        ProviderName = record.ProviderName ?? string.Empty,
                        Level = record.LevelDisplayName ?? record.Level?.ToString() ?? string.Empty,
                        MachineName = record.MachineName ?? Environment.MachineName,
                        Message = message,
                        RawData = record.ToXml() ?? string.Empty
                    });
                }
            }
        }

        return results;
    }
}

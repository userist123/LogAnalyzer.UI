using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure;

public sealed class EvtxParser : IEventParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

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

                    string rawXml;
                    try { rawXml = record.ToXml() ?? string.Empty; }
                    catch (EventLogException) { rawXml = string.Empty; }

                    var parsedEvent = new ParsedEvent
                    {
                        EventId = record.Id,
                        TimeCreated = record.TimeCreated ?? DateTime.MinValue,
                        ProviderName = record.ProviderName ?? string.Empty,
                        Level = record.LevelDisplayName ?? record.Level?.ToString() ?? string.Empty,
                        MachineName = record.MachineName ?? Environment.MachineName,
                        Message = message,
                        RawData = rawXml
                    };

                    PopulateStructuredFields(parsedEvent, rawXml);
                    results.Add(parsedEvent);
                }
            }
        }

        return results;
    }

    private static void PopulateStructuredFields(ParsedEvent parsedEvent, string rawXml)
    {
        if (string.IsNullOrWhiteSpace(rawXml)) return;

        XElement root;
        try
        {
            root = XElement.Parse(rawXml);
        }
        catch
        {
            return;
        }

        var eventData = root.Element(Ns + "EventData") ?? root.Element(Ns + "UserData");
        if (eventData == null) return;

        string GetField(params string[] names)
        {
            foreach (var name in names)
            {
                var value = eventData.Elements(Ns + "Data")
                    .FirstOrDefault(d => string.Equals((string?)d.Attribute("Name"), name, StringComparison.OrdinalIgnoreCase))
                    ?.Value;
                if (!string.IsNullOrWhiteSpace(value)) return value.Trim();

                var descendant = eventData.Descendants()
                    .FirstOrDefault(el => string.Equals(el.Name.LocalName, name, StringComparison.OrdinalIgnoreCase));
                if (descendant != null && !string.IsNullOrWhiteSpace(descendant.Value)) return descendant.Value.Trim();
            }
            return string.Empty;
        }

        parsedEvent.SubjectUserName = GetField("SubjectUserName");
        parsedEvent.TargetUserName = GetField("TargetUserName", "User", "AccountName");
        parsedEvent.IpAddress = GetField("IpAddress", "SourceIp", "SourceAddress").Replace("::ffff:", string.Empty);
        parsedEvent.LogonType = GetField("LogonType");
        parsedEvent.WorkstationName = GetField("WorkstationName", "Computer");
        parsedEvent.ProcessName = GetField("NewProcessName", "Image", "ProcessName", "ServiceFileName");
        parsedEvent.CommandLine = GetField("CommandLine");
        parsedEvent.ParentProcessName = GetField("ParentProcessName", "ParentImage");
    }
}

using System.Collections.Generic;

namespace LogAnalyzer.Core.Services;

public sealed class KnowledgeBaseService
{
    private readonly Dictionary<long, string> _officialDescriptions = new();

    public string? GetOfficialDescription(long eventId) =>
        _officialDescriptions.TryGetValue(eventId, out var value) ? value : null;

    public void RegisterDescription(long eventId, string description) =>
        _officialDescriptions[eventId] = description;
}

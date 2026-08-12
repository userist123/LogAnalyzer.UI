using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IDatabaseService
    {
        void InitializeDatabase();
        void ClearDatabase();
        void SaveEvents(IEnumerable<ParsedEvent> events);
        void SaveRegistryArtifacts(IEnumerable<RegistryArtifact> artifacts);
        void SaveTimeline(IEnumerable<TimelineItem> timelineItems);
        
        IEnumerable<ParsedEvent> GetEvents(int limit, int offset, string search, string profileName, List<int> targetEventIds);
        int GetEventsCount(string search, string profileName, List<int> targetEventIds);
        
        IEnumerable<RegistryArtifact> GetRegistryArtifacts(int limit, int offset, string search);
        int GetRegistryArtifactsCount(string search);
        
        IEnumerable<TimelineItem> GetTimeline(int limit, int offset, string search);
        int GetTimelineCount(string search);
        
        int GetUniqueHostsCount();
    }
}

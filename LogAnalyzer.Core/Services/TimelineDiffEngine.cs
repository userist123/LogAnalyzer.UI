using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class TimelineDiffResult
    {
        public List<TimelineItem> NewOrInjectedEvents { get; set; } = new();
        public List<TimelineItem> CommonBaselineEvents { get; set; } = new();
        public int TotalDiffCount => NewOrInjectedEvents.Count;
        public string SummaryRo { get; set; } = string.Empty;
    }

    public class TimelineDiffEngine
    {
        /// <summary>
        /// Compară cronologia unui sistem suspect cu o cronologie de bază (golden image / baseline curat)
        /// și izolează exclusiv evenimentele noi sau anomale introduse în timpul atacului.
        /// </summary>
        public TimelineDiffResult CompareTimelines(IEnumerable<TimelineItem> suspectTimeline, IEnumerable<TimelineItem> baselineTimeline)
        {
            var result = new TimelineDiffResult();
            if (suspectTimeline == null) return result;

            var baselineSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (baselineTimeline != null)
            {
                foreach (var item in baselineTimeline)
                {
                    // Semnătură unică bazată pe categorie, sursă și descriere
                    string sig = $"{item.Category}|{item.Source}|{item.Description.Trim()}";
                    baselineSet.Add(sig);
                }
            }

            foreach (var item in suspectTimeline)
            {
                string sig = $"{item.Category}|{item.Source}|{item.Description.Trim()}";
                if (!baselineSet.Contains(sig))
                {
                    result.NewOrInjectedEvents.Add(item);
                }
                else
                {
                    result.CommonBaselineEvents.Add(item);
                }
            }

            result.SummaryRo = $"Diferențial de Cronologie: Din {suspectTimeline.Count()} evenimente analizate pe hostul suspect, {result.TotalDiffCount} evenimente sunt UNICE (absențe din baseline-ul curat), reprezentând activitatea introdusă de atacator.";
            return result;
        }
    }
}

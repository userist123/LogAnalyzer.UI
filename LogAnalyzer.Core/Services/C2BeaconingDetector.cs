using System;
using System.Collections.Generic;
using System.Linq;

namespace LogAnalyzer.Core.Services
{
    public class BeaconingCandidate
    {
        public string Destination { get; set; } = string.Empty; // IP, Domeniu sau Canal
        public int ConnectionCount { get; set; }
        public double MeanIntervalSeconds { get; set; }
        public double StandardDeviationSeconds { get; set; }
        public double CoefficientOfVariation { get; set; } // CV = sigma / mu (< 0.15 = periodicitate certă)
        public double JitterPercent { get; set; }
        public string ThreatLevel { get; set; } = "Low";
        public string MitreTechniqueId { get; set; } = "T1071";
        public string Description { get; set; } = string.Empty;
    }

    public class C2BeaconingDetector
    {
        /// <summary>
        /// Analizează statistic intervalele de timp dintre conexiuni sau interogări pentru a demasca beaconing C2 automat.
        /// </summary>
        public List<BeaconingCandidate> AnalyzeConnections(IEnumerable<(string Destination, DateTime Timestamp)> events)
        {
            var results = new List<BeaconingCandidate>();
            if (events == null) return results;

            // Grupăm pe destinație (IP / Domeniu)
            var grouped = events
                .GroupBy(e => e.Destination)
                .Where(g => g.Count() >= 5); // Avem nevoie de cel puțin 5 conexiuni pentru relevanță statistică

            foreach (var group in grouped)
            {
                var sortedTimes = group.Select(e => e.Timestamp).OrderBy(t => t).ToList();
                var intervals = new List<double>();

                for (int i = 1; i < sortedTimes.Count; i++)
                {
                    double diffSec = (sortedTimes[i] - sortedTimes[i - 1]).TotalSeconds;
                    if (diffSec > 0 && diffSec < 86400) // Excludem pauzele mai mari de o zi
                    {
                        intervals.Add(diffSec);
                    }
                }

                if (intervals.Count < 4) continue;

                double mean = intervals.Average();
                if (mean <= 0) continue;

                double sumSquaredDiff = intervals.Sum(d => Math.Pow(d - mean, 2));
                double stdDev = Math.Sqrt(sumSquaredDiff / intervals.Count);
                double cv = stdDev / mean; // Coeficient de variație

                // Dacă CV < 0.20 sau există periodicitate rigidă
                if (cv < 0.25)
                {
                    double jitter = (stdDev / mean) * 100.0;
                    string threatLevel = "Low";
                    if (cv < 0.08) threatLevel = "Critical"; // Periodicitate matematică aproape perfectă
                    else if (cv < 0.15) threatLevel = "High";
                    else if (cv < 0.25) threatLevel = "Medium";

                    results.Add(new BeaconingCandidate
                    {
                        Destination = group.Key,
                        ConnectionCount = sortedTimes.Count,
                        MeanIntervalSeconds = Math.Round(mean, 1),
                        StandardDeviationSeconds = Math.Round(stdDev, 1),
                        CoefficientOfVariation = Math.Round(cv, 3),
                        JitterPercent = Math.Round(jitter, 1),
                        ThreatLevel = threatLevel,
                        MitreTechniqueId = "T1071.001",
                        Description = $"Comportament periodic automat detectat către [{group.Key}]: {sortedTimes.Count} conexiuni la fiecare ~{mean:N0} secunde (CV={cv:F2}, Jitter={jitter:F1}%). Probabilitate ridicată de canal Command & Control (C2)."
                    });
                }
            }

            return results.OrderByDescending(r => r.ThreatLevel == "Critical" ? 3 : r.ThreatLevel == "High" ? 2 : 1).ToList();
        }
    }
}

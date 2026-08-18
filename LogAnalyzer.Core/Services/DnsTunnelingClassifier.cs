using System;
using System.Collections.Generic;
using System.Linq;

namespace LogAnalyzer.Core.Services
{
    public class DnsAnomalyResult
    {
        public string QueryDomain { get; set; } = string.Empty;
        public double ShannonEntropy { get; set; }
        public int SubdomainLength { get; set; }
        public double ConsonantRatio { get; set; }
        public bool IsDgaCandidate { get; set; }
        public bool IsTunnelingCandidate { get; set; }
        public string MitreTechniqueId { get; set; } = "T1071.004";
        public string Reason { get; set; } = string.Empty;
    }

    public class DnsTunnelingClassifier
    {
        private static readonly HashSet<char> Vowels = new HashSet<char> { 'a', 'e', 'i', 'o', 'u', 'y' };

        /// <summary>
        /// Clasifică o listă de interogări DNS pentru a detecta tunelarea datelor (DNS Tunneling) și domenii generate algoritmic (DGA).
        /// </summary>
        public List<DnsAnomalyResult> AnalyzeDnsQueries(IEnumerable<string> domains)
        {
            var results = new List<DnsAnomalyResult>();
            if (domains == null) return results;

            foreach (var rawDomain in domains)
            {
                if (string.IsNullOrWhiteSpace(rawDomain)) continue;
                string domain = rawDomain.Trim().ToLowerInvariant();

                string[] parts = domain.Split('.');
                string mainSubdomain = parts.Length > 2 ? parts[0] : (parts.Length > 0 ? parts[0] : domain);

                double entropy = CalculateShannonEntropy(mainSubdomain);
                int subLength = mainSubdomain.Length;
                double consonantRatio = CalculateConsonantRatio(mainSubdomain);

                bool isTunneling = subLength > 40 || (subLength > 25 && entropy > 3.8);
                bool isDga = (entropy > 3.5 && consonantRatio > 0.75 && subLength >= 12) || (entropy > 4.0 && subLength >= 10);

                if (isTunneling || isDga)
                {
                    string reason = isTunneling 
                        ? $"Tunelare DNS suspectă (Lungime: {subLength} caractere, Entropie: {entropy:F2})" 
                        : $"Domeniu generat algoritmic (DGA) (Entropie: {entropy:F2}, Raport Consoane: {consonantRatio * 100:F0}%)";

                    results.Add(new DnsAnomalyResult
                    {
                        QueryDomain = rawDomain,
                        ShannonEntropy = entropy,
                        SubdomainLength = subLength,
                        ConsonantRatio = consonantRatio,
                        IsDgaCandidate = isDga,
                        IsTunnelingCandidate = isTunneling,
                        MitreTechniqueId = isTunneling ? "T1071.004" : "T1568.002",
                        Reason = reason
                    });
                }
            }

            return results;
        }

        private static double CalculateShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0.0;
            var freq = new Dictionary<char, int>();
            foreach (char c in s)
            {
                if (freq.ContainsKey(c)) freq[c]++;
                else freq[c] = 1;
            }

            double entropy = 0.0;
            double len = s.Length;
            foreach (var count in freq.Values)
            {
                double p = count / len;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static double CalculateConsonantRatio(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0.0;
            int letterCount = 0;
            int consonantCount = 0;

            foreach (char c in s)
            {
                if (char.IsLetter(c))
                {
                    letterCount++;
                    if (!Vowels.Contains(c)) consonantCount++;
                }
            }

            return letterCount == 0 ? 0.0 : (double)consonantCount / letterCount;
        }
    }
}

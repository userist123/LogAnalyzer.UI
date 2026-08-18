using System;
using System.Collections.Generic;
using System.Linq;

namespace LogAnalyzer.Core.Services
{
    public class ThreatFeedMatch
    {
        public string IocValue { get; set; } = string.Empty;
        public string ThreatActorOrCampaign { get; set; } = string.Empty;
        public string MalwareFamily { get; set; } = string.Empty;
        public string Confidence { get; set; } = "High";
        public string Description { get; set; } = string.Empty;
    }

    public class OfflineThreatFeedMatcher
    {
        private readonly Dictionary<string, ThreatFeedMatch> _knownHashes = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ThreatFeedMatch> _knownIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ThreatFeedMatch> _knownDomains = new(StringComparer.OrdinalIgnoreCase);

        public OfflineThreatFeedMatcher()
        {
            // Populare semnături de bază cunoscute (offline / air-gapped)
            RegisterHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Test Sample", "Generic Test");
            RegisterHash("44d88612fea8a8f36de82e1278abb02f", "WannaCry Ransomware", "WannaCry");
            RegisterHash("d0cf11e031e4e3b7b2ebf53139369931", "Mimikatz Credential Dumper", "Mimikatz");

            RegisterIp("185.220.101.5", "Tor Exit Node", "Tor Network Relay");
            RegisterIp("198.51.100.24", "Cobalt Strike C2 Server", "CobaltStrike");
            RegisterIp("203.0.113.88", "LockBit 3.0 Exfiltration Host", "LockBit");

            RegisterDomain("malicious-c2-server.com", "APT29 C2 Infrastructure", "Cozy Bear");
            RegisterDomain("pastebin-exfil-bot.net", "Exfiltration Endpoint", "DataStealer");
        }

        public void RegisterHash(string hash, string threatActor, string family)
        {
            _knownHashes[hash] = new ThreatFeedMatch { IocValue = hash, ThreatActorOrCampaign = threatActor, MalwareFamily = family, Description = $"Hash identificat în baza de semnături offline ca aparținând familiei [{family}]." };
        }

        public void RegisterIp(string ip, string threatActor, string family)
        {
            _knownIps[ip] = new ThreatFeedMatch { IocValue = ip, ThreatActorOrCampaign = threatActor, MalwareFamily = family, Description = $"Adresă IP identificată în feed-ul offline ca [{threatActor}]." };
        }

        public void RegisterDomain(string domain, string threatActor, string family)
        {
            _knownDomains[domain] = new ThreatFeedMatch { IocValue = domain, ThreatActorOrCampaign = threatActor, MalwareFamily = family, Description = $"Domeniu FQDN identificat în feed-ul offline ca C2 pentru [{threatActor}]." };
        }

        public ThreatFeedMatch? MatchHash(string hash) => _knownHashes.TryGetValue(hash, out var m) ? m : null;
        public ThreatFeedMatch? MatchIp(string ip) => _knownIps.TryGetValue(ip, out var m) ? m : null;
        public ThreatFeedMatch? MatchDomain(string domain) => _knownDomains.TryGetValue(domain, out var m) ? m : null;

        public List<ThreatFeedMatch> MatchAllIocs(IEnumerable<string> hashes, IEnumerable<string> ips, IEnumerable<string> domains)
        {
            var matches = new List<ThreatFeedMatch>();
            if (hashes != null)
            {
                foreach (var h in hashes)
                {
                    var m = MatchHash(h);
                    if (m != null) matches.Add(m);
                }
            }
            if (ips != null)
            {
                foreach (var ip in ips)
                {
                    var m = MatchIp(ip);
                    if (m != null) matches.Add(m);
                }
            }
            if (domains != null)
            {
                foreach (var d in domains)
                {
                    var m = MatchDomain(d);
                    if (m != null) matches.Add(m);
                }
            }
            return matches;
        }
    }
}

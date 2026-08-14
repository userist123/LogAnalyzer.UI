using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public static class StixMispExportService
    {
        /// <summary>
        /// Exportă indicatorii de compromitere (IoC) și alertele în format internațional STIX 2.1 Bundle.
        /// </summary>
        public static void ExportToStix21(string filePath, IEnumerable<DetectedIssue> issues, IEnumerable<IocItem> iocs, string sessionHashes)
        {
            var stixObjects = new List<object>();

            // 1. Identity Object (SOC Platform)
            string identityId = $"identity--{Guid.NewGuid()}";
            stixObjects.Add(new
            {
                type = "identity",
                spec_version = "2.1",
                id = identityId,
                created = DateTime.UtcNow.ToString("o"),
                modified = DateTime.UtcNow.ToString("o"),
                name = "LogAnalyzer DFIR Platform",
                identity_class = "system"
            });

            // 2. Report Object
            string reportId = $"report--{Guid.NewGuid()}";
            var objectRefs = new List<string> { identityId };

            // 3. Observed IoCs (Indicators)
            foreach (var ioc in iocs)
            {
                string indId = $"indicator--{Guid.NewGuid()}";
                objectRefs.Add(indId);

                string pattern = ioc.Type switch
                {
                    IocType.IPv4 => $"[ipv4-addr:value = '{ioc.Value}']",
                    IocType.IPv6 => $"[ipv6-addr:value = '{ioc.Value}']",
                    IocType.Hash => ioc.Value.Length == 32 ? $"[file:hashes.'MD5' = '{ioc.Value}']" : $"[file:hashes.'SHA-256' = '{ioc.Value}']",
                    IocType.Domain => $"[domain-name:value = '{ioc.Value}']",
                    IocType.URL => $"[url:value = '{ioc.Value}']",
                    _ => $"[file:hashes.'SHA-256' = '{ioc.Value}']"
                };

                stixObjects.Add(new
                {
                    type = "indicator",
                    spec_version = "2.1",
                    id = indId,
                    created = DateTime.UtcNow.ToString("o"),
                    modified = DateTime.UtcNow.ToString("o"),
                    name = $"IoC {ioc.Type}: {ioc.Value}",
                    pattern = pattern,
                    pattern_type = "stix",
                    valid_from = DateTime.UtcNow.ToString("o"),
                    created_by_ref = identityId
                });
            }

            // 4. Attack Patterns & Incident Objects
            foreach (var issue in issues)
            {
                string incidentId = $"incident--{Guid.NewGuid()}";
                objectRefs.Add(incidentId);

                stixObjects.Add(new
                {
                    type = "incident",
                    spec_version = "2.1",
                    id = incidentId,
                    created = issue.CreatedAt.ToUniversalTime().ToString("o"),
                    modified = DateTime.UtcNow.ToString("o"),
                    name = issue.Title,
                    description = issue.Explanation,
                    confidence = issue.Severity == "Critical" ? 95 : issue.Severity == "High" ? 80 : 50,
                    external_references = new[]
                    {
                        new
                        {
                            source_name = "mitre-attack",
                            external_id = issue.MitreTechniqueId ?? "T1000"
                        }
                    },
                    created_by_ref = identityId
                });
            }

            stixObjects.Add(new
            {
                type = "report",
                spec_version = "2.1",
                id = reportId,
                created = DateTime.UtcNow.ToString("o"),
                modified = DateTime.UtcNow.ToString("o"),
                name = "DFIR Security Incident Investigation Report",
                description = "Proces-verbal tehnic de analiză a urmelor de compromitere (Chain of Custody).",
                report_types = new[] { "threat-actor", "malware", "vulnerability" },
                published = DateTime.UtcNow.ToString("o"),
                object_refs = objectRefs,
                created_by_ref = identityId
            });

            var bundle = new
            {
                type = "bundle",
                id = $"bundle--{Guid.NewGuid()}",
                objects = stixObjects
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(bundle, options);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        /// <summary>
        /// Exportă indicatorii în format MISP Event JSON.
        /// </summary>
        public static void ExportToMispJson(string filePath, IEnumerable<DetectedIssue> issues, IEnumerable<IocItem> iocs, string hostOrCase)
        {
            var attributes = new List<object>();

            foreach (var ioc in iocs)
            {
                string mispType = ioc.Type switch
                {
                    IocType.IPv4 => "ip-dst",
                    IocType.IPv6 => "ip-dst",
                    IocType.Hash => ioc.Value.Length == 32 ? "md5" : "sha256",
                    IocType.Domain => "domain",
                    IocType.URL => "url",
                    _ => "other"
                };

                attributes.Add(new
                {
                    category = "Network activity",
                    type = mispType,
                    value = ioc.Value,
                    to_ids = true,
                    comment = "Identificat prin analiza forenzică LogAnalyzer DFIR"
                });
            }

            foreach (var issue in issues)
            {
                attributes.Add(new
                {
                    category = "Targeting data",
                    type = "text",
                    value = $"{issue.Title} - {issue.MitreTechniqueId}",
                    to_ids = false,
                    comment = issue.Explanation
                });
            }

            var mispEvent = new
            {
                Event = new
                {
                    info = $"DFIR Incident Investigation: {hostOrCase}",
                    date = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                    threat_level_id = "1", // High
                    analysis = "2", // Completed
                    distribution = "0", // Your organization only
                    Attribute = attributes
                }
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(mispEvent, options);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services.Network
{
    public class SiemForwarderConfig
    {
        public string SplunkHecUrl { get; set; } = string.Empty; // ex: https://splunk.corp:8088/services/collector/event
        public string SplunkHecToken { get; set; } = string.Empty;
        public string SentinelWorkspaceId { get; set; } = string.Empty;
        public string SentinelSharedKey { get; set; } = string.Empty;
    }

    public class SiemForwarderService
    {
        private readonly HttpClient _httpClient;

        public SiemForwarderService(HttpClient? httpClient = null)
        {
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <summary>
        /// Trimite o listă de alerte de securitate confirmate către Splunk HEC (HTTP Event Collector).
        /// </summary>
        public async Task<bool> ForwardAlertsToSplunkHecAsync(
            IEnumerable<DetectedIssue> issues,
            SiemForwarderConfig config,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(config.SplunkHecUrl) || string.IsNullOrWhiteSpace(config.SplunkHecToken) || issues == null)
            {
                return false;
            }

            try
            {
                var sb = new StringBuilder();
                foreach (var issue in issues)
                {
                    var splunkPayload = new
                    {
                        time = ((DateTimeOffset)issue.CreatedAt).ToUnixTimeSeconds(),
                        host = Environment.MachineName,
                        sourcetype = "loganalyzer:alert",
                        @event = new
                        {
                            title = issue.Title,
                            severity = issue.Severity,
                            mitre_technique = issue.MitreTechniqueId,
                            explanation = issue.Explanation
                        }
                    };
                    sb.AppendLine(JsonSerializer.Serialize(splunkPayload));
                }

                using var req = new HttpRequestMessage(HttpMethod.Post, config.SplunkHecUrl)
                {
                    Content = new StringContent(sb.ToString(), Encoding.UTF8, "application/json")
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Splunk", config.SplunkHecToken);

                using var res = await _httpClient.SendAsync(req, cancellationToken);
                return res.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Generează mesaje în format standard Syslog RFC 5424 (CEF / Common Event Format) pentru integrare cu orice SIEM.
        /// </summary>
        public List<string> FormatToCefSyslog(IEnumerable<DetectedIssue> issues)
        {
            var results = new List<string>();
            if (issues == null) return results;

            foreach (var issue in issues)
            {
                // Format CEF: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
                int sevNum = issue.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? 10 : (issue.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ? 8 : 4);
                string cef = $"CEF:0|LogAnalyzer|DFIR Enterprise|10.0|ALERT_{issue.MitreTechniqueId}|{issue.Title}|{sevNum}|msg={issue.Explanation.Replace("|", "\\|")} mitreTech={issue.MitreTechniqueId}";
                results.Add(cef);
            }

            return results;
        }
    }
}

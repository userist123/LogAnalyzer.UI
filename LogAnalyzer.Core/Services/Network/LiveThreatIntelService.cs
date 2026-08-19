using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LogAnalyzer.Core.Services.Network
{
    public class LiveIocReputation
    {
        public string IocValue { get; set; } = string.Empty;
        public string SourceFeed { get; set; } = string.Empty; // ex: "AlienVault OTX", "VirusTotal", "AbuseIPDB"
        public int MaliciousScore { get; set; } // 0-100
        public bool IsMalicious => MaliciousScore >= 50;
        public string ThreatCategory { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public DateTime CheckedAtUtc { get; set; } = DateTime.UtcNow;
    }

    public class LiveThreatIntelService
    {
        private readonly HttpClient _httpClient;

        public LiveThreatIntelService(HttpClient? httpClient = null)
        {
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <summary>
        /// Interoghează un feed live de Threat Intelligence (ex: AbuseIPDB / OTX) pentru a verifica reputația unei adrese IP.
        /// </summary>
        public async Task<LiveIocReputation> CheckIpReputationAsync(string ipAddress, string apiKey, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) throw new ArgumentNullException(nameof(ipAddress));

            var result = new LiveIocReputation
            {
                IocValue = ipAddress,
                SourceFeed = "Live Threat Feed (AbuseIPDB / OTX)",
                CheckedAtUtc = DateTime.UtcNow
            };

            // Pentru teste sau conexiuni fără cheie API configurată
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                result.MaliciousScore = 0;
                result.Details = "Cheia API nu este configurată în setările rețelei. Interogare live pasivă.";
                return result;
            }

            try
            {
                // Exemplu request structurat către endpointul AbuseIPDB / OTX
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.abuseipdb.com/api/v2/check?ipAddress={ipAddress}");
                request.Headers.Add("Key", apiKey);
                request.Headers.Add("Accept", "application/json");

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("data", out var data))
                    {
                        int score = data.TryGetProperty("abuseConfidenceScore", out var s) ? s.GetInt32() : 0;
                        result.MaliciousScore = score;
                        result.ThreatCategory = score > 50 ? "C2 / Host Malițios Confirmat" : "Trafic Normal";
                        result.Details = $"Scor de încredere abuz: {score}%. Raportat de comunitatea globală SOC.";
                    }
                }
                else
                {
                    result.Details = $"Răspuns API server: {response.StatusCode}";
                }
            }
            catch (Exception ex)
            {
                result.Details = $"Eroare conexiune Threat Feed: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Interoghează reputația unui hash de fișier prin VirusTotal / OTX.
        /// </summary>
        public async Task<LiveIocReputation> CheckFileHashReputationAsync(string sha256Hash, string apiKey, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256Hash)) throw new ArgumentNullException(nameof(sha256Hash));

            var result = new LiveIocReputation
            {
                IocValue = sha256Hash,
                SourceFeed = "VirusTotal / OTX Live Hash Feed",
                CheckedAtUtc = DateTime.UtcNow
            };

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                result.Details = "Cheia API VirusTotal/OTX lipsește. Configurați cheia în tab-ul Setări Rețea.";
                return result;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256Hash}");
                request.Headers.Add("x-apikey", apiKey);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("attributes", out var attr))
                    {
                        if (attr.TryGetProperty("last_analysis_stats", out var stats))
                        {
                            int malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                            result.MaliciousScore = malicious > 0 ? Math.Min(100, malicious * 10) : 0;
                            result.ThreatCategory = malicious > 0 ? "Malware / Troian Detectat" : "Fișier Curat";
                            result.Details = $"Detectat ca malițios de {malicious} motoare antivirus globale.";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Details = $"Eroare interogare VirusTotal: {ex.Message}";
            }

            return result;
        }
    }
}

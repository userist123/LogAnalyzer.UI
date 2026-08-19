using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services.Network
{
    public class M365AuthConfig
    {
        public string TenantId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
    }

    public class M365LiveConnectorService
    {
        private readonly HttpClient _httpClient;

        public M365LiveConnectorService(HttpClient? httpClient = null)
        {
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <summary>
        /// Obține un token OAuth2 Bearer de la Microsoft Identity Platform pentru Microsoft Graph API.
        /// </summary>
        public async Task<string?> GetAccessTokenAsync(M365AuthConfig config, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(config.TenantId) || string.IsNullOrWhiteSpace(config.ClientId) || string.IsNullOrWhiteSpace(config.ClientSecret))
            {
                return null;
            }

            try
            {
                string tokenUrl = $"https://login.microsoftonline.com/{config.TenantId}/oauth2/v2.0/token";
                var parameters = new Dictionary<string, string>
                {
                    { "client_id", config.ClientId },
                    { "scope", "https://graph.microsoft.com/.default" },
                    { "client_secret", config.ClientSecret },
                    { "grant_type", "client_credentials" }
                };

                using var req = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
                {
                    Content = new FormUrlEncodedContent(parameters)
                };

                using var res = await _httpClient.SendAsync(req, cancellationToken);
                if (res.IsSuccessStatusCode)
                {
                    string json = await res.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("access_token", out var tok))
                    {
                        return tok.GetString();
                    }
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Descarcă în timp real ultimele jurnale de sign-in Entra ID prin Microsoft Graph API.
        /// </summary>
        public async Task<List<ParsedEvent>> FetchRecentSignInsAsync(string accessToken, int topCount = 100, CancellationToken cancellationToken = default)
        {
            var events = new List<ParsedEvent>();
            if (string.IsNullOrWhiteSpace(accessToken)) return events;

            try
            {
                string graphUrl = $"https://graph.microsoft.com/v1.0/auditLogs/signIns?$top={topCount}&$orderby=createdDateTime desc";
                using var req = new HttpRequestMessage(HttpMethod.Get, graphUrl);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                using var res = await _httpClient.SendAsync(req, cancellationToken);
                if (res.IsSuccessStatusCode)
                {
                    string json = await res.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in val.EnumerateArray())
                        {
                            string user = item.TryGetProperty("userPrincipalName", out var upn) ? upn.GetString() ?? "User" : "User";
                            string ip = item.TryGetProperty("ipAddress", out var ipProp) ? ipProp.GetString() ?? "-" : "-";
                            string app = item.TryGetProperty("appDisplayName", out var appProp) ? appProp.GetString() ?? "-" : "-";
                            DateTime time = item.TryGetProperty("createdDateTime", out var cd) && cd.TryGetDateTime(out var dt) ? dt : DateTime.UtcNow;

                            events.Add(new ParsedEvent
                            {
                                EventId = 20101, // Cloud M365 Sign-in Event ID
                                TimeCreated = time,
                                Level = "Information",
                                ProviderName = "Microsoft Entra ID (Azure AD)",
                                MachineName = "M365-CLOUD-TENANT",
                                Message = $"[M365 LIVE] Autentificare utilizator '{user}' în aplicația '{app}' de la IP {ip}."
                            });
                        }
                    }
                }
            }
            catch { }

            return events;
        }
    }
}

using System;
using System.Diagnostics.Eventing.Reader;
using System.Security;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Watchers
{
    public class LiveEventLogWatcherService : IDisposable
    {
        private EventLogWatcher? _securityWatcher;
        private EventLogWatcher? _sysmonWatcher;
        private EventLogWatcher? _powerShellWatcher;
        private EventLogWatcher? _classicPowerShellWatcher;
        private EventLogWatcher? _systemWatcher;
        private bool _isRunning;

        public event Action<ParsedEvent>? OnEventReceived;
        public event Action<string>? OnStatusChanged;
        public event Action<Exception>? OnErrorOccurred;

        public bool IsRunning => _isRunning;

        /// <summary>
        /// Pornește abonarea în timp real la canalele de securitate ale unui host (local sau remote).
        /// </summary>
        public void StartWatching(string? remoteHost = null, string? domain = null, string? username = null, SecureString? password = null)
        {
            if (_isRunning) return;

            try
            {
                EventLogSession session;
                if (!string.IsNullOrWhiteSpace(remoteHost) && remoteHost != "localhost" && remoteHost != "127.0.0.1" && remoteHost != Environment.MachineName)
                {
                    session = new EventLogSession(remoteHost, domain, username, password, SessionAuthentication.Default);
                    OnStatusChanged?.Invoke($"Conectare live stabilită cu gazda la distanță [{remoteHost}]...");
                }
                else
                {
                    session = EventLogSession.GlobalSession;
                    OnStatusChanged?.Invoke("Abonare live stabilită pe stația locală...");
                }

                // 1. Canal Security
                TrySubscribeChannel(session, "Security", "*", ref _securityWatcher);

                // 2. Canal Sysmon
                TrySubscribeChannel(session, "Microsoft-Windows-Sysmon/Operational", "*", ref _sysmonWatcher);

                // 3. Canal PowerShell Operational & Classic
                TrySubscribeChannel(session, "Microsoft-Windows-PowerShell/Operational", "*", ref _powerShellWatcher);
                TrySubscribeChannel(session, "Windows PowerShell", "*", ref _classicPowerShellWatcher);

                // 4. Canal System
                TrySubscribeChannel(session, "System", "*[System[(EventID=7045)]]", ref _systemWatcher);

                _isRunning = true;
                OnStatusChanged?.Invoke("🔴 Monitorizare în timp real ACTIVĂ. Se interceptează evenimente...");
            }
            catch (Exception ex)
            {
                _isRunning = false;
                OnErrorOccurred?.Invoke(ex);
                OnStatusChanged?.Invoke($"Eroare pornire abonare live: {ex.Message}");
            }
        }

        private void TrySubscribeChannel(EventLogSession session, string channelName, string query, ref EventLogWatcher? watcher)
        {
            try
            {
                var eventQuery = new EventLogQuery(channelName, PathType.LogName, query)
                {
                    Session = session,
                    TolerateQueryErrors = true
                };

                watcher = new EventLogWatcher(eventQuery);
                watcher.EventRecordWritten += Watcher_EventRecordWritten;
                watcher.Enabled = true;
            }
            catch (Exception ex)
            {
                OnStatusChanged?.Invoke($"Avertisment: Canalul '{channelName}' nu este accesibil ({ex.Message}).");
            }
        }

        private void Watcher_EventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                using var rec = e.EventRecord;
                string? message = null;
                try
                {
                    message = rec.FormatDescription();
                }
                catch
                {
                    message = $"Event ID {rec.Id} from {rec.ProviderName}";
                }

                var parsed = new ParsedEvent
                {
                    EventId = rec.Id,
                    TimeCreated = rec.TimeCreated ?? DateTime.UtcNow,
                    Level = rec.LevelDisplayName ?? "Information",
                    ProviderName = rec.ProviderName ?? "SecurityLog",
                    MachineName = rec.MachineName ?? Environment.MachineName,
                    Message = message ?? $"Eveniment ID {rec.Id}"
                };

                OnEventReceived?.Invoke(parsed);
            }
            catch (Exception ex)
            {
                OnErrorOccurred?.Invoke(ex);
            }
        }

        /// <summary>
        /// Oprește abonarea în timp real.
        /// </summary>
        public void StopWatching()
        {
            if (!_isRunning) return;

            DisposeWatcher(ref _securityWatcher);
            DisposeWatcher(ref _sysmonWatcher);
            DisposeWatcher(ref _powerShellWatcher);
            DisposeWatcher(ref _classicPowerShellWatcher);
            DisposeWatcher(ref _systemWatcher);

            _isRunning = false;
            OnStatusChanged?.Invoke("⏹ Monitorizare în timp real OPRITĂ.");
        }

        private void DisposeWatcher(ref EventLogWatcher? watcher)
        {
            if (watcher != null)
            {
                try
                {
                    watcher.Enabled = false;
                    watcher.EventRecordWritten -= Watcher_EventRecordWritten;
                    watcher.Dispose();
                }
                catch { }
                watcher = null;
            }
        }

        public void Dispose()
        {
            StopWatching();
        }
    }
}

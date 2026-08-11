using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services;

public sealed class AuditLogService
{
    private readonly List<string> _entries = new();
    private string _lastHash = "GENESIS";
    private readonly string? _logPath;

    public AuditLogService() { }

    public AuditLogService(string logPath)
    {
        _logPath = logPath;
        var directory = Path.GetDirectoryName(Path.GetFullPath(logPath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
    }

    public void LogAction(string action, string details) => LogAction("analyst", action, details);

    public void LogAction(string actor, string action, string details)
    {
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var line = $"{timestamp}|{actor}|{action}|{details}|{_lastHash}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line))).ToLowerInvariant();
        var record = $"{line}|{hash}";
        _entries.Add(record);
        _lastHash = hash;
        if (_logPath != null) File.AppendAllText(_logPath, record + Environment.NewLine, new UTF8Encoding(false));
    }

    public IReadOnlyList<string> GetEntries() => _entries;
}

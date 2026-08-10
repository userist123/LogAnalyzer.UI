using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LogAnalyzer.UI.Services;

public sealed record CustodyEntry(DateTimeOffset Timestamp, string Actor, string Action, string Details, string PreviousHash, string Hash);

public sealed class ChainOfCustodyService
{
    private readonly string _path;
    private readonly object _sync = new();
    private string _lastHash = "GENESIS";

    public ChainOfCustodyService(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (File.Exists(path)) RestoreLastHash();
    }

    public CustodyEntry Append(string actor, string action, string details)
    {
        lock (_sync)
        {
            var timestamp = DateTimeOffset.UtcNow;
            var canonical = $"{timestamp:O}|{actor}|{action}|{details}|{_lastHash}";
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            var entry = new CustodyEntry(timestamp, actor, action, details, _lastHash, hash);
            File.AppendAllText(_path, JsonSerializer.Serialize(entry) + Environment.NewLine, new UTF8Encoding(false));
            _lastHash = hash;
            return entry;
        }
    }

    public bool Verify()
    {
        if (!File.Exists(_path)) return true;
        var previous = "GENESIS";
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var entry = JsonSerializer.Deserialize<CustodyEntry>(line);
            if (entry is null || entry.PreviousHash != previous) return false;
            var canonical = $"{entry.Timestamp:O}|{entry.Actor}|{entry.Action}|{entry.Details}|{entry.PreviousHash}";
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(entry.Hash))) return false;
            previous = entry.Hash;
        }
        return true;
    }

    private void RestoreLastHash()
    {
        string? line = null;
        foreach (var item in File.ReadLines(_path)) line = item;
        if (!string.IsNullOrWhiteSpace(line)) _lastHash = JsonSerializer.Deserialize<CustodyEntry>(line)?.Hash ?? "GENESIS";
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LogAnalyzer.Core.Services
{
    public class ProvenanceLedgerEntry
    {
        public int SequenceNumber { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string ActionType { get; set; } = string.Empty; // ex: "FILE_INGESTED", "PARSER_EXECUTED", "THREAT_DETECTED", "EVIDENCE_EXPORTED"
        public string EvidenceReference { get; set; } = string.Empty;
        public string SourceSha256 { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string PreviousEntryHash { get; set; } = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000000000000000";
        public string EntryHash { get; set; } = string.Empty;
    }

    public class ProvenanceLedgerService
    {
        private readonly List<ProvenanceLedgerEntry> _entries = new();
        private readonly string _ledgerFilePath;
        private readonly object _lock = new();

        public ProvenanceLedgerService(string? customPath = null)
        {
            _ledgerFilePath = customPath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "provenance_ledger.json");
            LoadLedger();
        }

        public ProvenanceLedgerEntry AppendEntry(string actionType, string evidenceRef, string sourceSha256, string details)
        {
            lock (_lock)
            {
                string prevHash = _entries.Count > 0 
                    ? _entries[^1].EntryHash 
                    : "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000000000000000";

                var entry = new ProvenanceLedgerEntry
                {
                    SequenceNumber = _entries.Count + 1,
                    TimestampUtc = DateTime.UtcNow,
                    ActionType = actionType,
                    EvidenceReference = evidenceRef,
                    SourceSha256 = sourceSha256,
                    Details = details,
                    PreviousEntryHash = prevHash
                };

                entry.EntryHash = ComputeEntryHash(entry);
                _entries.Add(entry);
                SaveLedger();
                return entry;
            }
        }

        public (bool IsValid, string Message, int FailedAtSequence) ValidateLedgerIntegrity()
        {
            lock (_lock)
            {
                if (_entries.Count == 0) return (true, "Jurnalul de proveniență este curat (0 intrări).", 0);

                string expectedPrev = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000000000000000";

                for (int i = 0; i < _entries.Count; i++)
                {
                    var entry = _entries[i];

                    if (entry.PreviousEntryHash != expectedPrev)
                    {
                        return (false, $"Rupere a lanțului criptografic la înregistrarea #{entry.SequenceNumber}! Hash-ul anterior nu corespunde.", entry.SequenceNumber);
                    }

                    string actualHash = ComputeEntryHash(entry);
                    if (entry.EntryHash != actualHash)
                    {
                        return (false, $"Alterare detectată la înregistrarea #{entry.SequenceNumber}! Hash-ul calculat nu corespunde conținutului.", entry.SequenceNumber);
                    }

                    expectedPrev = entry.EntryHash;
                }

                return (true, $"✅ Integritatea întregului lanț probatoriu ({_entries.Count} intrări) a fost verificată cu succes criptografic!", 0);
            }
        }

        public IReadOnlyList<ProvenanceLedgerEntry> GetEntries()
        {
            lock (_lock) { return _entries.AsReadOnly(); }
        }

        private string ComputeEntryHash(ProvenanceLedgerEntry e)
        {
            string raw = $"{e.SequenceNumber}|{e.TimestampUtc:O}|{e.ActionType}|{e.EvidenceReference}|{e.SourceSha256}|{e.Details}|{e.PreviousEntryHash}";
            using var sha = SHA256.Create();
            byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        private void SaveLedger()
        {
            try
            {
                string json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_ledgerFilePath, json);
            }
            catch { }
        }

        private void LoadLedger()
        {
            try
            {
                if (File.Exists(_ledgerFilePath))
                {
                    string json = File.ReadAllText(_ledgerFilePath);
                    var loaded = JsonSerializer.Deserialize<List<ProvenanceLedgerEntry>>(json);
                    if (loaded != null)
                    {
                        _entries.Clear();
                        _entries.AddRange(loaded);
                    }
                }
            }
            catch { }
        }
    }
}

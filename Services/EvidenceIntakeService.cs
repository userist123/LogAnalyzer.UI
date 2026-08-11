using System;
using System.IO;

namespace LogAnalyzer.UI.Services;

public sealed record EvidenceReceipt(string FilePath, long Length, DateTimeOffset ImportedAt, string Sha256, string AuditHash);

public sealed class EvidenceIntakeService
{
    private readonly SecurePathService _paths;
    private readonly ChainOfCustodyService _custody;

    public EvidenceIntakeService(SecurePathService paths, ChainOfCustodyService custody)
    {
        _paths = paths;
        _custody = custody;
    }

    public EvidenceReceipt Import(string filePath, string actor)
    {
        if (!_paths.IsSafeRegularFile(filePath)) throw new InvalidDataException("Evidence must be a regular file and cannot be a reparse point.");
        var fullPath = Path.GetFullPath(filePath);
        var hash = _paths.ComputeSha256(fullPath);
        var info = new FileInfo(fullPath);
        var audit = _custody.Append(actor, "EVIDENCE_IMPORTED", $"Path={fullPath};Length={info.Length};SHA256={hash}");
        return new EvidenceReceipt(fullPath, info.Length, audit.Timestamp, hash, audit.Hash);
    }
}

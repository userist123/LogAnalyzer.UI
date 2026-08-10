using System;
using System.IO;
using System.Security.Cryptography;
using LogAnalyzer.UI.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class SecurePathServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "LogAnalyzerTests_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void ComputeSha256_MatchesKnownHash()
    {
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "evidence.bin");
        var content = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        File.WriteAllBytes(file, content);

        var service = new SecurePathService();
        var result = service.ComputeSha256(file);
        var expected = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        Assert.Equal(expected, result);
    }

    [Fact]
    public void IsSafeRegularFile_ExistingFile_ReturnsTrue()
    {
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "regular.evtx");
        File.WriteAllText(file, "test");
        Assert.True(new SecurePathService().IsSafeRegularFile(file));
    }

    [Fact]
    public void IsSafeRegularFile_MissingFile_ReturnsFalse()
    {
        Assert.False(new SecurePathService().IsSafeRegularFile(Path.Combine(_dir, "missing.evtx")));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); } catch { }
    }
}

using System;
using System.IO;
using LogAnalyzer.UI.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class SqlCipherIntegrationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "LogAnalyzerSqlCipher_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Database_CreatesSchema_InsertsAndSearchesIoc()
    {
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, "knowledge.db");
        var keyPath = Path.Combine(_directory, "knowledge.key");
        var protectedSecrets = new ProtectedSecretStore();
        var keyStore = new SqlCipherKeyStore(protectedSecrets, keyPath);

        using var database = new SqlCipherDatabase(databasePath, keyStore);
        var knowledgeBase = new IocKnowledgeBaseService(database);
        var id = knowledgeBase.Add(new IocRecord(0, "SHA256", "deadbeef", "test indicator", "T1059", "High", DateTimeOffset.UtcNow));

        var results = knowledgeBase.Search("deadbeef");

        Assert.True(id > 0);
        var result = Assert.Single(results);
        Assert.Equal("SHA256", result.Type);
        Assert.Equal("deadbeef", result.Value);
    }

    [Fact]
    public void Database_ReopensWithSameProtectedKey()
    {
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, "knowledge.db");
        var keyPath = Path.Combine(_directory, "knowledge.key");
        var protectedSecrets = new ProtectedSecretStore();

        using (var first = new SqlCipherDatabase(databasePath, new SqlCipherKeyStore(protectedSecrets, keyPath)))
        {
            var knowledgeBase = new IocKnowledgeBaseService(first);
            knowledgeBase.Add(new IocRecord(0, "IP", "203.0.113.10", "test", null, "Medium", DateTimeOffset.UtcNow));
        }

        using var second = new SqlCipherDatabase(databasePath, new SqlCipherKeyStore(protectedSecrets, keyPath));
        var reopened = new IocKnowledgeBaseService(second).Search("203.0.113.10");
        Assert.Single(reopened);
    }

    [Fact]
    public void Database_DifferentKey_CannotReadExistingDatabase()
    {
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, "knowledge.db");
        var keyPath = Path.Combine(_directory, "knowledge.key");
        var wrongKeyPath = Path.Combine(_directory, "wrong.key");
        var protectedSecrets = new ProtectedSecretStore();

        using (var first = new SqlCipherDatabase(databasePath, new SqlCipherKeyStore(protectedSecrets, keyPath)))
        {
            new IocKnowledgeBaseService(first).Add(new IocRecord(0, "URL", "https://example.invalid", "test", null, "Low", DateTimeOffset.UtcNow));
        }

        Assert.ThrowsAny<Exception>(() =>
        {
            using var wrong = new SqlCipherDatabase(databasePath, new SqlCipherKeyStore(protectedSecrets, wrongKeyPath));
        });
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
        }
        catch { }
    }
}

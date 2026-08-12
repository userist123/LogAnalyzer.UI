using System;
using System.IO;
using LogAnalyzer.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class DatabaseMigrationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "LogAnalyzerMigration_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void LegacyDatabase_IsMigratedAndEncrypted()
    {
        Directory.CreateDirectory(_directory);
        var legacyPath = Path.Combine(_directory, "legacy.db");
        var encryptedDirectory = Path.Combine(_directory, "encrypted");

        using (var legacy = new SqliteConnection($"Data Source={legacyPath}"))
        {
            legacy.Open();
            using var command = legacy.CreateCommand();
            command.CommandText = @"
                CREATE TABLE Events (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, EventId INTEGER, TimeCreated TEXT, ProviderName TEXT,
                    Level TEXT, MachineName TEXT, Message TEXT, XmlData TEXT, OfficialDescription TEXT,
                    TacticalExample TEXT, ReferenceUrl TEXT, PotentialCriticality TEXT
                );
                INSERT INTO Events (EventId, TimeCreated, Message) VALUES (4625, '2026-08-11T10:00:00.0000000Z', 'legacy event');";
            command.ExecuteNonQuery();
        }

        var database = new DatabaseService(encryptedDirectory, legacyPath);

        Assert.Equal(1, database.GetEventsCount(null!, null!, null!));
        Assert.True(File.Exists(Path.Combine(encryptedDirectory, "LogAnalyzer.key")));
        Assert.ThrowsAny<Exception>(() =>
        {
            using var unkeyed = new SqliteConnection($"Data Source={Path.Combine(encryptedDirectory, "LogAnalyzer.db")};Pooling=False");
            unkeyed.Open();
            using var command = unkeyed.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master;";
            command.ExecuteScalar();
        });
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }
        catch { }
    }
}
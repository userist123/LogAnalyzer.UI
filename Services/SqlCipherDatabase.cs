using System;
using System.IO;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace LogAnalyzer.UI.Services;

public sealed class SqlCipherDatabase : IDisposable
{
    private readonly SqliteConnection _connection;

    public SqlCipherDatabase(string databasePath, SqlCipherKeyStore keyStore)
    {
        Batteries_V2.Init();
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString());
        _connection.Open();
        ApplyKey(keyStore.GetOrCreateKey());
        Configure();
    }

    public SqliteConnection Connection => _connection;

    private void ApplyKey(byte[] key)
    {
        var hex = Convert.ToHexString(key).ToLowerInvariant();
        CryptographicOperationsHelper.Zero(key);
        using var command = _connection.CreateCommand();
        command.CommandText = $"PRAGMA key = \"x'{hex}'\";";
        command.ExecuteNonQuery();
        command.CommandText = "SELECT count(*) FROM sqlite_master;";
        command.ExecuteScalar();
    }

    private void Configure()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;";
        command.ExecuteNonQuery();
    }

    public void Dispose() => _connection.Dispose();

    private static class CryptographicOperationsHelper
    {
        public static void Zero(byte[] bytes) => System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
    }
}

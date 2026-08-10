using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;

namespace LogAnalyzer.UI.Services;

public sealed record IocRecord(long Id, string Type, string Value, string? Description, string? MitreTechnique, string Severity, DateTimeOffset CreatedAt);

public sealed class IocKnowledgeBaseService
{
    private readonly SqlCipherDatabase _database;

    public IocKnowledgeBaseService(SqlCipherDatabase database)
    {
        _database = database;
        EnsureSchema();
    }

    public long Add(IocRecord ioc)
    {
        using var command = _database.Connection.CreateCommand();
        command.CommandText = "INSERT INTO Iocs(Type, Value, Description, MitreTechnique, Severity, CreatedAt) VALUES ($type, $value, $description, $mitre, $severity, $created); SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("$type", ioc.Type);
        command.Parameters.AddWithValue("$value", ioc.Value);
        command.Parameters.AddWithValue("$description", (object?)ioc.Description ?? DBNull.Value);
        command.Parameters.AddWithValue("$mitre", (object?)ioc.MitreTechnique ?? DBNull.Value);
        command.Parameters.AddWithValue("$severity", ioc.Severity);
        command.Parameters.AddWithValue("$created", ioc.CreatedAt.UtcDateTime.ToString("O"));
        return Convert.ToInt64(command.ExecuteScalar());
    }

    public IReadOnlyList<IocRecord> Search(string value, int limit = 100)
    {
        var result = new List<IocRecord>();
        using var command = _database.Connection.CreateCommand();
        command.CommandText = "SELECT Id, Type, Value, Description, MitreTechnique, Severity, CreatedAt FROM Iocs WHERE Value LIKE $value OR Description LIKE $value ORDER BY Id DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$value", $"%{value}%");
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new IocRecord(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetString(5), DateTimeOffset.Parse(reader.GetString(6))));
        }
        return result;
    }

    private void EnsureSchema()
    {
        using var command = _database.Connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS Iocs (Id INTEGER PRIMARY KEY AUTOINCREMENT, Type TEXT NOT NULL, Value TEXT NOT NULL, Description TEXT NULL, MitreTechnique TEXT NULL, Severity TEXT NOT NULL, CreatedAt TEXT NOT NULL); CREATE INDEX IF NOT EXISTS IX_Iocs_Value ON Iocs(Value);";
        command.ExecuteNonQuery();
    }
}

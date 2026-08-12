using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using SQLitePCL;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.Infrastructure.Services
{
    [SupportedOSPlatform("windows")]
    public class DatabaseService : IDatabaseService
    {
        private readonly string _dbPath;
        private readonly string _keyPath;
        private readonly string _connectionString;

        public DatabaseService()
            : this(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogAnalyzer"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LogAnalyzer.db"))
        {
        }

        public DatabaseService(string databaseDirectory, string? legacyDatabasePath = null)
        {
            if (string.IsNullOrWhiteSpace(databaseDirectory)) throw new ArgumentException("A database directory is required.", nameof(databaseDirectory));

            Batteries_V2.Init();
            Directory.CreateDirectory(databaseDirectory);
            _dbPath = Path.Combine(databaseDirectory, "LogAnalyzer.db");
            _keyPath = Path.Combine(databaseDirectory, "LogAnalyzer.key");
            _connectionString = CreateConnectionString(_dbPath);

            if (!File.Exists(_dbPath) && !string.IsNullOrWhiteSpace(legacyDatabasePath) && File.Exists(legacyDatabasePath))
            {
                MigrateLegacyDatabase(legacyDatabasePath);
            }
        }

        public void InitializeDatabase()
        {
            using var connection = OpenConnection();
            
            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS Events (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    EventId INTEGER,
                    TimeCreated TEXT,
                    ProviderName TEXT,
                    Level TEXT,
                    MachineName TEXT,
                    Message TEXT,
                    XmlData TEXT,
                    OfficialDescription TEXT,
                    TacticalExample TEXT,
                    ReferenceUrl TEXT,
                    PotentialCriticality TEXT
                );
                CREATE TABLE IF NOT EXISTS RegistryArtifacts (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    HiveType TEXT,
                    Category TEXT,
                    KeyPath TEXT,
                    ValueName TEXT,
                    ValueData TEXT,
                    SuspicionLevel TEXT
                );
                CREATE TABLE IF NOT EXISTS Timeline (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT,
                    Source TEXT,
                    Category TEXT,
                    Severity TEXT,
                    MitreTags TEXT,
                    UserOrHost TEXT,
                    Description TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_eid ON Events(EventId);
                CREATE INDEX IF NOT EXISTS idx_events_msg ON Events(Message);
                CREATE INDEX IF NOT EXISTS idx_reg_key ON RegistryArtifacts(KeyPath);
            ";
            command.ExecuteNonQuery();
        }

        public void ClearDatabase()
        {
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM Events; DELETE FROM RegistryArtifacts; DELETE FROM Timeline;";
            command.ExecuteNonQuery();
        }

        public void SaveEvents(IEnumerable<ParsedEvent> events)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT INTO Events (
                    EventId, TimeCreated, ProviderName, Level, MachineName, Message, XmlData,
                    OfficialDescription, TacticalExample, ReferenceUrl, PotentialCriticality
                ) VALUES (
                    $EventId, $TimeCreated, $ProviderName, $Level, $MachineName, $Message, $XmlData,
                    $OfficialDescription, $TacticalExample, $ReferenceUrl, $PotentialCriticality
                )
            ";
            
            var pEventId = command.Parameters.Add("$EventId", SqliteType.Integer);
            var pTimeCreated = command.Parameters.Add("$TimeCreated", SqliteType.Text);
            var pProviderName = command.Parameters.Add("$ProviderName", SqliteType.Text);
            var pLevel = command.Parameters.Add("$Level", SqliteType.Text);
            var pMachineName = command.Parameters.Add("$MachineName", SqliteType.Text);
            var pMessage = command.Parameters.Add("$Message", SqliteType.Text);
            var pXmlData = command.Parameters.Add("$XmlData", SqliteType.Text);
            var pOfficialDescription = command.Parameters.Add("$OfficialDescription", SqliteType.Text);
            var pTacticalExample = command.Parameters.Add("$TacticalExample", SqliteType.Text);
            var pReferenceUrl = command.Parameters.Add("$ReferenceUrl", SqliteType.Text);
            var pPotentialCriticality = command.Parameters.Add("$PotentialCriticality", SqliteType.Text);
            
            foreach (var ev in events)
            {
                pEventId.Value = ev.EventId;
                pTimeCreated.Value = ev.TimeCreated.ToString("o");
                pProviderName.Value = ev.ProviderName ?? (object)DBNull.Value;
                pLevel.Value = ev.Level ?? (object)DBNull.Value;
                pMachineName.Value = ev.MachineName ?? (object)DBNull.Value;
                pMessage.Value = ev.Message ?? (object)DBNull.Value;
                pXmlData.Value = ev.XmlData ?? (object)DBNull.Value;
                pOfficialDescription.Value = ev.OfficialDescription ?? (object)DBNull.Value;
                pTacticalExample.Value = ev.TacticalExample ?? (object)DBNull.Value;
                pReferenceUrl.Value = ev.ReferenceUrl ?? (object)DBNull.Value;
                pPotentialCriticality.Value = ev.PotentialCriticality ?? (object)DBNull.Value;
                
                command.ExecuteNonQuery();
            }
            transaction.Commit();
        }

        public void SaveRegistryArtifacts(IEnumerable<RegistryArtifact> artifacts)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT INTO RegistryArtifacts (
                    HiveType, Category, KeyPath, ValueName, ValueData, SuspicionLevel
                ) VALUES (
                    $HiveType, $Category, $KeyPath, $ValueName, $ValueData, $SuspicionLevel
                )
            ";
            
            var pHiveType = command.Parameters.Add("$HiveType", SqliteType.Text);
            var pCategory = command.Parameters.Add("$Category", SqliteType.Text);
            var pKeyPath = command.Parameters.Add("$KeyPath", SqliteType.Text);
            var pValueName = command.Parameters.Add("$ValueName", SqliteType.Text);
            var pValueData = command.Parameters.Add("$ValueData", SqliteType.Text);
            var pSuspicionLevel = command.Parameters.Add("$SuspicionLevel", SqliteType.Text);
            
            foreach (var art in artifacts)
            {
                pHiveType.Value = art.HiveType ?? (object)DBNull.Value;
                pCategory.Value = art.Category ?? (object)DBNull.Value;
                pKeyPath.Value = art.KeyPath ?? (object)DBNull.Value;
                pValueName.Value = art.ValueName ?? (object)DBNull.Value;
                pValueData.Value = art.ValueData ?? (object)DBNull.Value;
                pSuspicionLevel.Value = art.SuspicionLevel ?? (object)DBNull.Value;
                
                command.ExecuteNonQuery();
            }
            transaction.Commit();
        }

        public IEnumerable<ParsedEvent> GetEvents(int limit, int offset, string search, string profileName, List<int> targetEventIds)
        {
            var list = new List<ParsedEvent>();
            using var connection = OpenConnection();
            
            var command = connection.CreateCommand();
            string query = "SELECT * FROM Events WHERE 1=1";
            if (!string.IsNullOrWhiteSpace(search))
            {
                query += " AND (EventId LIKE $search OR Message LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{search}%");
            }
            if (targetEventIds != null && targetEventIds.Count > 0)
            {
                query += $" AND EventId IN ({string.Join(",", targetEventIds)})";
            }
            query += " ORDER BY TimeCreated DESC LIMIT $limit OFFSET $offset";
            
            command.CommandText = query;
            command.Parameters.AddWithValue("$limit", limit);
            command.Parameters.AddWithValue("$offset", offset);
            
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                DateTime.TryParse(reader.GetString(reader.GetOrdinal("TimeCreated")), out var time);
                list.Add(new ParsedEvent
                {
                    EventId = reader.GetInt32(reader.GetOrdinal("EventId")),
                    TimeCreated = time,
                    ProviderName = reader.IsDBNull(reader.GetOrdinal("ProviderName")) ? null : reader.GetString(reader.GetOrdinal("ProviderName")),
                    Level = reader.IsDBNull(reader.GetOrdinal("Level")) ? null : reader.GetString(reader.GetOrdinal("Level")),
                    MachineName = reader.IsDBNull(reader.GetOrdinal("MachineName")) ? null : reader.GetString(reader.GetOrdinal("MachineName")),
                    Message = reader.IsDBNull(reader.GetOrdinal("Message")) ? null : reader.GetString(reader.GetOrdinal("Message")),
                    XmlData = reader.IsDBNull(reader.GetOrdinal("XmlData")) ? null : reader.GetString(reader.GetOrdinal("XmlData")),
                    OfficialDescription = reader.IsDBNull(reader.GetOrdinal("OfficialDescription")) ? null : reader.GetString(reader.GetOrdinal("OfficialDescription")),
                    TacticalExample = reader.IsDBNull(reader.GetOrdinal("TacticalExample")) ? null : reader.GetString(reader.GetOrdinal("TacticalExample")),
                    ReferenceUrl = reader.IsDBNull(reader.GetOrdinal("ReferenceUrl")) ? null : reader.GetString(reader.GetOrdinal("ReferenceUrl")),
                    PotentialCriticality = reader.IsDBNull(reader.GetOrdinal("PotentialCriticality")) ? null : reader.GetString(reader.GetOrdinal("PotentialCriticality"))
                });
            }
            return list;
        }

        public int GetEventsCount(string search, string profileName, List<int> targetEventIds)
        {
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            string query = "SELECT COUNT(*) FROM Events WHERE 1=1";
            if (!string.IsNullOrWhiteSpace(search))
            {
                query += " AND (EventId LIKE $search OR Message LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{search}%");
            }
            if (targetEventIds != null && targetEventIds.Count > 0)
            {
                query += $" AND EventId IN ({string.Join(",", targetEventIds)})";
            }
            command.CommandText = query;
            return Convert.ToInt32(command.ExecuteScalar());
        }

        public IEnumerable<RegistryArtifact> GetRegistryArtifacts(int limit, int offset, string search)
        {
            var list = new List<RegistryArtifact>();
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            string query = "SELECT * FROM RegistryArtifacts WHERE 1=1";
            
            string? catFilter = null;
            string actualSearch = search;
            if (!string.IsNullOrWhiteSpace(search) && search.StartsWith("[CAT:"))
            {
                int endIdx = search.IndexOf(']');
                if (endIdx > 5)
                {
                    catFilter = search.Substring(5, endIdx - 5);
                    actualSearch = search.Substring(endIdx + 1).Trim();
                }
            }

            if (!string.IsNullOrWhiteSpace(actualSearch))
            {
                query += " AND (KeyPath LIKE $search OR ValueName LIKE $search OR ValueData LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{actualSearch}%");
            }
            if (!string.IsNullOrWhiteSpace(catFilter))
            {
                query += " AND Category LIKE $category";
                command.Parameters.AddWithValue("$category", $"%{catFilter}%");
            }

            query += " LIMIT $limit OFFSET $offset";
            command.CommandText = query;
            command.Parameters.AddWithValue("$limit", limit);
            command.Parameters.AddWithValue("$offset", offset);
            
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new RegistryArtifact
                {
                    HiveType = reader.IsDBNull(reader.GetOrdinal("HiveType")) ? null : reader.GetString(reader.GetOrdinal("HiveType")),
                    Category = reader.IsDBNull(reader.GetOrdinal("Category")) ? null : reader.GetString(reader.GetOrdinal("Category")),
                    KeyPath = reader.IsDBNull(reader.GetOrdinal("KeyPath")) ? null : reader.GetString(reader.GetOrdinal("KeyPath")),
                    ValueName = reader.IsDBNull(reader.GetOrdinal("ValueName")) ? null : reader.GetString(reader.GetOrdinal("ValueName")),
                    ValueData = reader.IsDBNull(reader.GetOrdinal("ValueData")) ? null : reader.GetString(reader.GetOrdinal("ValueData")),
                    SuspicionLevel = reader.IsDBNull(reader.GetOrdinal("SuspicionLevel")) ? null : reader.GetString(reader.GetOrdinal("SuspicionLevel"))
                });
            }
            return list;
        }

        public int GetRegistryArtifactsCount(string search)
        {
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            string query = "SELECT COUNT(*) FROM RegistryArtifacts WHERE 1=1";
            
            string? catFilter = null;
            string actualSearch = search;
            if (!string.IsNullOrWhiteSpace(search) && search.StartsWith("[CAT:"))
            {
                int endIdx = search.IndexOf(']');
                if (endIdx > 5)
                {
                    catFilter = search.Substring(5, endIdx - 5);
                    actualSearch = search.Substring(endIdx + 1).Trim();
                }
            }

            if (!string.IsNullOrWhiteSpace(actualSearch))
            {
                query += " AND (KeyPath LIKE $search OR ValueName LIKE $search OR ValueData LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{actualSearch}%");
            }
            if (!string.IsNullOrWhiteSpace(catFilter))
            {
                query += " AND Category LIKE $category";
                command.Parameters.AddWithValue("$category", $"%{catFilter}%");
            }

            command.CommandText = query;
            return Convert.ToInt32(command.ExecuteScalar());
        }

        public IEnumerable<TimelineItem> GetTimeline(int limit, int offset, string search)
        {
            var list = new List<TimelineItem>();
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            string query = "SELECT * FROM Timeline WHERE 1=1";
            if (!string.IsNullOrWhiteSpace(search))
            {
                query += " AND (Category LIKE $search OR Description LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{search}%");
            }
            query += " ORDER BY Timestamp DESC LIMIT $limit OFFSET $offset";
            command.CommandText = query;
            command.Parameters.AddWithValue("$limit", limit);
            command.Parameters.AddWithValue("$offset", offset);
            
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                DateTime.TryParse(reader.GetString(reader.GetOrdinal("Timestamp")), out var time);
                list.Add(new TimelineItem
                {
                    Timestamp = time,
                    Source = reader.GetString(reader.GetOrdinal("Source")),
                    Category = reader.GetString(reader.GetOrdinal("Category")),
                    Severity = reader.IsDBNull(reader.GetOrdinal("Severity")) ? null : reader.GetString(reader.GetOrdinal("Severity")),
                    MitreTags = reader.IsDBNull(reader.GetOrdinal("MitreTags")) ? null : reader.GetString(reader.GetOrdinal("MitreTags")),
                    UserOrHost = reader.GetString(reader.GetOrdinal("UserOrHost")),
                    Description = reader.GetString(reader.GetOrdinal("Description"))
                });
            }
            return list;
        }

        public int GetTimelineCount(string search)
        {
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            string query = "SELECT COUNT(*) FROM Timeline WHERE 1=1";
            if (!string.IsNullOrWhiteSpace(search))
            {
                query += " AND (Category LIKE $search OR Description LIKE $search)";
                command.Parameters.AddWithValue("$search", $"%{search}%");
            }
            command.CommandText = query;
            return Convert.ToInt32(command.ExecuteScalar());
        }

        public void SaveTimeline(IEnumerable<TimelineItem> timelineItems)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = @"
                INSERT INTO Timeline (
                    Timestamp, Source, Category, Severity, MitreTags, UserOrHost, Description
                ) VALUES (
                    $Timestamp, $Source, $Category, $Severity, $MitreTags, $UserOrHost, $Description
                )
            ";
            
            var pTimestamp = command.Parameters.Add("$Timestamp", SqliteType.Text);
            var pSource = command.Parameters.Add("$Source", SqliteType.Text);
            var pCategory = command.Parameters.Add("$Category", SqliteType.Text);
            var pSeverity = command.Parameters.Add("$Severity", SqliteType.Text);
            var pMitreTags = command.Parameters.Add("$MitreTags", SqliteType.Text);
            var pUserOrHost = command.Parameters.Add("$UserOrHost", SqliteType.Text);
            var pDescription = command.Parameters.Add("$Description", SqliteType.Text);
            
            foreach (var item in timelineItems)
            {
                pTimestamp.Value = item.Timestamp.ToString("o");
                pSource.Value = item.Source;
                pCategory.Value = item.Category;
                pSeverity.Value = item.Severity ?? (object)DBNull.Value;
                pMitreTags.Value = item.MitreTags ?? (object)DBNull.Value;
                pUserOrHost.Value = item.UserOrHost;
                pDescription.Value = item.Description;
                
                command.ExecuteNonQuery();
            }
            transaction.Commit();
        }

        public int GetUniqueHostsCount()
        {
            using var connection = OpenConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(DISTINCT MachineName) FROM Events";
            return Convert.ToInt32(command.ExecuteScalar());
        }
        private SqliteConnection OpenConnection()
        {
            return OpenEncryptedConnection(_dbPath);
        }

        private static string CreateConnectionString(string path) => new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();

        private void ApplyKey(SqliteConnection connection)
        {
            var key = GetOrCreateKey();
            try
            {
                using var command = connection.CreateCommand();
                command.CommandText = $"PRAGMA key = \"x'{Convert.ToHexString(key).ToLowerInvariant()}'\";";
                command.ExecuteNonQuery();
                command.CommandText = "SELECT count(*) FROM sqlite_master;";
                command.ExecuteScalar();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        private byte[] GetOrCreateKey()
        {
            if (File.Exists(_keyPath)) return Convert.FromBase64String(DpapiEncryptionService.Decrypt(File.ReadAllText(_keyPath)));

            var key = RandomNumberGenerator.GetBytes(32);
            try
            {
                var temporaryPath = _keyPath + ".tmp";
                File.WriteAllText(temporaryPath, DpapiEncryptionService.Encrypt(Convert.ToBase64String(key)));
                File.Move(temporaryPath, _keyPath, true);
                return key;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }

        private void MigrateLegacyDatabase(string legacyDatabasePath)
        {
            var temporaryPath = _dbPath + ".migrating-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var connection = OpenEncryptedConnection(temporaryPath))
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "ATTACH DATABASE $legacyPath AS legacy KEY '';";
                    command.Parameters.AddWithValue("$legacyPath", Path.GetFullPath(legacyDatabasePath));
                    command.ExecuteNonQuery();
                    command.Parameters.Clear();
                    command.CommandText = "SELECT sqlcipher_export('main', 'legacy');";
                    command.ExecuteNonQuery();
                    command.CommandText = "DETACH DATABASE legacy;";
                    command.ExecuteNonQuery();
                    command.CommandText = "SELECT count(*) FROM sqlite_master;";
                    command.ExecuteScalar();
                }

                File.Move(temporaryPath, _dbPath);
            }
            catch (Exception ex)
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
                throw new InvalidOperationException("The existing database could not be migrated. The original database was left unchanged.", ex);
            }
        }

        private SqliteConnection OpenEncryptedConnection(string path)
        {
            var connection = new SqliteConnection(CreateConnectionString(path));
            connection.Open();
            try
            {
                ApplyKey(connection);
                return connection;
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}

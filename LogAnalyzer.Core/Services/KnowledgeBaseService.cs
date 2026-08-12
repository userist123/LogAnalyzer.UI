using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class KnowledgeBaseService
    {
        private readonly Dictionary<int, EventKnowledgeItem> _kbDictionary = new Dictionary<int, EventKnowledgeItem>();
        private readonly string _alertsStoragePath;

        public KnowledgeBaseService()
        {
            _alertsStoragePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SavedAlerts.json");
        }

        public void LoadCategories(string categoriesFolderPath)
        {
            _kbDictionary.Clear();

            if (!Directory.Exists(categoriesFolderPath)) return;

            var jsonFiles = Directory.GetFiles(categoriesFolderPath, "*.json");
            foreach (var file in jsonFiles)
            {
                try
                {
                    string jsonContent = File.ReadAllText(file);
                    var items = JsonSerializer.Deserialize<List<EventKnowledgeItem>>(jsonContent, new JsonSerializerOptions 
                    { 
                        PropertyNameCaseInsensitive = true 
                    });

                    if (items != null)
                    {
                        foreach (var item in items)
                        {
                            if (int.TryParse(item.EventID, out int eid))
                            {
                                if (!_kbDictionary.ContainsKey(eid))
                                {
                                    _kbDictionary[eid] = item;
                                }
                            }
                        }
                    }
                }
                catch 
                { 
                    // Ignoră erorile minore de parsare JSON
                }
            }
        }

        public EventKnowledgeItem? GetDetails(int eventId)
        {
            _kbDictionary.TryGetValue(eventId, out var item);
            return item;
        }

        public void SaveAlert(DetectedIssue alert)
        {
            var existing = LoadSavedAlerts();
            existing.Insert(0, alert);
            File.WriteAllText(_alertsStoragePath, JsonSerializer.Serialize(existing, new JsonSerializerOptions { WriteIndented = true }));
        }

        public List<DetectedIssue> LoadSavedAlerts()
        {
            if (!File.Exists(_alertsStoragePath)) return new List<DetectedIssue>();
            try { return JsonSerializer.Deserialize<List<DetectedIssue>>(File.ReadAllText(_alertsStoragePath)) ?? new List<DetectedIssue>(); }
            catch { return new List<DetectedIssue>(); }
        }
    }
}
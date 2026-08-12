using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;

namespace LogAnalyzer.Core.Models
{
    public enum AlertStatus { Nouă, Investigare, Confirmată, FalsPozitiv }

    public partial class DetectedIssue : ObservableObject
    {
        [ObservableProperty] private string _title = string.Empty;
        [ObservableProperty] private string _severity = "Low";
        [ObservableProperty] private string _explanation = string.Empty;
        [ObservableProperty] private string _mitreTacticName = string.Empty;
        [ObservableProperty] private string _mitreTechniqueId = string.Empty;
        [ObservableProperty] private string _complianceTag = string.Empty;
        [ObservableProperty] private DateTime _createdAt = DateTime.Now;
        [ObservableProperty] private bool _isVerified;
        [ObservableProperty] private AlertStatus _status = AlertStatus.Nouă;
        [ObservableProperty] private string _sessionFileHashes = string.Empty;
        
        public List<ParsedEvent> RelatedEvents { get; set; } = new();
    }
}
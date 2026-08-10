using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace LogAnalyzer.Core.Models;

public partial class DetectedIssue : ObservableObject
{
    [ObservableProperty] private string _title = string.Empty;
    [ObservableProperty] private string _severity = "Medium";
    [ObservableProperty] private string _explanation = string.Empty;
    [ObservableProperty] private AlertStatus _status = AlertStatus.Nouă;
    [ObservableProperty] private DateTime _createdAt = DateTime.Now;
    [ObservableProperty] private bool _isVerified;
    [ObservableProperty] private string _mitreTechniqueId = string.Empty;
    [ObservableProperty] private string _complianceTag = string.Empty;
}

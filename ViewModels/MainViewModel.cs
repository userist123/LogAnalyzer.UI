using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Services;
using Microsoft.Win32;

namespace LogAnalyzer.UI.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IEventParser _eventParser;
    private readonly IAnalysisEngine _analysisEngine;
    private readonly IRegistryParser _registryParser;
    private readonly AuditLogService _auditService;
    private readonly KnowledgeBaseService _kbService;
    private readonly PluginManagerService _pluginManager;

    public ObservableCollection<ParsedEvent> Events { get; set; } = new();
    public ObservableCollection<DetectedIssue> DetectedIssues { get; set; } = new();
    public ObservableCollection<RegistryArtifact> RegistryArtifacts { get; set; } = new();
    public ObservableCollection<TimelineItem> TimelineItems { get; set; } = new();
    public ObservableCollection<IocItem> CurrentIocs { get; set; } = new();

    [ObservableProperty] private ICollectionView? _eventsView;
    [ObservableProperty] private ICollectionView? _artifactsView;
    [ObservableProperty] private ICollectionView? _issuesView;
    [ObservableProperty] private ICollectionView? _timelineView;

    [ObservableProperty] private string _searchEventsText = string.Empty;
    [ObservableProperty] private string _searchArtifactsText = string.Empty;

    [ObservableProperty] private string _inspectorMachineName = "-";
    [ObservableProperty] private string _inspectorProviderName = "-";
    [ObservableProperty] private string _inspectorTimeCreated = "-";
    [ObservableProperty] private string _inspectorMessage = "Selectează un eveniment sau artefact...";

    [ObservableProperty] private ParsedEvent? _selectedEvent;
    [ObservableProperty] private RegistryArtifact? _selectedArtifact;
    [ObservableProperty] private TimelineItem? _selectedTimelineItem;

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _statusMessage = "Sistem pregătit pentru investigație offline...";
    [ObservableProperty] private bool _hideVerifiedAlerts;

    public ObservableCollection<DfirProfile> Profiles { get; } = new()
    {
        new DfirProfile { Name = "1. Toate Evenimentele (Implicit)", TargetEventIds = new() },
        new DfirProfile { Name = "2. Autentificări Eșuate", TargetEventIds = new() { 4625, 4771 } },
        new DfirProfile { Name = "3. Modificări Conturi", TargetEventIds = new() { 4720, 4722 } },
        new DfirProfile { Name = "4. Evaziune Jurnale", TargetEventIds = new() { 1102, 104 } }
    };

    [ObservableProperty] private DfirProfile? _selectedProfile;

    partial void OnSearchEventsTextChanged(string value) { EventsView?.Refresh(); TimelineView?.Refresh(); }
    partial void OnSearchArtifactsTextChanged(string value) => ArtifactsView?.Refresh();
    partial void OnHideVerifiedAlertsChanged(bool value) => IssuesView?.Refresh();
    partial void OnSelectedProfileChanged(DfirProfile? value) { EventsView?.Refresh(); TimelineView?.Refresh(); }

    public MainViewModel(
        IEventParser eventParser, IAnalysisEngine analysisEngine, IRegistryParser registryParser,
        AuditLogService auditService, KnowledgeBaseService kbService, PluginManagerService pluginManager)
    {
        _eventParser = eventParser;
        _analysisEngine = analysisEngine;
        _registryParser = registryParser;
        _auditService = auditService;
        _kbService = kbService;
        _pluginManager = pluginManager;

        SelectedProfile = Profiles.First();

        EventsView = CollectionViewSource.GetDefaultView(Events);
        EventsView.Filter = FilterEvents;

        ArtifactsView = CollectionViewSource.GetDefaultView(RegistryArtifacts);
        ArtifactsView.Filter = FilterArtifacts;

        IssuesView = CollectionViewSource.GetDefaultView(DetectedIssues);
        IssuesView.Filter = FilterIssues;

        TimelineView = CollectionViewSource.GetDefaultView(TimelineItems);
        TimelineView.Filter = FilterTimeline;
    }

    private void UpdateInspector(string machine, string provider, string time, string message)
    {
        InspectorMachineName = machine;
        InspectorProviderName = provider;
        InspectorTimeCreated = time;
        InspectorMessage = message;

        Application.Current.Dispatcher.Invoke(() => CurrentIocs.Clear());

        if (string.IsNullOrWhiteSpace(message)) return;

        Task.Run(() =>
        {
            var iocs = new List<IocItem>();

            var ipMatches = Regex.Matches(message, @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b");
            foreach (Match m in ipMatches) if (!iocs.Any(i => i.Value == m.Value)) iocs.Add(new IocItem { Type = IocType.IPv4, Value = m.Value });

            var hashMatches = Regex.Matches(message, @"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{64}\b");
            foreach (Match m in hashMatches) if (!iocs.Any(i => i.Value == m.Value)) iocs.Add(new IocItem { Type = IocType.Hash, Value = m.Value });

            Application.Current.Dispatcher.Invoke(() =>
            {
                foreach (var i in iocs) CurrentIocs.Add(i);
            });
        });
    }

    partial void OnSelectedEventChanged(ParsedEvent? value) { if (value != null) UpdateInspector(value.MachineName ?? "-", value.ProviderName ?? "-", value.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), value.Message ?? ""); }
    partial void OnSelectedArtifactChanged(RegistryArtifact? value) { if (value != null) UpdateInspector("NTUSER", value.Category ?? "Registru", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), $"Cheie: {value.KeyPath}\nValoare: {value.ValueData}"); }
    partial void OnSelectedTimelineItemChanged(TimelineItem? value) { if (value != null) UpdateInspector(value.UserOrHost ?? "-", value.Source ?? "-", value.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"), value.Description ?? ""); }

    private bool _isPopupActive = false;
    private DetectedIssue? _selectedIssue;

    public DetectedIssue? SelectedIssue
    {
        get => _selectedIssue;
        set
        {
            if (_isPopupActive) return;
            SetProperty(ref _selectedIssue, value);

            if (value != null)
            {
                UpdateInspector("SOC", "Alertă Securitate", value.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"), $"{value.Title}\nSev: {value.Severity}\n{value.Explanation}");

                Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    _isPopupActive = true;
                    var alertWindow = new LogAnalyzer.UI.Views.AlertDetailWindow(value, _auditService) { Owner = Application.Current.MainWindow };
                    alertWindow.ShowDialog();
                    _selectedIssue = null;
                    OnPropertyChanged(nameof(SelectedIssue));
                    IssuesView?.Refresh();
                    _isPopupActive = false;
                });
            }
        }
    }

    [RelayCommand]
    private void OpenGenericDetail(object item)
    {
        if (item == null) return;
        Application.Current.Dispatcher.InvokeAsync(() =>
        {
            var window = new LogAnalyzer.UI.Views.GenericDetailWindow(item, EscalateToAlert) { Owner = Application.Current.MainWindow };
            window.ShowDialog();
        });
    }

    private void EscalateToAlert(object item)
    {
        string title = "Alertă Manuală Escalată", msg = "Artefact suspect identificat.";
        if (item is ParsedEvent ev) { title = $"EID {ev.EventId}"; msg = ev.Message ?? ""; }
        else if (item is RegistryArtifact reg) { title = "Registru Suspect"; msg = reg.ValueData ?? ""; }
        else if (item is TimelineItem tl) { title = tl.Category ?? "Investigație"; msg = tl.Description ?? ""; }

        var newAlert = new DetectedIssue { Title = title, Severity = "High", Explanation = msg, Status = AlertStatus.Nouă };

        Application.Current.Dispatcher.Invoke(() =>
        {
            DetectedIssues.Insert(0, newAlert);
            IssuesView?.Refresh();
            StatusMessage = "✅ Alertă manuală adăugată!";
        });
    }

    [RelayCommand]
    private void PivotIoc(string value)
    {
        SearchEventsText = value;
        StatusMessage = $"Filtrare după IOC: {value}";
    }

    [RelayCommand]
    private async Task LoadFolderAsync()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Selectează folderul cu loguri" };
        if (dialog.ShowDialog() == true) await ProcessFilesAsync(Directory.GetFiles(dialog.FolderName, "*", SearchOption.AllDirectories));
    }

    [RelayCommand]
    private async Task LoadFilesAsync()
    {
        var dialog = new OpenFileDialog { Title = "Selectează fișiere", Multiselect = true, Filter = "Toate fișierele (*.*)|*.*" };
        if (dialog.ShowDialog() == true) await ProcessFilesAsync(dialog.FileNames);
    }

    [RelayCommand]
    private void ExportToCsv()
    {
        if (EventsView == null || EventsView.IsEmpty) return;
        var dialog = new SaveFileDialog { Filter = "Raport CSV (*.csv)|*.csv", FileName = "Raport_Incident.csv" };
        if (dialog.ShowDialog() == true)
        {
            var sb = new StringBuilder(); sb.AppendLine("Data,Severitate,EventID,Sursa,Mesaj");
            foreach (ParsedEvent ev in EventsView)
                sb.AppendLine($"{ev.TimeCreated},{ev.Level},{ev.EventId},{ev.ProviderName},\"{ev.Message?.Replace("\r", " ").Replace("\n", " ") ?? ""}\"");
            File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
            StatusMessage = "Export CSV complet.";
        }
    }

    [RelayCommand]
    private void ExportPdfReport()
    {
        var dialog = new SaveFileDialog { Filter = "Raport PDF (*.pdf)|*.pdf", FileName = $"Raport_Forenzic_{DateTime.Now:yyyyMMdd_HHmmss}.pdf" };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                PdfReportService.GenerateReport(dialog.FileName, DetectedIssues.ToList(), TimelineItems.ToList(), "Hashes");
                StatusMessage = "✅ Raport PDF generat cu succes!";
            }
            catch (Exception ex) { StatusMessage = $"Eroare PDF: {ex.Message}"; }
        }
    }

    private async Task ProcessFilesAsync(string[] allFiles)
    {
        IsLoading = true;
        StatusMessage = "Procesare artefacte...";
        Events.Clear(); RegistryArtifacts.Clear(); DetectedIssues.Clear(); TimelineItems.Clear();

        await Task.Run(() =>
        {
            var evtxFiles = allFiles.Where(f => f.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var file in evtxFiles)
            {
                try
                {
                    foreach (var ev in _eventParser.ParseEvtxFile(file))
                    {
                        Application.Current.Dispatcher.Invoke(() => Events.Add(ev));
                    }
                }
                catch { }
            }

            var regFiles = allFiles.Where(f => f.EndsWith(".reg", StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var file in regFiles)
            {
                try
                {
                    foreach (var art in _registryParser.ParseRegFile(file))
                    {
                        Application.Current.Dispatcher.Invoke(() => RegistryArtifacts.Add(art));
                    }
                }
                catch { }
            }

            var hiveFiles = allFiles.Where(f =>
                Path.GetFileName(f).Equals("NTUSER.DAT", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var file in hiveFiles)
            {
                try
                {
                    foreach (var art in _registryParser.ParseNtUserDat(file))
                    {
                        Application.Current.Dispatcher.Invoke(() => RegistryArtifacts.Add(art));
                    }
                }
                catch { }
            }

            var issues = _analysisEngine.AnalyzeEvents(Events.ToList());
            Application.Current.Dispatcher.Invoke(() =>
            {
                foreach (var i in issues) DetectedIssues.Add(i);
                foreach (var ev in Events) TimelineItems.Add(new TimelineItem { Timestamp = ev.TimeCreated, Source = "EVTX", Category = $"EID {ev.EventId}", Description = ev.Message ?? "-", UserOrHost = ev.MachineName ?? "-" });
                StatusMessage = $"Procesare completă: {Events.Count} loguri, {RegistryArtifacts.Count} artefacte registru.";
            });
        });

        IsLoading = false;
    }

    private bool FilterEvents(object obj)
    {
        if (obj is not ParsedEvent ev) return false;
        if (SelectedProfile != null && SelectedProfile.TargetEventIds != null && SelectedProfile.TargetEventIds.Any() && !SelectedProfile.TargetEventIds.Contains(ev.EventId)) return false;
        if (string.IsNullOrWhiteSpace(SearchEventsText)) return true;
        string q = SearchEventsText.ToLower();
        return ev.EventId.ToString().Contains(q) || (ev.Message != null && ev.Message.ToLower().Contains(q));
    }

    private bool FilterArtifacts(object obj)
    {
        if (obj is not RegistryArtifact art) return false;
        if (string.IsNullOrWhiteSpace(SearchArtifactsText)) return true;
        string q = SearchArtifactsText.ToLower();
        return (art.KeyPath != null && art.KeyPath.ToLower().Contains(q)) ||
               (art.ValueName != null && art.ValueName.ToLower().Contains(q)) ||
               (art.ValueData != null && art.ValueData.ToLower().Contains(q)) ||
               (art.Category != null && art.Category.ToLower().Contains(q));
    }

    private bool FilterTimeline(object obj)
    {
        if (obj is not TimelineItem item) return false;
        if (string.IsNullOrWhiteSpace(SearchEventsText)) return true;
        string q = SearchEventsText.ToLower();
        return (item.Description != null && item.Description.ToLower().Contains(q)) ||
               (item.Category != null && item.Category.ToLower().Contains(q));
    }

    private bool FilterIssues(object obj) => !(HideVerifiedAlerts && ((DetectedIssue)obj).IsVerified);
}

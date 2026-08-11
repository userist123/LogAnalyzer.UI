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

namespace LogAnalyzer.UI.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly IEventParser _eventParser;
        private readonly IAnalysisEngine _analysisEngine;
        private readonly IRegistryParser _registryParser;
        private readonly AuditLogService _auditService;
        private readonly KnowledgeBaseService _kbService;
        private readonly PluginManagerService _pluginManager;
        private readonly IDatabaseService _databaseService;
        private readonly IAuditCollectionService _collectionService;

        private const int PageSize = 100;

        public ObservableCollection<ParsedEvent> Events { get; set; } = new();
        public ObservableCollection<DetectedIssue> DetectedIssues { get; set; } = new();
        public ObservableCollection<RegistryArtifact> RegistryArtifacts { get; set; } = new();
        public ObservableCollection<TimelineItem> TimelineItems { get; set; } = new();
        public ObservableCollection<IocItem> CurrentIocs { get; set; } = new();

        [ObservableProperty] private ICollectionView? _issuesView;

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

        // Session / Module Management
        [ObservableProperty] private int _selectedModuleIndex = 0; // 0 for Forensics, 1 for Collection

        // Dashboard stats
        [ObservableProperty] private int _selectedTabIndex = 0;
        [ObservableProperty] private int _totalEventsCount;
        [ObservableProperty] private int _totalAlertsCount;
        [ObservableProperty] private int _totalRegistryCount;
        [ObservableProperty] private int _totalHostsCount;

        // Paging properties
        [ObservableProperty] private int _evtxCurrentPage = 1;
        [ObservableProperty] private int _evtxTotalPages = 1;
        [ObservableProperty] private int _registryCurrentPage = 1;
        [ObservableProperty] private int _registryTotalPages = 1;
        [ObservableProperty] private int _timelineCurrentPage = 1;
        [ObservableProperty] private int _timelineTotalPages = 1;

        // Audit Data Collection Properties
        public ObservableCollection<string> TargetTypes { get; } = new() { "PC", "Server", "NAS", "DataCenter" };
        [ObservableProperty] private string _selectedTargetType = "PC";
        [ObservableProperty] private string _collectionOutputDir = "C:\\fișiere audit";
        [ObservableProperty] private string _collectionHostname = "PC-AUDIT";
        [ObservableProperty] private string _collectionLogs = string.Empty;
        [ObservableProperty] private bool _isCollectionRunning;
        [ObservableProperty] private int _syslogPort = 514;
        [ObservableProperty] private bool _isSyslogActive;

        public bool IsCollectionNotRunning => !IsCollectionRunning;
        public bool IsSyslogInactive => !IsSyslogActive;

        partial void OnIsCollectionRunningChanged(bool value) => OnPropertyChanged(nameof(IsCollectionNotRunning));
        partial void OnIsSyslogActiveChanged(bool value) => OnPropertyChanged(nameof(IsSyslogInactive));

        public ObservableCollection<DfirProfile> Profiles { get; } = new()
        {
            new DfirProfile { Name = "1. Toate Evenimentele (Implicit)", TargetEventIds = new() },
            new DfirProfile { Name = "2. Autentificări Eșuate", TargetEventIds = new() { 4625, 4771 } },
            new DfirProfile { Name = "3. Modificări Conturi", TargetEventIds = new() { 4720, 4722 } },
            new DfirProfile { Name = "4. Evaziune Jurnale", TargetEventIds = new() { 1102, 104 } }
        };

        [ObservableProperty] private DfirProfile? _selectedProfile;

        // Trigger DB reloading when search parameters change
        partial void OnSearchEventsTextChanged(string value)
        {
            EvtxCurrentPage = 1;
            TimelineCurrentPage = 1;
            ReloadEvtxFromDb();
            ReloadTimelineFromDb();
        }

        partial void OnSearchArtifactsTextChanged(string value)
        {
            RegistryCurrentPage = 1;
            ReloadRegistryFromDb();
        }

        partial void OnSelectedProfileChanged(DfirProfile? value)
        {
            EvtxCurrentPage = 1;
            ReloadEvtxFromDb();
        }

        partial void OnEvtxCurrentPageChanged(int value) => ReloadEvtxFromDb();
        partial void OnRegistryCurrentPageChanged(int value) => ReloadRegistryFromDb();
        partial void OnTimelineCurrentPageChanged(int value) => ReloadTimelineFromDb();
        partial void OnHideVerifiedAlertsChanged(bool value) => IssuesView?.Refresh();

        public MainViewModel(
            IEventParser eventParser, IAnalysisEngine analysisEngine, IRegistryParser registryParser,
            AuditLogService auditService, KnowledgeBaseService kbService, PluginManagerService pluginManager,
            IDatabaseService databaseService, IAuditCollectionService collectionService)
        {
            _eventParser = eventParser;
            _analysisEngine = analysisEngine;
            _registryParser = registryParser;
            _auditService = auditService;
            _kbService = kbService;
            _pluginManager = pluginManager;
            _databaseService = databaseService;
            _collectionService = collectionService;

            SelectedProfile = Profiles.First();

            try
            {
                string categoriesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Categories");
                _kbService.LoadCategories(categoriesPath);
            }
            catch { }

            IssuesView = CollectionViewSource.GetDefaultView(DetectedIssues);
            IssuesView.Filter = FilterIssues;
        }

        private void ReloadEvtxFromDb()
        {
            try
            {
                var targetIds = SelectedProfile?.TargetEventIds ?? new List<int>();
                int count = _databaseService.GetEventsCount(SearchEventsText, null, targetIds);
                EvtxTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetEvents(PageSize, (EvtxCurrentPage - 1) * PageSize, SearchEventsText, null, targetIds);
                Events.Clear();
                foreach (var ev in list) Events.Add(ev);
            }
            catch { }
        }

        private void ReloadRegistryFromDb()
        {
            try
            {
                int count = _databaseService.GetRegistryArtifactsCount(SearchArtifactsText);
                RegistryTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetRegistryArtifacts(PageSize, (RegistryCurrentPage - 1) * PageSize, SearchArtifactsText);
                RegistryArtifacts.Clear();
                foreach (var reg in list) RegistryArtifacts.Add(reg);
            }
            catch { }
        }

        private void ReloadTimelineFromDb()
        {
            try
            {
                int count = _databaseService.GetTimelineCount(SearchEventsText);
                TimelineTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetTimeline(PageSize, (TimelineCurrentPage - 1) * PageSize, SearchEventsText);
                TimelineItems.Clear();
                foreach (var item in list) TimelineItems.Add(item);
            }
            catch { }
        }

        private void ReloadDashboardStats()
        {
            try
            {
                TotalEventsCount = _databaseService.GetEventsCount(null, null, null);
                TotalRegistryCount = _databaseService.GetRegistryArtifactsCount(null);
                TotalHostsCount = _databaseService.GetUniqueHostsCount();
                TotalAlertsCount = DetectedIssues.Count;
            }
            catch { }
        }

        [RelayCommand]
        private void SwitchModule(string indexStr)
        {
            if (int.TryParse(indexStr, out int index))
            {
                SelectedModuleIndex = index;
                if (index == 0)
                {
                    ReloadDashboardStats();
                }
            }
        }

        [RelayCommand]
        private void Navigate(string indexStr)
        {
            if (int.TryParse(indexStr, out int index))
            {
                SelectedTabIndex = index;
            }
        }

        [RelayCommand] private void NextEvtxPage() { if (EvtxCurrentPage < EvtxTotalPages) EvtxCurrentPage++; }
        [RelayCommand] private void PrevEvtxPage() { if (EvtxCurrentPage > 1) EvtxCurrentPage--; }

        [RelayCommand] private void NextRegistryPage() { if (RegistryCurrentPage < RegistryTotalPages) RegistryCurrentPage++; }
        [RelayCommand] private void PrevRegistryPage() { if (RegistryCurrentPage > 1) RegistryCurrentPage--; }

        [RelayCommand] private void NextTimelinePage() { if (TimelineCurrentPage < TimelineTotalPages) TimelineCurrentPage++; }
        [RelayCommand] private void PrevTimelinePage() { if (TimelineCurrentPage > 1) TimelineCurrentPage--; }

        // Data Collection Commands
        [RelayCommand]
        private void SelectCollectionOutputDir()
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Selectează directorul rădăcină pentru audit" };
            if (dialog.ShowDialog() == true)
            {
                CollectionOutputDir = dialog.FolderName;
            }
        }

        [RelayCommand]
        private async Task StartCollectionAsync()
        {
            if (IsCollectionRunning) return;
            IsCollectionRunning = true;
            CollectionLogs = string.Empty;

            try
            {
                await _collectionService.RunCollectionAsync(
                    SelectedTargetType,
                    CollectionOutputDir,
                    CollectionHostname,
                    log => App.Current.Dispatcher.Invoke(() => CollectionLogs += log + Environment.NewLine)
                );
            }
            catch (Exception ex)
            {
                CollectionLogs += $"[FATAL ERROR] {ex.Message}" + Environment.NewLine;
            }
            finally
            {
                IsCollectionRunning = false;
            }
        }

        [RelayCommand]
        private void StartSyslog()
        {
            CollectionLogs = string.Empty;
            _collectionService.StartSyslogListener(
                SyslogPort,
                CollectionOutputDir,
                CollectionHostname,
                log => App.Current.Dispatcher.Invoke(() => CollectionLogs += log + Environment.NewLine)
            );
            IsSyslogActive = _collectionService.IsSyslogListenerActive;
        }

        [RelayCommand]
        private void StopSyslog()
        {
            _collectionService.StopSyslogListener();
            IsSyslogActive = false;
            CollectionLogs += "[SYSLOG] Receptorul de syslog a fost oprit de investigator." + Environment.NewLine;
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
                    foreach(var i in iocs) CurrentIocs.Add(i);
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
                        ReloadDashboardStats();
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
            else if (item is RegistryArtifact reg) { title = $"Registru Suspect"; msg = reg.ValueData ?? ""; }
            else if (item is TimelineItem tl) { title = tl.Category ?? "Investigație"; msg = tl.Description ?? ""; }

            var newAlert = new DetectedIssue { Title = title, Severity = "High", Explanation = msg, Status = AlertStatus.Nouă };
            
            Application.Current.Dispatcher.Invoke(() => 
            {
                DetectedIssues.Insert(0, newAlert);
                IssuesView?.Refresh();
                ReloadDashboardStats();
                StatusMessage = "✅ Alertă manuală adăugată!";
            });
        }

        [RelayCommand]
        private void PivotIoc(string value)
        {
            SearchEventsText = value;
            SelectedTabIndex = 1; // Comută la evenimente
            SelectedModuleIndex = 0; // Comută la forensics
            StatusMessage = $"Filtrare după IOC: {value}";
        }

        [RelayCommand]
        private async Task LoadFolderAsync()
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Selectează folderul cu loguri" };
            if (dialog.ShowDialog() == true) await ProcessFilesAsync(Directory.GetFiles(dialog.FolderName));
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
            try
            {
                var targetIds = SelectedProfile?.TargetEventIds ?? new List<int>();
                int count = _databaseService.GetEventsCount(SearchEventsText, null, targetIds);
                if (count == 0) return;

                var dialog = new SaveFileDialog { Filter = "Raport CSV (*.csv)|*.csv", FileName = "Raport_Incident.csv" };
                if (dialog.ShowDialog() == true)
                {
                    var sb = new StringBuilder(); 
                    sb.AppendLine("Data,Severitate,EventID,Sursa,Mesaj");
                    
                    int limit = 5000;
                    for (int offset = 0; offset < count; offset += limit)
                    {
                        var chunk = _databaseService.GetEvents(limit, offset, SearchEventsText, null, targetIds);
                        foreach (ParsedEvent ev in chunk)
                        {
                            sb.AppendLine($"{ev.TimeCreated},{ev.Level},{ev.EventId},{ev.ProviderName},\"{ev.Message?.Replace("\r", " ").Replace("\n", " ") ?? ""}\"");
                        }
                    }
                    
                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                    StatusMessage = "Export CSV complet.";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Eroare la export CSV: {ex.Message}";
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
                    var timeline = _databaseService.GetTimeline(500, 0, null).ToList();
                    PdfReportService.GenerateReport(dialog.FileName, DetectedIssues.ToList(), timeline, "Hashes");
                    StatusMessage = $"✅ Raport PDF generat cu succes!";
                } 
                catch (Exception ex) 
                { 
                    StatusMessage = $"Eroare PDF: {ex.Message}"; 
                }
            }
        }

        private async Task ProcessFilesAsync(string[] allFiles)
        {
            IsLoading = true;
            StatusMessage = "Inițializare bază de date SQLite...";
            Events.Clear(); RegistryArtifacts.Clear(); DetectedIssues.Clear(); TimelineItems.Clear();
            _databaseService.ClearDatabase();

            await Task.Run(() =>
            {
                var evtxFiles = allFiles.Where(f => f.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToArray();
                int totalEvtxProcessed = 0;
                foreach (var file in evtxFiles)
                {
                    try 
                    {
                        var batch = new List<ParsedEvent>();
                        var timelineBatch = new List<TimelineItem>();
                        
                        foreach (var ev in _eventParser.ParseEvtxFile(file)) 
                        {
                            var kbDetails = _kbService.GetDetails(ev.EventId);
                            if (kbDetails != null)
                            {
                                ev.OfficialDescription = kbDetails.ExtendedDescription;
                                ev.TacticalExample = kbDetails.EventExample;
                                ev.ReferenceUrl = kbDetails.ReferenceUrl;
                                ev.PotentialCriticality = kbDetails.PotentialCriticality;
                            }
                            batch.Add(ev);
                            
                            timelineBatch.Add(new TimelineItem 
                            { 
                                Timestamp = ev.TimeCreated, 
                                Source = "EVTX", 
                                Category = $"EID {ev.EventId}", 
                                Description = ev.Message ?? "-", 
                                UserOrHost = ev.MachineName ?? "-" 
                            });

                            if (batch.Count >= 5000)
                            {
                                _databaseService.SaveEvents(batch);
                                _databaseService.SaveTimeline(timelineBatch);
                                totalEvtxProcessed += batch.Count;
                                batch.Clear();
                                timelineBatch.Clear();
                                StatusMessage = $"Se încarcă logurile... ({totalEvtxProcessed} procesate)";
                            }
                        }
                        if (batch.Count > 0)
                        {
                            _databaseService.SaveEvents(batch);
                            _databaseService.SaveTimeline(timelineBatch);
                            totalEvtxProcessed += batch.Count;
                        }
                    } 
                    catch { }
                }

                var regFiles = allFiles.Where(f => f.EndsWith(".reg", StringComparison.OrdinalIgnoreCase)).ToArray();
                int totalRegProcessed = 0;
                foreach (var file in regFiles)
                {
                    try 
                    {
                        var batch = new List<RegistryArtifact>();
                        foreach (var reg in _registryParser.ParseRegFile(file)) 
                        {
                            batch.Add(reg);
                            if (batch.Count >= 5000)
                            {
                                _databaseService.SaveRegistryArtifacts(batch);
                                totalRegProcessed += batch.Count;
                                batch.Clear();
                                StatusMessage = $"Se încarcă artefacte registru... ({totalRegProcessed} procesate)";
                            }
                        }
                        if (batch.Count > 0)
                        {
                            _databaseService.SaveRegistryArtifacts(batch);
                            totalRegProcessed += batch.Count;
                        }
                    } 
                    catch { }
                }

                var datFiles = allFiles.Where(f => f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase) || f.EndsWith("ntuser", StringComparison.OrdinalIgnoreCase)).ToArray();
                foreach (var file in datFiles)
                {
                    try 
                    {
                        var batch = new List<RegistryArtifact>();
                        foreach (var reg in _registryParser.ParseNtUserDat(file)) 
                        {
                            batch.Add(reg);
                            if (batch.Count >= 5000)
                            {
                                _databaseService.SaveRegistryArtifacts(batch);
                                totalRegProcessed += batch.Count;
                                batch.Clear();
                                StatusMessage = $"Se încarcă NTUSER.DAT... ({totalRegProcessed} procesate)";
                            }
                        }
                        if (batch.Count > 0)
                        {
                            _databaseService.SaveRegistryArtifacts(batch);
                            totalRegProcessed += batch.Count;
                        }
                    } 
                    catch { }
                }

                StatusMessage = "Analiză de securitate...";
                var securityEventIds = new List<int> { 1102, 104, 4625, 4624, 4720, 4722, 4732, 7045, 4697, 4688 };
                var eventsForAnalysis = _databaseService.GetEvents(100000, 0, null, null, securityEventIds).ToList();
                
                var issues = _analysisEngine.AnalyzeEvents(eventsForAnalysis);
                
                Application.Current.Dispatcher.Invoke(() => 
                {
                    foreach (var i in issues) DetectedIssues.Add(i);
                });
            });

            EvtxCurrentPage = 1;
            RegistryCurrentPage = 1;
            TimelineCurrentPage = 1;
            
            ReloadEvtxFromDb();
            ReloadRegistryFromDb();
            ReloadTimelineFromDb();
            ReloadDashboardStats();
            
            SelectedTabIndex = 0; 
            IsLoading = false;
            StatusMessage = $"Procesare completă: {TotalEventsCount} loguri și {TotalRegistryCount} artefacte registru salvate.";
        }

        private bool FilterIssues(object obj) => !(HideVerifiedAlerts && ((DetectedIssue)obj).IsVerified);
    }
}
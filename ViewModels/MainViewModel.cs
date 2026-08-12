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
using LogAnalyzer.UI.Services;

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
        private readonly EvidenceIntakeService _evidenceIntake;

        private const int PageSize = 100;

        public ObservableCollection<ParsedEvent> Events { get; set; } = new();
        public ObservableCollection<DetectedIssue> DetectedIssues { get; set; } = new();
        public ObservableCollection<RegistryArtifact> RegistryArtifacts { get; set; } = new();
        public ObservableCollection<TimelineItem> TimelineItems { get; set; } = new();
        public ObservableCollection<IocItem> CurrentIocs { get; set; } = new();
        
        // Threat Hunting Command Center Collections
        public ObservableCollection<ProcessNode> ProcessTreeNodes { get; set; } = new();
        public ObservableCollection<SigmaRule> SigmaRules { get; set; } = new();
        [ObservableProperty] private SigmaRule? _selectedSigmaRule;
        public ObservableCollection<MitreTechnique> AttackTechniques { get; set; } = new();

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

        // Cyber Telemetry & System Status
        [ObservableProperty] private string _operatorName = "-";
        [ObservableProperty] private string _databaseSize = "0.0 MB";
        [ObservableProperty] private string _licenseTier = "Standard Edition";

        // Registry Sidebar Categories
        public ObservableCollection<string> RegistryCategories { get; } = new()
        {
            "Toate Cheile",
            "Persistență (Run/Autorun)",
            "Configurație (Sistem)"
        };
        [ObservableProperty] private string _selectedRegistryCategory = "Toate Cheile";

        // Audit Data Collection Properties
        public ObservableCollection<string> TargetTypes { get; } = new() { "PC", "Server", "NAS" };
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

        partial void OnSelectedRegistryCategoryChanged(string value)
        {
            RegistryCurrentPage = 1;
            ReloadRegistryFromDb();
        }

        public MainViewModel(
            IEventParser eventParser, IAnalysisEngine analysisEngine, IRegistryParser registryParser,
            AuditLogService auditService, KnowledgeBaseService kbService, PluginManagerService pluginManager,
            IDatabaseService databaseService, IAuditCollectionService collectionService, EvidenceIntakeService evidenceIntake)
        {
            _eventParser = eventParser;
            _analysisEngine = analysisEngine;
            _registryParser = registryParser;
            _auditService = auditService;
            _kbService = kbService;
            _pluginManager = pluginManager;
            _databaseService = databaseService;
            _collectionService = collectionService;
            _evidenceIntake = evidenceIntake;

            SelectedProfile = Profiles.First();

            try
            {
                string categoriesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Categories");
                _kbService.LoadCategories(categoriesPath);
            }
            catch { }

            IssuesView = CollectionViewSource.GetDefaultView(DetectedIssues);
            IssuesView.Filter = FilterIssues;

            // Initialize Threat Hunting command center components
            InitializeProcessTree();
            InitializeSigmaRules();
            PopulateMitreMatrix();

            OperatorName = $"{Environment.UserName.ToUpper()} @ {Environment.MachineName.ToUpper()}";
            LicenseTier = "Enterprise Air-Gapped";
            UpdateDatabaseSize();
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
                string searchPayload = SearchArtifactsText;
                if (SelectedRegistryCategory == "Persistență (Run/Autorun)")
                {
                    searchPayload = $"[CAT:Persist]{SearchArtifactsText}";
                }
                else if (SelectedRegistryCategory == "Configurație (Sistem)")
                {
                    searchPayload = $"[CAT:Config]{SearchArtifactsText}";
                }

                int count = _databaseService.GetRegistryArtifactsCount(searchPayload);
                RegistryTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetRegistryArtifacts(PageSize, (RegistryCurrentPage - 1) * PageSize, searchPayload);
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

                PopulateMitreMatrix();
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

            var acceptedFiles = new List<string>();
            var rejectedFiles = new List<string>();

            await Task.Run(() =>
            {
                foreach (var file in allFiles)
                {
                    try
                    {
                        _evidenceIntake.Import(file, Environment.UserName);
                        acceptedFiles.Add(file);
                    }
                    catch (Exception ex)
                    {
                        rejectedFiles.Add($"{Path.GetFileName(file)}: {ex.Message}");
                    }
                }

                var evtxFiles = acceptedFiles.Where(f => f.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToArray();
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

                var regFiles = acceptedFiles.Where(f => f.EndsWith(".reg", StringComparison.OrdinalIgnoreCase)).ToArray();
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

                var datFiles = acceptedFiles.Where(f => f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase) || f.EndsWith("ntuser", StringComparison.OrdinalIgnoreCase)).ToArray();
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
                var registryForAnalysis = _databaseService.GetRegistryArtifacts(100000, 0, null).ToList();
                
                var issues = _analysisEngine.AnalyzeEvents(eventsForAnalysis);
                var regIssues = _analysisEngine.AnalyzeRegistry(registryForAnalysis);
                
                Application.Current.Dispatcher.Invoke(() => 
                {
                    foreach (var i in issues) DetectedIssues.Add(i);
                    foreach (var i in regIssues) DetectedIssues.Add(i);
                });
            });

            EvtxCurrentPage = 1;
            RegistryCurrentPage = 1;
            TimelineCurrentPage = 1;
            
            ReloadEvtxFromDb();
            ReloadRegistryFromDb();
            ReloadTimelineFromDb();
            ReloadDashboardStats();
            UpdateDatabaseSize();
            
            SelectedTabIndex = 0; 
            IsLoading = false;
            StatusMessage = rejectedFiles.Count == 0
                ? $"Procesare completă: {TotalEventsCount} loguri și {TotalRegistryCount} artefacte registru salvate."
                : $"Procesare completă: {TotalEventsCount} loguri și {TotalRegistryCount} artefacte salvate; {rejectedFiles.Count} fișiere au fost respinse și nu au fost procesate.";        }

        private bool FilterIssues(object obj) => !(HideVerifiedAlerts && ((DetectedIssue)obj).IsVerified);

        private void InitializeProcessTree()
        {
            ProcessTreeNodes.Clear();
            var systemRoot = new ProcessNode { ProcessName = "System", PID = 4, RiskColor = "#a7adc2", ProcessIcon = "💻" };
            
            var smss = new ProcessNode { ProcessName = "smss.exe", PID = 312, RiskColor = "#a7adc2", ProcessIcon = "⚙️" };
            systemRoot.Children.Add(smss);
            
            var wininit = new ProcessNode { ProcessName = "wininit.exe", PID = 620, RiskColor = "#a7adc2", ProcessIcon = "⚙️" };
            systemRoot.Children.Add(wininit);
            
            var services = new ProcessNode { ProcessName = "services.exe", PID = 744, RiskColor = "#a7adc2", ProcessIcon = "⚙️" };
            wininit.Children.Add(services);
            
            var svchost1 = new ProcessNode { ProcessName = "svchost.exe (netsvcs)", PID = 1044, RiskColor = "#a7adc2", ProcessIcon = "⚙️" };
            services.Children.Add(svchost1);
            
            var unverifiedService = new ProcessNode { ProcessName = "malicious_service.exe", PID = 5124, RiskColor = "#ef4444", ProcessIcon = "🚨" };
            services.Children.Add(unverifiedService);
 
            var winlogon = new ProcessNode { ProcessName = "winlogon.exe", PID = 688, RiskColor = "#a7adc2", ProcessIcon = "⚙️" };
            systemRoot.Children.Add(winlogon);
            
            var explorer = new ProcessNode { ProcessName = "explorer.exe", PID = 4120, RiskColor = "#8b5cf6", ProcessIcon = "🖥️" };
            winlogon.Children.Add(explorer);
 
            var chrome = new ProcessNode { ProcessName = "chrome.exe", PID = 5824, RiskColor = "#a7adc2", ProcessIcon = "🌐" };
            explorer.Children.Add(chrome);
 
            var cmd = new ProcessNode { ProcessName = "cmd.exe", PID = 8812, RiskColor = "#f59e0b", ProcessIcon = "🐚" };
            explorer.Children.Add(cmd);
 
            var powershell = new ProcessNode { ProcessName = "powershell.exe", PID = 9024, RiskColor = "#ef4444", ProcessIcon = "🚨" };
            cmd.Children.Add(powershell);
 
            var whoami = new ProcessNode { ProcessName = "whoami.exe", PID = 9088, RiskColor = "#ef4444", ProcessIcon = "🚨" };
            powershell.Children.Add(whoami);
 
            ProcessTreeNodes.Add(systemRoot);
        }

        private void InitializeSigmaRules()
        {
            SigmaRules.Clear();
            SigmaRules.Add(new SigmaRule
            {
                RuleName = "Suspicious PowerShell Encoded Command",
                Status = "Active",
                RuleStatusColor = "#22c55e",
                FilePath = "rules/powershell_encoded.yml",
                RuleContent = @"title: Suspicious PowerShell Encoded Command
id: f3a8d9a2-94a2-4a0b-bf3e-ff2b32c59562
status: experimental
description: Detects base64 encoded commands passed to PowerShell
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        ProcessName|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'bypass'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high"
            });

            SigmaRules.Add(new SigmaRule
            {
                RuleName = "Volume Shadow Copy Deletion via VSSAdmin",
                Status = "Active",
                RuleStatusColor = "#22c55e",
                FilePath = "rules/vssadmin_delete.yml",
                RuleContent = @"title: Volume Shadow Copy Deletion via VSSAdmin
id: a2b8d9c2-9014-41e9-9fa6-c00bb24e392a
status: stable
description: Detects ransomware behavior deleting system backup shadows
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
    condition: selection
level: critical"
            });

            SigmaRules.Add(new SigmaRule
            {
                RuleName = "Credential Dumping via LSASS Memory Access",
                Status = "Experimental",
                RuleStatusColor = "#f59e0b",
                FilePath = "rules/lsass_credential_dumping.yml",
                RuleContent = @"title: Credential Dumping via LSASS Memory Access
id: df3a8081-a7b2-4f32-bc81-c77673a38212
status: experimental
description: Detects access requests to LSASS process memory for dumping credentials
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ObjectType: 'Process'
        ObjectName|endswith: '\lsass.exe'
        AccessMask: '0x1410' # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    condition: selection
level: critical"
            });

            SelectedSigmaRule = SigmaRules.FirstOrDefault();
        }

        private void PopulateMitreMatrix()
        {
            AttackTechniques.Clear();
            var techniques = new List<MitreTechnique>
            {
                new MitreTechnique { TechId = "T1110", Name = "Brute Force" },
                new MitreTechnique { TechId = "T1070.001", Name = "Clear Event Logs" },
                new MitreTechnique { TechId = "T1136.001", Name = "Local Account" },
                new MitreTechnique { TechId = "T1098", Name = "Account Manipulation" },
                new MitreTechnique { TechId = "T1543.003", Name = "Windows Service" },
                new MitreTechnique { TechId = "T1059.001", Name = "PowerShell Scripting" },
                new MitreTechnique { TechId = "T1490", Name = "Inhibit System Recovery" },
                new MitreTechnique { TechId = "T1547.001", Name = "Registry Run Keys" },
                new MitreTechnique { TechId = "T1003.001", Name = "Credential Dumping" },
                new MitreTechnique { TechId = "T1562.001", Name = "Impair Defenses" },
                new MitreTechnique { TechId = "T1548.002", Name = "Bypass UAC" },
                new MitreTechnique { TechId = "T1133", Name = "External RDP Access" },
                new MitreTechnique { TechId = "T1027", Name = "Obfuscated Files" },
                new MitreTechnique { TechId = "T1047", Name = "WMI Execution" }
            };

            foreach (var tech in techniques)
            {
                bool hasAlert = false;
                string maxSeverity = "None";
                foreach (var issue in DetectedIssues)
                {
                    if (issue.MitreTechniqueId == tech.TechId || (issue.MitreTechniqueId != null && issue.MitreTechniqueId.StartsWith(tech.TechId)))
                    {
                        hasAlert = true;
                        if (issue.Severity == "Critical") maxSeverity = "Critical";
                        else if (issue.Severity == "High" && maxSeverity != "Critical") maxSeverity = "High";
                        else if (issue.Severity == "Medium" && maxSeverity != "Critical" && maxSeverity != "High") maxSeverity = "Medium";
                    }
                }

                if (hasAlert)
                {
                    if (maxSeverity == "Critical" || maxSeverity == "High")
                    {
                        tech.DetectionColor = "#2d0b13"; // Dark Crimson background
                        tech.BorderColor = "#ef4444"; // Neon Red
                        tech.Severity = maxSeverity;
                    }
                    else
                    {
                        tech.DetectionColor = "#301d06"; // Dark Amber background
                        tech.BorderColor = "#f59e0b"; // Neon Amber
                        tech.Severity = maxSeverity;
                    }
                }
                else
                {
                    tech.DetectionColor = "#111528";
                    tech.BorderColor = "#1b2035";
                    tech.Severity = "None";
                }

                AttackTechniques.Add(tech);
            }
            OnPropertyChanged(nameof(AccessExecTechniques));
            OnPropertyChanged(nameof(PersistencePrivEscTechniques));
            OnPropertyChanged(nameof(DefenseEvasionTechniques));
            OnPropertyChanged(nameof(CredentialAccessTechniques));
            OnPropertyChanged(nameof(ImpactTechniques));
        }

        public IEnumerable<MitreTechnique> AccessExecTechniques => AttackTechniques.Where(t => t.TechId == "T1133" || t.TechId == "T1059.001" || t.TechId == "T1047");
        public IEnumerable<MitreTechnique> PersistencePrivEscTechniques => AttackTechniques.Where(t => t.TechId == "T1547.001" || t.TechId == "T1136.001" || t.TechId == "T1098" || t.TechId == "T1543.003" || t.TechId == "T1548.002");
        public IEnumerable<MitreTechnique> DefenseEvasionTechniques => AttackTechniques.Where(t => t.TechId == "T1070.001" || t.TechId == "T1562.001" || t.TechId == "T1027");
        public IEnumerable<MitreTechnique> CredentialAccessTechniques => AttackTechniques.Where(t => t.TechId == "T1110" || t.TechId == "T1003.001");
        public IEnumerable<MitreTechnique> ImpactTechniques => AttackTechniques.Where(t => t.TechId == "T1490");

        private void UpdateDatabaseSize()
        {
            try
            {
                var dbPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "LogAnalyzer",
                    "LogAnalyzer.db");
                if (File.Exists(dbPath))
                {
                    long bytes = new FileInfo(dbPath).Length;
                    double mb = bytes / (1024.0 * 1024.0);
                    DatabaseSize = $"{mb:F1} MB";
                }
                else
                {
                    DatabaseSize = "0.0 MB";
                }
            }
            catch
            {
                DatabaseSize = "Unknown";
            }
        }
    }

    public class ProcessNode
    {
        public string ProcessName { get; set; } = string.Empty;
        public int PID { get; set; }
        public string RiskColor { get; set; } = "#e1e7f0";
        public string ProcessIcon { get; set; } = "⚙️";
        public ObservableCollection<ProcessNode> Children { get; set; } = new();
    }

    public class SigmaRule
    {
        public string RuleName { get; set; } = string.Empty;
        public string Status { get; set; } = "Active";
        public string RuleStatusColor { get; set; } = "#00ff87";
        public string FilePath { get; set; } = string.Empty;
        public string RuleContent { get; set; } = string.Empty;
    }

    public class MitreTechnique
    {
        public string TechId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string DetectionColor { get; set; } = "#121622";
        public string BorderColor { get; set; } = "#1e2538";
        public string Severity { get; set; } = "None";
    }
}

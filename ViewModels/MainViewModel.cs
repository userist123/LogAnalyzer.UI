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
            LicenseTier = "Enterprise Air-Gapped";
            UpdateDatabaseSize();
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

            UpdateInspector(value.MachineName ?? "-", value.ProviderName ?? "-", value.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), value.Message ?? "");

            SelectedEventProperties.Add(new("ID Eveniment", value.EventId.ToString()));
            SelectedEventProperties.Add(new("Sursă Jurnal", value.ProviderName ?? "-"));
            SelectedEventProperties.Add(new("Nivel Severitate", value.Level ?? "-"));
            SelectedEventProperties.Add(new("Nume Echipament", value.MachineName ?? "-"));
            SelectedEventProperties.Add(new("Data Colectare", value.TimeCreated.ToString("g")));

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

            if (value.EventId == 4625)
            {
                SelectedEventThreatScenario = "Atac de tip Brute Force sau Spraying de parole vizând contul de utilizator.";
                SelectedEventMitreMapping = "Credential Access - Brute Force (T1110)";
                SelectedEventMitigation = "1. Blocarea temporară a contului afectat.\n2. Verificarea IP-ului sursă din detaliile XML.\n3. Activarea autentificării multi-factor (MFA).\n4. Revizuirea politicilor de complexitate a parolelor.";
            }
            else if (value.EventId == 4720 || value.EventId == 4732)
            {
                SelectedEventThreatScenario = "Crearea unui cont local nou sau adăugarea unui cont în grupul de administratori locali.";
                SelectedEventMitreMapping = "Persistence - Local Account (T1136.001)";
                SelectedEventMitigation = "1. Validarea creării contului cu administratorii IT.\n2. Verificarea procesului care a inițiat modificarea.\n3. Eliminarea imediată a contului dacă este neautorizat.\n4. Auditarea drepturilor de administrator local.";
            }
            else if (value.EventId == 1102 || value.EventId == 104)
            {
                SelectedEventThreatScenario = "Curățarea sau ștergerea jurnalele de evenimente (EVTX) de securitate/sistem pentru a șterge urmele atacului.";
                SelectedEventMitreMapping = "Defense Evasion - Indicator Removal (T1070.001)";
                SelectedEventMitigation = "1. Identificarea utilizatorului și PID-ului procesului responsabil.\n2. Inspectarea activității imediate anterioare a host-ului.\n3. Centralizarea obligatorie a log-urilor pe un server extern (Syslog/SIEM air-gapped).";
            }
            else
            {
                SelectedEventThreatScenario = value.OfficialDescription ?? "Activitate de sistem înregistrată pentru analiză forenzică standard.";
                SelectedEventMitreMapping = string.IsNullOrWhiteSpace(value.PotentialCriticality) ? "Traseu de Audit Standard" : $"{value.PotentialCriticality} - Reference ID {value.EventId}";
                SelectedEventMitigation = value.TacticalExample ?? "1. Verificați legitimitatea procesului apelant.\n2. Comparați timestamp-ul cu baseline-ul de activitate al utilizatorului.";
            }
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

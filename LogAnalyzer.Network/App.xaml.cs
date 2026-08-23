using System;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure;
using LogAnalyzer.Infrastructure.Parsers;
using LogAnalyzer.Infrastructure.Services;
using LogAnalyzer.UI.ViewModels;
using LogAnalyzer.UI.Services;
using LogAnalyzer.UI.Views;

namespace LogAnalyzer.UI
{
    public partial class App : Application
    {
        public static IServiceProvider? ServiceProvider { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            string debugLogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_debug.log");
            string crashLogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_crash.log");

            SplashWindow? splash = null;
            try
            {
                File.WriteAllText(debugLogPath, "OnStartup starting...\n");
                base.OnStartup(e);

                this.DispatcherUnhandledException += (sender, args) =>
                {
                    File.AppendAllText(debugLogPath, $"Dispatcher unhandled exception: {args.Exception}\n");
                    MessageBox.Show($"Eroare critică internă:\n{args.Exception.Message}", "Crash", MessageBoxButton.OK, MessageBoxImage.Error);
                    args.Handled = true;
                };

                var services = new ServiceCollection();
                
                // Servicii Core (Utilitare)
                services.AddSingleton<AuditLogService>();
                services.AddSingleton<PluginManagerService>();
                services.AddSingleton<KnowledgeBaseService>();
                services.AddSingleton<LogAnalyzer.Core.Services.LicenseService>();

                var applicationDataPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "LogAnalyzer");
                Directory.CreateDirectory(applicationDataPath);
                services.AddSingleton<SecurePathService>();
                services.AddSingleton(sp => new ChainOfCustodyService(Path.Combine(applicationDataPath, "chain-of-custody.ndjson")));
                services.AddSingleton<EvidenceIntakeService>();
                // Motoarele din Infrastructure
                services.AddSingleton<IEventParser, EvtxParser>();
                services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
                services.AddSingleton<IRegistryParser, OfflineRegistryParser>();
                services.AddSingleton<IDatabaseService, DatabaseService>();
                services.AddSingleton<IAuditCollectionService, AuditCollectionService>();
                
                // Componentele MVVM și Ferestrele din UI
                services.AddTransient<MainViewModel>();
                services.AddTransient<MainWindow>();
                services.AddTransient<ActivationWindow>();

                File.AppendAllText(debugLogPath, "Building ServiceProvider...\n");
                ServiceProvider = services.BuildServiceProvider();
                File.AppendAllText(debugLogPath, "ServiceProvider built. Initializing Database...\n");

                var dbService = ServiceProvider.GetRequiredService<IDatabaseService>();
                dbService.InitializeDatabase();
                File.AppendAllText(debugLogPath, "Database initialized.\n");

                this.ShutdownMode = ShutdownMode.OnMainWindowClose;

                File.AppendAllText(debugLogPath, "Showing SplashWindow...\n");
                splash = new SplashWindow();
                splash.Show();
                File.AppendAllText(debugLogPath, "SplashWindow shown.\n");

                // 2. Verificăm licența
                var licenseService = ServiceProvider.GetRequiredService<LogAnalyzer.Core.Services.LicenseService>();
                File.AppendAllText(debugLogPath, $"Verifying license... (IsActivated: {licenseService.IsActivated()})\n");
                if (!licenseService.IsActivated())
                {
                    File.AppendAllText(debugLogPath, "License is not activated. Showing ActivationWindow...\n");
                    var activationWindow = ServiceProvider.GetRequiredService<ActivationWindow>();
                    bool? activated = activationWindow.ShowDialog();
                    File.AppendAllText(debugLogPath, $"ActivationWindow ShowDialog returned: {activated}\n");
                    if (activated != true)
                    {
                        File.AppendAllText(debugLogPath, "Shutdown called due to license failure.\n");
                        splash.Close();
                        this.Shutdown();
                        return;
                    }
                }

                // 3. Afișăm fereastra principală
                File.AppendAllText(debugLogPath, "Resolving MainWindow...\n");
                var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
                this.MainWindow = mainWindow;
                File.AppendAllText(debugLogPath, "Showing MainWindow...\n");
                mainWindow.Show();
                File.AppendAllText(debugLogPath, "MainWindow shown. Closing SplashWindow...\n");
                splash.Close();
                File.AppendAllText(debugLogPath, "Startup complete.\n");
            }
            catch (Exception ex)
            {
                File.WriteAllText(crashLogPath, $"CRASH: {ex.ToString()}");
                MessageBox.Show($"Eroare critică la pornire:\n\n{ex.Message}\n\n{ex.StackTrace}", "Eroare LogAnalyzer", MessageBoxButton.OK, MessageBoxImage.Error);
                try { splash?.Close(); } catch {}
                this.Shutdown();
            }
        }
    }
}

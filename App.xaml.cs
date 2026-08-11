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
                services.AddSingleton<LicenseService>();
                
                // Motoarele din Infrastructure
                services.AddSingleton<IEventParser, EvtxParser>();
                services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
                services.AddSingleton<IRegistryParser, OfflineRegistryParser>();
                services.AddSingleton<IDatabaseService, DatabaseService>();
                
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

                // Setăm temporar modul de oprire la explicit pentru a nu se închide aplicația când se închide SplashWindow
                this.ShutdownMode = ShutdownMode.OnExplicitShutdown;

                File.AppendAllText(debugLogPath, "Showing SplashWindow...\n");
                // 1. Afișăm SplashWindow
                var splash = new SplashWindow();
                splash.Show();
                File.AppendAllText(debugLogPath, "SplashWindow shown.\n");

                // 2. Verificăm licența
                var licenseService = ServiceProvider.GetRequiredService<LicenseService>();
                File.AppendAllText(debugLogPath, $"Verifying license... (IsActivated: {licenseService.IsActivated()})\n");
                if (!licenseService.IsActivated())
                {
                    File.AppendAllText(debugLogPath, "License is not activated. Showing ActivationWindow...\n");
                    splash.Hide();
                    var activationWindow = ServiceProvider.GetRequiredService<ActivationWindow>();
                    bool? activated = activationWindow.ShowDialog();
                    File.AppendAllText(debugLogPath, $"ActivationWindow ShowDialog returned: {activated}\n");
                    if (activated != true)
                    {
                        File.AppendAllText(debugLogPath, "Shutdown called due to license failure.\n");
                        this.Shutdown();
                        return;
                    }
                    splash.Show();
                }

                // Simulăm un mic delay pentru splash screen (1.5 secunde) pentru efect vizual de inițializare
                File.AppendAllText(debugLogPath, "Sleeping for 1500ms...\n");
                System.Threading.Thread.Sleep(1500);
                File.AppendAllText(debugLogPath, "Closing SplashWindow...\n");
                splash.Close();
                File.AppendAllText(debugLogPath, "SplashWindow closed.\n");

                // 3. Afișăm fereastra principală
                File.AppendAllText(debugLogPath, "Resolving MainWindow...\n");
                var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
                this.MainWindow = mainWindow;
                File.AppendAllText(debugLogPath, "Showing MainWindow...\n");
                mainWindow.Show();
                File.AppendAllText(debugLogPath, "MainWindow shown.\n");

                // Restabilim comportamentul normal de închidere
                this.ShutdownMode = ShutdownMode.OnLastWindowClose;
                File.AppendAllText(debugLogPath, "Startup complete.\n");
            }
            catch (Exception ex)
            {
                File.WriteAllText(crashLogPath, $"CRASH: {ex.ToString()}");
            }
        }
    }
}
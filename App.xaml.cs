using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure;
using LogAnalyzer.UI.ViewModels;
using LogAnalyzer.UI.Views;

namespace LogAnalyzer.UI;

public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        this.DispatcherUnhandledException += (sender, args) =>
        {
            MessageBox.Show($"Eroare critică internă:\n{args.Exception.Message}", "Crash", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        var services = new ServiceCollection();

        // Servicii Core (Utilitare)
        services.AddSingleton<AuditLogService>();
        services.AddSingleton<KnowledgeBaseService>();
        services.AddSingleton<PluginManagerService>();
        services.AddSingleton<LicenseService>();

        // Motoarele din Infrastructure
        services.AddSingleton<IEventParser, EvtxParser>();
        services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
        services.AddSingleton<IRegistryParser, RegistryParser>();

        // Componentele MVVM și ferestrele din UI
        services.AddTransient<MainViewModel>();
        services.AddTransient<MainWindow>();
        services.AddTransient<ActivationWindow>();

        ServiceProvider = services.BuildServiceProvider();

        // Verificăm licența ÎNAINTE de a afișa fereastra principală.
        // Dacă nu este activată sau a expirat, blocăm accesul la aplicație.
        var licenseService = ServiceProvider.GetRequiredService<LicenseService>();
        if (!licenseService.IsActivated())
        {
            var activationWindow = ServiceProvider.GetRequiredService<ActivationWindow>();
            bool? activated = activationWindow.ShowDialog();

            if (activated != true)
            {
                Shutdown();
                return;
            }
        }

        // Afișăm fereastra principală
        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }
}

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

        services.AddSingleton<AuditLogService>();
        services.AddSingleton<KnowledgeBaseService>();
        services.AddSingleton<PluginManagerService>();
        services.AddSingleton<LicenseService>();

        services.AddSingleton<IEventParser, EvtxParser>();
        services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
        services.AddSingleton<IRegistryParser, RegistryParser>();

        services.AddTransient<MainViewModel>();
        services.AddTransient<MainWindow>();
        services.AddTransient<ActivationWindow>();

        ServiceProvider = services.BuildServiceProvider();

        var licenseService = ServiceProvider.GetRequiredService<LicenseService>();
        if (!licenseService.IsActivated)
        {
            var activationWindow = ServiceProvider.GetRequiredService<ActivationWindow>();
            bool? activated = activationWindow.ShowDialog();

            if (activated != true)
            {
                Shutdown();
                return;
            }
        }

        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }
}

using System;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using LogAnalyzer.UI.Services;
using LogAnalyzer.UI.ViewModels;
using LogAnalyzer.UI.Views;

namespace LogAnalyzer.UI;

public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"Eroare critică internă:\n{args.Exception.Message}",
                "LogAnalyzer.UI Crash",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };

        Exit += (_, _) =>
        {
            if (ServiceProvider is IDisposable disposable)
                disposable.Dispose();
        };

        var services = new ServiceCollection();
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogAnalyzer.UI");
        Directory.CreateDirectory(appData);

        var custodyLogPath = Path.Combine(appData, "custody.log");
        var databasePath = Path.Combine(appData, "knowledge.db");
        var databaseKeyPath = Path.Combine(appData, "knowledge.key");

        services.AddSingleton(new SecurityBootstrap(custodyLogPath));
        services.AddSingleton(sp => sp.GetRequiredService<SecurityBootstrap>().HardwareIdentity);
        services.AddSingleton(sp => sp.GetRequiredService<SecurityBootstrap>().SecurePaths);
        services.AddSingleton(sp => sp.GetRequiredService<SecurityBootstrap>().ChainOfCustody);
        services.AddSingleton<EvidenceIntakeService>();

        services.AddSingleton<ProtectedSecretStore>();
        services.AddSingleton(sp => new SqlCipherKeyStore(sp.GetRequiredService<ProtectedSecretStore>(), databaseKeyPath));
        services.AddSingleton(sp => new SqlCipherDatabase(databasePath, sp.GetRequiredService<SqlCipherKeyStore>()));
        services.AddSingleton<IocKnowledgeBaseService>();

        services.AddTransient<MainViewModel>();
        services.AddTransient<MainWindow>();

        ServiceProvider = services.BuildServiceProvider();

        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        MainWindow = mainWindow;
        mainWindow.Show();
    }
}

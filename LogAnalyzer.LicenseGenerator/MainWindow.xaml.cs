using System;
using System.IO;
using System.Windows;
using LogAnalyzer.Core.Services;
using Microsoft.Win32;

namespace LogAnalyzer.LicenseGenerator;

public partial class MainWindow : Window
{
    private readonly LicenseService _licenseService = new();

    public MainWindow()
    {
        InitializeComponent();
        HardwareIdTextBox.Text = _licenseService.GetHardwareId();
        ExpiryDatePicker.SelectedDate = DateTime.Today.AddYears(1);
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        if (ExpiryDatePicker.SelectedDate is not DateTime expiry || expiry.Date <= DateTime.UtcNow.Date)
        {
            StatusText.Text = "Alege o dată de expirare în viitor.";
            return;
        }

        var date = expiry.Date.ToString("yyyy-MM-dd");
        var key = _licenseService.GenerateKey(HardwareIdTextBox.Text, expiry.Date);
        LicenseTextBox.Text = $"{key}|{date}";
        StatusText.Text = "Licență generată. Copiază valoarea în ActivationWindow.";
    }

    private void CopyHardwareId_Click(object sender, RoutedEventArgs e)
    {
        Clipboard.SetText(HardwareIdTextBox.Text);
        StatusText.Text = "Hardware ID copiat.";
    }

    private void CopyLicense_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(LicenseTextBox.Text))
        {
            StatusText.Text = "Generează mai întâi o licență.";
            return;
        }

        Clipboard.SetText(LicenseTextBox.Text);
        StatusText.Text = "Licență copiată în clipboard.";
    }

    private void SaveLicense_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(LicenseTextBox.Text))
        {
            StatusText.Text = "Generează mai întâi o licență.";
            return;
        }

        var dialog = new SaveFileDialog { Filter = "License file (*.lic)|*.lic", FileName = "license.lic" };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, LicenseTextBox.Text);
            StatusText.Text = $"Licența a fost salvată: {Path.GetFileName(dialog.FileName)}";
        }
    }
}

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
        HardwareIdTextBox.Text = string.Empty;
        ExpiryDatePicker.SelectedDate = DateTime.Today.AddYears(1);
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        var hardwareId = HardwareIdTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(hardwareId))
        {
            StatusText.Text = "Introdu Hardware ID-ul clientului.";
            HardwareIdTextBox.Focus();
            return;
        }

        if (ExpiryDatePicker.SelectedDate is not DateTime expiry || expiry.Date <= DateTime.UtcNow.Date)
        {
            StatusText.Text = "Alege o datÄƒ de expirare Ã®n viitor.";
            return;
        }

        var date = expiry.Date.ToString("yyyy-MM-dd");
        var key = _licenseService.GenerateKey(hardwareId, expiry.Date);
        LicenseTextBox.Text = $"{key}|{date}";
        StatusText.Text = "LicenÈ›Äƒ generatÄƒ. CopiazÄƒ valoarea Ã®n ActivationWindow.";
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
            StatusText.Text = "GenereazÄƒ mai Ã®ntâi o licenÈ›Äƒ.";
            return;
        }

        Clipboard.SetText(LicenseTextBox.Text);
        StatusText.Text = "LicenÈ›Äƒ copiatÄƒ în clipboard.";
    }

    private void SaveLicense_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(LicenseTextBox.Text))
        {
            StatusText.Text = "GenereazÄƒ mai Ã®ntâi o licenÈ›Äƒ.";
            return;
        }

        var dialog = new SaveFileDialog { Filter = "License file (*.lic)|*.lic", FileName = "license.lic" };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, LicenseTextBox.Text);
            StatusText.Text = $"LicenÈ›a a fost salvatÄƒ: {Path.GetFileName(dialog.FileName)}";
        }
    }
}
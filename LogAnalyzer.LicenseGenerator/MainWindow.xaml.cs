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

    private void PasteHardwareId_Click(object sender, RoutedEventArgs e)
    {
        if (Clipboard.ContainsText())
        {
            HardwareIdTextBox.Text = Clipboard.GetText().Trim();
            StatusText.Text = "Hardware ID lipit din clipboard.";
        }
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        var hardwareId = HardwareIdTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(hardwareId))
        {
            StatusText.Text = "Introdu Hardware ID-ul primit de la client.";
            HardwareIdTextBox.Focus();
            return;
        }

        if (ExpiryDatePicker.SelectedDate is not DateTime expiry || expiry.Date <= DateTime.UtcNow.Date)
        {
            StatusText.Text = "Alege o data de expirare in viitor.";
            return;
        }

        var date = expiry.Date.ToString("yyyy-MM-dd");
        var key = _licenseService.GenerateKey(hardwareId, expiry.Date);
        LicenseTextBox.Text = $"{key}|{date}";
        StatusText.Text = "Licenta generata. Copiaza tot textul (cheie + data) si trimite-l clientului.";
    }

    private void CopyLicense_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(LicenseTextBox.Text))
        {
            StatusText.Text = "Genereaza mai intai o licenta.";
            return;
        }

        Clipboard.SetText(LicenseTextBox.Text);
        StatusText.Text = "Licenta copiata in clipboard.";
    }

    private void SaveLicense_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(LicenseTextBox.Text))
        {
            StatusText.Text = "Genereaza mai intai o licenta.";
            return;
        }

        var dialog = new SaveFileDialog { Filter = "License file (*.lic)|*.lic", FileName = "license.lic" };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, LicenseTextBox.Text);
            StatusText.Text = $"Licenta a fost salvata: {Path.GetFileName(dialog.FileName)}";
        }
    }
}

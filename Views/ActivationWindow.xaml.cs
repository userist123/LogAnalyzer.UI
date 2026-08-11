using System.Windows;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.UI.Views
{
    public partial class ActivationWindow : Window
    {
        private readonly LicenseService _licenseService;

        public ActivationWindow(LicenseService licenseService)
        {
            InitializeComponent();
            _licenseService = licenseService;

            TxtHardwareId.Text = _licenseService.GetHardwareId();
        }

        private void CopyHardwareId_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtHardwareId.Text);
            MessageBox.Show("ID-ul hardware a fost copiat în clipboard.", "Copiat", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Activate_Click(object sender, RoutedEventArgs e)
        {
            if (_licenseService.ValidateAndSaveKey(TxtLicenseKey.Text))
            {
                MessageBox.Show("Licența a fost activată cu succes! Aplicația va porni.", "Activare Reușită", MessageBoxButton.OK, MessageBoxImage.Information);
                this.DialogResult = true;
            }
            else
            {
                MessageBox.Show("Cheia de licență este invalidă pentru acest Hardware ID sau formatul este incorect. Introdu textul complet primit, în formatul CHEIE|DATĂ.", "Eroare Activare", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}

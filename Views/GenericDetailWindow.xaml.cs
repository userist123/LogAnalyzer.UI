using System;
using System.Windows;

namespace LogAnalyzer.UI.Views
{
    public partial class GenericDetailWindow : Window
    {
        private readonly object _item;
        private readonly Action<object> _escalateAction;

        public GenericDetailWindow(object item, Action<object> escalateAction)
        {
            InitializeComponent();
            _item = item;
            _escalateAction = escalateAction;
            
            // WPF va alege automat designul (EVTX sau Registry) pe baza tipului acestui obiect
            this.DataContext = _item;
        }

        private void Escalate_Click(object sender, RoutedEventArgs e)
        {
            _escalateAction?.Invoke(_item);
            MessageBox.Show("Artefact escaladat cu succes în Alerte!", "SOC", MessageBoxButton.OK, MessageBoxImage.Information);
            this.Close();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
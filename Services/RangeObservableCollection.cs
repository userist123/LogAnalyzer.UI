using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace LogAnalyzer.UI.Services;

/// <summary>
/// ObservableCollection care permite adăugarea în bloc a mai multor elemente
/// generând o singură notificare CollectionChanged (Reset), în loc de N notificări
/// individuale. Reduce drastic timpul de populare a grid-urilor WPF pentru
/// volume mari de evenimente (zeci de mii de rânduri din fișiere EVTX).
/// </summary>
public class RangeObservableCollection<T> : ObservableCollection<T>
{
    private bool _suppressNotification;

    public void AddRange(IEnumerable<T> items)
    {
        if (items == null) return;

        _suppressNotification = true;
        try
        {
            foreach (var item in items)
            {
                Items.Add(item);
            }
        }
        finally
        {
            _suppressNotification = false;
        }

        OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
    {
        if (!_suppressNotification)
            base.OnCollectionChanged(e);
    }
}

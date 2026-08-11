using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace LogAnalyzer.UI.Services;

/// <summary>
/// ObservableCollection care permite adăugarea în bloc a mai multor elemente
/// generând o singură notificare CollectionChanged de tip Add (incrementală),
/// în loc de N notificări individuale sau de un Reset costisitor. Permite
/// ICollectionView (cu Filter/Sort atașat) să insereze doar elementele noi,
/// fără să reevalueze întreaga colecție la fiecare lot, ceea ce elimină
/// saccadarea la volume mari de evenimente (zeci de mii de rânduri EVTX).
/// </summary>
public class RangeObservableCollection<T> : ObservableCollection<T>
{
    private bool _suppressNotification;

    public void AddRange(IEnumerable<T> items)
    {
        if (items == null) return;

        var newItems = items as IList<T> ?? new List<T>(items);
        if (newItems.Count == 0) return;

        int startIndex = Count;

        _suppressNotification = true;
        try
        {
            foreach (var item in newItems)
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

        var changedItems = newItems as IList ?? new List<T>(newItems);
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, changedItems, startIndex));
    }

    protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
    {
        if (!_suppressNotification)
            base.OnCollectionChanged(e);
    }
}

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace LogAnalyzer.UI.Services;

/// <summary>
/// ObservableCollection care permite adăugarea în bloc a mai multor elemente,
/// trimițând câte o notificare CollectionChanged de tip Add pentru fiecare element
/// în parte. WPF ICollectionView (cu Filter/Sort atașat) nu suportă o notificare
/// Add cu mai multe elemente deodată (aruncă "Range actions are not supported"),
/// dar suportă perfect adaugări incrementale element-cu-element fără să reevalueze
/// întreaga colecție, ceea ce elimină atât crash-ul cât și saccadarea la volume
/// mari de evenimente (zeci de mii de rânduri EVTX).
/// </summary>
public class RangeObservableCollection<T> : ObservableCollection<T>
{
    public void AddRange(IEnumerable<T> items)
    {
        if (items == null) return;

        var newItems = items as IList<T> ?? new List<T>(items);
        if (newItems.Count == 0) return;

        foreach (var item in newItems)
        {
            int index = Items.Count;
            Items.Add(item);
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, item, index));
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
    }
}

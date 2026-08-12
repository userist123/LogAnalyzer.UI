namespace LogAnalyzer.Core.Models
{
    public enum IocType { IPv4, IPv6, Hash, Domain, URL }

    public class IocItem
    {
        public IocType Type { get; set; }
        public string Value { get; set; } = string.Empty;
    }
}
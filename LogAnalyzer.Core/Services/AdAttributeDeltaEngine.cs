using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AdAttributeDeltaEngine
    {
        public List<AdAttributeDelta> ExtractDeltas(IEnumerable<ParsedEvent> events)
        {
            var deltas = new List<AdAttributeDelta>();
            if (events == null) return deltas;

            var list = events.ToList();

            // 1. Modificare Obiect Serviciu Director (EID 5136)
            var eid5136 = list.Where(e => e.EventId == 5136).ToList();
            foreach (var e in eid5136)
            {
                string msg = e.Message ?? string.Empty;
                string attrName = ExtractField(msg, "Attribute LDAP Display Name:") ?? ExtractField(msg, "AttributeName:") ?? "Attribute";
                string attrVal = ExtractField(msg, "Attribute Value:") ?? ExtractField(msg, "Value:") ?? "-";
                string op = ExtractField(msg, "Operation Type:") ?? "Value Added";
                string dn = ExtractField(msg, "Object DN:") ?? ExtractField(msg, "ObjectName:") ?? "CN=DirectoryObject,DC=domain,DC=local";
                string user = ExtractField(msg, "Account Name:") ?? "Admin";

                string impact = "Medium";
                if (attrName.Contains("servicePrincipalName", StringComparison.OrdinalIgnoreCase)) impact = "High (Kerberoasting Target)";
                if (attrName.Contains("userAccountControl", StringComparison.OrdinalIgnoreCase)) impact = "Critical (Account Delegation / PreAuth)";
                if (attrName.Contains("adminCount", StringComparison.OrdinalIgnoreCase)) impact = "Critical (AdminSDHolder)";
                if (attrName.Contains("msDS-AllowedToDelegateTo", StringComparison.OrdinalIgnoreCase)) impact = "Critical (Constrained Delegation)";

                deltas.Add(new AdAttributeDelta
                {
                    ObjectClass = dn.Contains("CN=Users") ? "User" : (dn.Contains("CN=Policies") ? "GPO" : "Container"),
                    ObjectDn = dn,
                    AttributeName = attrName,
                    OldValue = op.Contains("Delete", StringComparison.OrdinalIgnoreCase) ? attrVal : "-",
                    NewValue = op.Contains("Add", StringComparison.OrdinalIgnoreCase) ? attrVal : attrVal,
                    Operation = op,
                    ModifiedBy = user,
                    SecurityImpact = impact,
                    Timestamp = e.TimeCreated
                });
            }

            // 2. Modificare Cont Utilizator (EID 4738)
            var eid4738 = list.Where(e => e.EventId == 4738).ToList();
            foreach (var e in eid4738)
            {
                string msg = e.Message ?? string.Empty;
                string target = ExtractField(msg, "Target Account Name:") ?? "User";
                string caller = ExtractField(msg, "Subject: Account Name:") ?? ExtractField(msg, "Account Name:") ?? "Admin";

                if (msg.Contains("Don't Require Preauth", StringComparison.OrdinalIgnoreCase) || msg.Contains("DONT_REQ_PREAUTH", StringComparison.OrdinalIgnoreCase))
                {
                    deltas.Add(new AdAttributeDelta
                    {
                        ObjectClass = "User",
                        ObjectDn = $"CN={target},CN=Users,DC=domain,DC=local",
                        AttributeName = "userAccountControl: DONT_REQ_PREAUTH",
                        OldValue = "Disabled",
                        NewValue = "Enabled",
                        Operation = "Security Flag Added",
                        ModifiedBy = caller,
                        SecurityImpact = "Critical (AS-REP Roasting Vulnerability Introduced)",
                        Timestamp = e.TimeCreated
                    });
                }

                if (msg.Contains("Service Principal Names:", StringComparison.OrdinalIgnoreCase) && !msg.Contains("Service Principal Names: -", StringComparison.OrdinalIgnoreCase))
                {
                    deltas.Add(new AdAttributeDelta
                    {
                        ObjectClass = "User",
                        ObjectDn = $"CN={target},CN=Users,DC=domain,DC=local",
                        AttributeName = "servicePrincipalName",
                        OldValue = "-",
                        NewValue = "SPN Assigned",
                        Operation = "Value Added",
                        ModifiedBy = caller,
                        SecurityImpact = "High (Kerberoasting Target Created)",
                        Timestamp = e.TimeCreated
                    });
                }
            }

            return deltas;
        }

        private static string? ExtractField(string text, string fieldLabel)
        {
            if (string.IsNullOrEmpty(text)) return null;
            int idx = text.IndexOf(fieldLabel, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            int start = idx + fieldLabel.Length;
            int end = text.IndexOf('\n', start);
            if (end < 0) end = text.Length;

            var val = text.Substring(start, end - start).Trim();
            return string.IsNullOrEmpty(val) ? null : val;
        }
    }
}

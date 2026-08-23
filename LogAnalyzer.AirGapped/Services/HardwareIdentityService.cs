using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.UI.Services;

public sealed class HardwareIdentityService
{
    public string GetHardwareId()
    {
        // Obținem adresele MAC ale plăcilor fizice (chiar dacă sunt deconectate / cablu scos în mod Air-Gapped)
        var macs = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback && 
                        n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(n => n.GetPhysicalAddress().ToString())
            .Where(x => !string.IsNullOrWhiteSpace(x) && x != "000000000000")
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        var material = string.Join("|", 
            Environment.MachineName, 
            Environment.ProcessorCount.ToString(), 
            Environment.OSVersion.Platform.ToString(), 
            string.Join(",", macs));

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }
}

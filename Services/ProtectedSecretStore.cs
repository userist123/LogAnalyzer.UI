using System;
using System.IO;
using System.Security.Cryptography;

namespace LogAnalyzer.UI.Services;

public sealed class ProtectedSecretStore
{
    public void Protect(string path, ReadOnlySpan<byte> secret, bool machineScope = false)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A secret path is required.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var scope = machineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;
        var protectedBytes = ProtectedData.Protect(secret.ToArray(), null, scope);
        var temporaryPath = fullPath + ".tmp";
        File.WriteAllBytes(temporaryPath, protectedBytes);
        File.Move(temporaryPath, fullPath, true);
    }

    public byte[] Unprotect(string path, bool machineScope = false)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A secret path is required.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("Protected secret not found.", fullPath);
        var scope = machineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;
        return ProtectedData.Unprotect(File.ReadAllBytes(fullPath), null, scope);
    }
}

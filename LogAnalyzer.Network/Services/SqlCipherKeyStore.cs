using System;
using System.IO;
using System.Security.Cryptography;

namespace LogAnalyzer.UI.Services;

public sealed class SqlCipherKeyStore
{
    private readonly ProtectedSecretStore _protectedSecrets;
    private readonly string _keyPath;

    public SqlCipherKeyStore(ProtectedSecretStore protectedSecrets, string keyPath)
    {
        _protectedSecrets = protectedSecrets;
        _keyPath = keyPath;
    }

    public byte[] GetOrCreateKey()
    {
        if (File.Exists(_keyPath)) return _protectedSecrets.Unprotect(_keyPath);
        var key = RandomNumberGenerator.GetBytes(32);
        _protectedSecrets.Protect(_keyPath, key);
        CryptographicOperations.ZeroMemory(key);
        return _protectedSecrets.Unprotect(_keyPath);
    }
}

using System;
using System.IO;
using System.Security.Cryptography;

namespace LogAnalyzer.UI.Services;

public sealed class SecurePathService
{
    public string ComputeSha256(string filePath)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException("Evidence file not found.", filePath);
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    public bool IsSafeRegularFile(string filePath)
    {
        try
        {
            var fullPath = Path.GetFullPath(filePath);
            var info = new FileInfo(fullPath);
            return info.Exists && !info.Attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch
        {
            return false;
        }
    }
}

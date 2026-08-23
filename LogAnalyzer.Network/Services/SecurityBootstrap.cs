using System;

namespace LogAnalyzer.UI.Services;

public sealed class SecurityBootstrap
{
    public HardwareIdentityService HardwareIdentity { get; }
    public SecurePathService SecurePaths { get; }
    public ChainOfCustodyService ChainOfCustody { get; }

    public SecurityBootstrap(string custodyLogPath)
    {
        HardwareIdentity = new HardwareIdentityService();
        SecurePaths = new SecurePathService();
        ChainOfCustody = new ChainOfCustodyService(custodyLogPath);
    }
}

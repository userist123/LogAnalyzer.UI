using System.Collections.Generic;

namespace LogAnalyzer.Core.Services;

public sealed class PluginManagerService
{
    private readonly List<string> _loadedPlugins = new();

    public IReadOnlyList<string> LoadedPlugins => _loadedPlugins;

    public void RegisterPlugin(string pluginName) => _loadedPlugins.Add(pluginName);
}

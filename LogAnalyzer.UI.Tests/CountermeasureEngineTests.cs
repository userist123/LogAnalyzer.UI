using System;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services.Network;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class CountermeasureEngineTests
    {
        [Fact]
        public void GeneratePlaybook_CreatesPhishingCountermeasures()
        {
            var engine = new CyberAttackCountermeasureEngine();
            var alert = new DetectedIssue
            {
                Title = "🎣 ALERTĂ CRITICĂ: Tentativă de Phishing / Descărcare Payload Malițios",
                Severity = "Critical",
                MitreTechniqueId = "T1566.001",
                Explanation = "Tentativa de phishing detectata prin descarcare certutil."
            };

            var playbook = engine.GeneratePlaybook(alert, "SRV-TEST");

            Assert.NotNull(playbook);
            Assert.Contains("Phishing", playbook.AttackCategory);
            Assert.NotEmpty(playbook.Actions);
            Assert.Contains(playbook.Actions, a => a.ActionType == "BlockIoC");
            Assert.Contains(playbook.Actions, a => a.ActionType == "KillProcess");
        }

        [Fact]
        public void GeneratePlaybook_CreatesRansomwareIsolationCountermeasures()
        {
            var engine = new CyberAttackCountermeasureEngine();
            var alert = new DetectedIssue
            {
                Title = "🚨 ALERTĂ CRITICĂ: Tentativă Distrugere Shadow Copies (Ransomware)",
                Severity = "Critical",
                MitreTechniqueId = "T1490"
            };

            var playbook = engine.GeneratePlaybook(alert, "WS-FINANCE");

            Assert.NotNull(playbook);
            Assert.Contains("Ransomware", playbook.AttackCategory);
            Assert.Contains(playbook.Actions, a => a.ActionType == "Isolate");
        }
    }
}

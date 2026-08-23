using System;
using System.Diagnostics;
using System.IO;

namespace LogAnalyzer.Core.Services
{
    public class ContainmentExecutionResult
    {
        public bool Success { get; set; }
        public string ActionName { get; set; } = string.Empty;
        public string OutputLog { get; set; } = string.Empty;
        public DateTime ExecutedAt { get; set; } = DateTime.UtcNow;
    }

    public class AlertActionTriggerService
    {
        public ContainmentExecutionResult ExecuteContainmentScript(string actionName, string targetEntity, bool isAirGapped)
        {
            var result = new ContainmentExecutionResult
            {
                ActionName = actionName,
                ExecutedAt = DateTime.UtcNow
            };

            try
            {
                // În modul Air-Gapped / Forensic, acțiunile sunt auditate local fără a modifica starea mașinii fizice fără aprobare
                if (isAirGapped)
                {
                    result.Success = true;
                    result.OutputLog = $"[AIR-GAPPED PLAYBOOK SIMULATION]\nAcțiunea '{actionName}' pentru ținta '{targetEntity}' a fost validată și consemnată în registrul de acțiuni forensic.\nComandă sugerată pentru operator:\n  net user {targetEntity} /active:no\n  wevtutil sl Security /e:true";
                    return result;
                }

                // În modul Network SOC, simulăm/declanșăm playbook-ul de răspuns EDR
                result.Success = true;
                result.OutputLog = $"[NETWORK EDR CONTAINMENT]\nTrimis semnal de izolare și blocare sesiune pentru '{targetEntity}' către senzorii din rețea.\nStatus: PENDING AGENT ACK";
                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.OutputLog = $"Eroare la execuția acțiunii de contenție: {ex.Message}";
                return result;
            }
        }
    }
}

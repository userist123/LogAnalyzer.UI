using System;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public enum Nis2Stage
    {
        EarlyWarning_24h,   // Avertizare Timpurie (24 ore)
        Notification_72h,   // Notificare Incident (72 ore)
        FinalReport_1Month  // Raport Final (1 Lună)
    }

    public class Nis2NotificationService
    {
        public string GenerateDnscDraft(
            Nis2Stage stage,
            string organizationName,
            string cuiOrFiscalCode,
            string incidentTitle,
            string affectedSystems,
            DateTime incidentDiscoveredUtc,
            AttackStoryline? storyline,
            int totalEvents,
            int totalAlerts)
        {
            var sb = new StringBuilder();
            var now = DateTime.UtcNow;

            sb.AppendLine("================================================================================");
            sb.AppendLine("NOTIFICARE FORMALĂ INCIDENT CIBERNETIC SEMNIFICATIV — DIRECTIVA NIS2 / OUG 155/2024");
            sb.AppendLine("Către: Directoratul Național de Securitate Cibernetică (DNSC) — contact@dnsc.ro");
            sb.AppendLine("================================================================================");
            sb.AppendLine();

            string stageName = stage switch
            {
                Nis2Stage.EarlyWarning_24h => "ETAPA 1: AVERTIZARE TIMPURIE (Termen legal: 24 ore de la detectare)",
                Nis2Stage.Notification_72h => "ETAPA 2: NOTIFICARE DE INCIDENT (Termen legal: 72 ore de la detectare)",
                Nis2Stage.FinalReport_1Month => "ETAPA 3: RAPORT FINAL DE EVALUARE ȘI REMEDIERE (Termen legal: 1 lună)",
                _ => "NOTIFICARE INCIDENT"
            };

            sb.AppendLine($"TIP DOCUMENT: {stageName}");
            sb.AppendLine($"DATA RAPORTĂRII: {now:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"MOMENT DETECTARE INCIDENT: {incidentDiscoveredUtc:yyyy-MM-dd HH:mm:ss} UTC");
            
            var elapsed = now - incidentDiscoveredUtc;
            sb.AppendLine($"TIMP SCURS DE LA DETECTARE: {elapsed.TotalHours:N1} ore");
            sb.AppendLine();

            sb.AppendLine("--- 1. DATE DE IDENTIFICARE ALE ENTITĂȚII ESENȚIALE / IMPORTANTE ---");
            sb.AppendLine($"Denumire Organizație: {organizationName}");
            sb.AppendLine($"Cod Unic de Înregistrare (CUI): {cuiOrFiscalCode}");
            sb.AppendLine($"Sector de Activitate (Anexa I/II NIS2): Infrastructură Critică / Servicii Esențiale");
            sb.AppendLine();

            sb.AppendLine("--- 2. DESCRIEREA SUMARĂ A INCIDENTULUI ---");
            sb.AppendLine($"Titlu Incident: {incidentTitle}");
            sb.AppendLine($"Echipamente / Stații Afectate: {affectedSystems}");
            sb.AppendLine($"Nivel de Severitate Evaluat: {(storyline != null ? storyline.RiskLevel : "RIDICAT")}");
            sb.AppendLine($"Volum Date Forenzice Auditate: {totalEvents} evenimente, {totalAlerts} alerte corelate.");
            sb.AppendLine();

            if (storyline != null && storyline.Nodes.Count > 0)
            {
                sb.AppendLine("--- 3. CRONOLOGIA VECTURILOR DE ATAC IDENTIFICAȚI (KILL CHAIN) ---");
                foreach (var node in storyline.Nodes)
                {
                    sb.AppendLine($"• [{node.Timestamp:yyyy-MM-dd HH:mm:ss} UTC] {node.StageName} — {node.Title} (Tehnică MITRE: {node.TechniqueId})");
                }
                sb.AppendLine();
            }

            sb.AppendLine("--- 4. MĂSURI DE URGENȚĂ ȘI MITIGARE APLICATE ---");
            sb.AppendLine("1. Izolarea logică a stațiilor compromise de la rețeaua locală și VPN.");
            sb.AppendLine("2. Extragerea și conservarea imaginilor probatorii (EVTX, Registry, Prefetch, $MFT) cu calcul SHA-256.");
            sb.AppendLine("3. Revocarea conturilor și a tichetelor Kerberos pentru utilizatorii vizați.");
            sb.AppendLine("4. Blocarea indicatorilor de compromitere (IOC) în firewall și gateway-ul de securitate.");
            sb.AppendLine();

            sb.AppendLine("--- 5. CONCLUZII PRELIMINARE ȘI PAȘI URMĂTORI ---");
            if (stage == Nis2Stage.EarlyWarning_24h)
            {
                sb.AppendLine("Această avertizare timpurie va fi urmată în termen de 72 de ore de o notificare completă de incident cu analiza cauzei rădăcină.");
            }
            else if (stage == Nis2Stage.Notification_72h)
            {
                sb.AppendLine("Se continuă analiza forenzică detaliată. Raportul final complet va fi transmis în termen de 30 de zile.");
            }
            else
            {
                sb.AppendLine("Incidentul a fost complet izolat, iar remedierea a fost finalizată conform procedurilor standard de răspuns la incidente.");
            }

            sb.AppendLine();
            sb.AppendLine("Generat automat prin LogAnalyzer DFIR Enterprise — Modul de Conformitate NIS2 / DNSC.");
            return sb.ToString();
        }
    }
}

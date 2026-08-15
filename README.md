# LogAnalyzer.UI

Aplicație desktop WPF (.NET 10) pentru analiza jurnalelor de evenimente Windows și triere DFIR: import EVTX/CSV, parsere de artefacte, motoare Sigma/YARA, detecție de anomalii, rapoarte HTML/PDF și export STIX 2.1/MISP — cu stocare criptată și lanț de custodie pentru probe.

## Funcționalități principale

- **Deep Triage** — import și normalizare EVTX, CSV de triere, artefacte Prefetch / LNK / Shimcache / Registry
- **Motoare de detecție** — Sigma Rule Engine, YARA Rule Engine, detecție de anomalii cu entropie Shannon
- **Analiză euristică** — scor de risc interactiv, playbook-uri de răspuns la incidente (IR)
- **Raportare** — HTML și PDF (QuestPDF), export STIX 2.1 / MISP pentru IOC-uri
- **Criminalistică** — intake de probe cu hash SHA-256, chain of custody append-only cu hash-chain verificabil
- **Securitate** — bază de date criptată SQLCipher, secrete protejate cu Windows DPAPI
- **Licențiere offline** — chei legate de Hardware ID, fără conexiune la internet

## Cerințe

### Rulare (artefact MVP)

- Windows 10/11 x64
- Nu necesită .NET instalat (pachet self-contained)

### Dezvoltare

- Windows 10/11 x64
- .NET SDK 10.x
- Visual Studio 2022+ sau VS Code

## Build și testare

```powershell
dotnet restore
dotnet build --configuration Release
dotnet test LogAnalyzer.UI.Tests/LogAnalyzer.UI.Tests.csproj --configuration Release
```

## Publicare (export MVP)

```powershell
dotnet publish LogAnalyzer.UI.csproj -c Release -p:PublishProfile=win-x64-singlefile
```

Artefactul rezultat: `publish\win-x64\` — executabil single-file self-contained.
Pipeline-ul CI produce automat același artefact (`LogAnalyzer-MVP-win-x64`) la fiecare push pe `main` și la PR-uri.

## Activare licență

1. La prima rulare, aplicația afișează fereastra de activare cu Hardware ID-ul stației (16 caractere hex).
2. Pe stația de administrare, generezi licența:

```powershell
.\Generate-LicenseKey.ps1 -HardwareId "A1B2C3D4E5F67890" -ExpiryDate "2030-12-31"
```

Fără parametri, scriptul folosește Hardware ID-ul mașinii locale și expirare implicită la 1 an.

3. Introdu în aplicație (sau în fișierul `license.lic`) stringul returnat, de forma `CHEIE|YYYY-MM-DD`.

> Notă MVP: mecanismul actual de generare este bazat pe hash cu salt partajat, nu pe semnătură asimetrică — vezi `Documentation/MVP-DECISIONS.md` (decizia 9) pentru limitare și planul de upgrade post-MVP.

## Structura proiectului

| Cale | Rol |
|---|---|
| `Views/`, `ViewModels/`, `Services/`, `LogAnalyzer.UI.csproj` | Aplicația WPF (UI, MVVM, servicii de aplicație) |
| `LogAnalyzer.Core/` | Modele, interfețe, servicii de domeniu |
| `LogAnalyzer.Infrastructure/` | Parsere artefacte, motoare de detecție, acces la date |
| `LogAnalyzer.UI.Tests/` | Teste unitare și de integrare |
| `Categories/` | Knowledge base de evenimente Windows pe categorii (JSON) |
| `Documentation/` | Status faze, decizii MVP, checklist de release |

## Securitate și limitări

- Controalele de integritate și trasabilitate sunt la nivel de aplicație; nu constituie certificare ORNISS / ISO/IEC 27037 / Common Criteria — vezi `Documentation/PHASE1-STATUS.md`.
- Raportarea vulnerabilităților: `SECURITY.md`.

## Status

Versiune curentă: **1.0.0-MVP**. Înainte de orice distribuție: `Documentation/RELEASE-CHECKLIST.md`.

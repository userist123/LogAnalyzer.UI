# Decizii MVP — LogAnalyzer.UI v1.0.0

Data: 2026-08-15. Scop: export MVP distribuibil, fără regresii de securitate și fără refactor riscant.

| # | Decizie | Alternativă respinsă | Motiv | Reevaluare |
|---|---------|----------------------|-------|------------|
| 1 | Self-contained single-file win-x64 | Framework-dependent | Stațiile țintă pot fi fără .NET runtime și fără internet | Post-MVP: installer MSIX |
| 2 | `PublishTrimmed=false` | Trimming | WPF + reflection/DI riscă erori la runtime | Doar cu teste e2e extinse |
| 3 | Fără Native AOT | Native AOT | WPF nu este suportat de Native AOT | De urmărit roadmap-ul .NET |
| 4 | Release manual din artefactul CI | Release automat pe tag | Validăm întâi artefactul pe mașină curată | După 2–3 release-uri reușite |
| 5 | Fără semnare Authenticode în MVP | Certificat self-signed | Nu adaugă încredere reală; SmartScreen blochează oricum | Certificat OV/EV la distribuție |
| 6 | Verificare knowledge base în CI ca warning | Blocare build | Nu întrerupem pipeline-ul pentru o verificare nouă, neconfirmată încă | Promovare la eroare după prima rulare |
| 7 | Fără `.sln` în acest val | `.sln` generat manual | CLI-ul acoperă build/test/publish; `.sln` se generează corect din Visual Studio | La prima sesiune în Visual Studio |
| 8 | Duplicări servicii UI/Core doar documentate | Refactor acum | Risc de regresie chiar înainte de MVP | Prima iterație post-MVP |
| 9 | Licențiere cu hash + salt în MVP | Rescriere RSA-PSS acum | Generatorul existent este operațional; trecerea la semnătură asimetrică cere refactor sincron în generator și validare | Critic imediat post-MVP, înainte de distribuție comercială |

## Cunoscute, amânate conștient

- **Derivă documentație vs. implementare:** `PHASE1-STATUS.md` menționează licențe semnate RSA-PSS, dar `Generate-LicenseKey.ps1` produce chei hash SHA-256 cu salt partajat. De verificat ce validează efectiv `LicenseService` și de aliniat generatorul cu validarea (vezi decizia 9).
- `MainWindow.xaml` (~131 KB) și `MainViewModel.cs` (~72 KB) — god objects; de spart pe UserControl-uri și ViewModel-uri per tab post-MVP.
- Branch-uri vechi neșterse (`faza1-*`, `feature/*`, `hotfix/*`) — curățare după merge-ul acestui PR.
- Versionarea centralizată în `Directory.Build.props` — de confirmat conținutul actual înainte de modificare.

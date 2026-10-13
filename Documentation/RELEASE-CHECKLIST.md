# Checklist export MVP — LogAnalyzer.UI

De parcurs în ordine înainte de orice distribuție externă.

## 1. Build și teste

- [ ] `dotnet build -c Release` — zero erori, zero warning-uri noi
- [ ] `dotnet test LogAnalyzer.UI.Tests/LogAnalyzer.UI.Tests.csproj -c Release` — toate testele verzi
- [ ] CI verde pe PR-ul de release (job-urile `build-test` și `package-mvp`)

## 2. Artefact

- [ ] Publish cu profilul `win-x64-singlefile` reușește local și în CI
- [ ] Executabilul pornește pe o mașină Windows curată, fără .NET instalat
- [ ] Knowledge base-ul (`Categories/*.json` și datele de evenimente) este prezent în output și se încarcă în UI
- [ ] Dimensiunea artefactului este rezonabilă pentru self-contained (~80–150 MB)

## 3. Fluxuri funcționale (smoke test pe mașină curată)

- [ ] Activare licență offline: cheia generată cu `Generate-LicenseKey.ps1` este acceptată
- [ ] Coerență generator ↔ validare: formatul `CHEIE|YYYY-MM-DD` trece validarea din aplicație
- [ ] Import EVTX și CSV de triere; timeline-ul se populează
- [ ] Motoarele Sigma/YARA rulează pe setul importat
- [ ] Raport HTML și raport PDF generate corect
- [ ] Export STIX 2.1 / MISP validează
- [ ] Chain of custody: verificarea hash-chain trece după import

## 4. Securitate

- [ ] Scanare secrete pe diff-ul de release — curată (GHAS nu este activ pe repo; rulează local `gitleaks detect`)
- [ ] Baza SQLCipher nu poate fi deschisă fără cheie
- [ ] Niciun secret/parolă hardcodată în fișierele noi

## 5. Release

- [ ] Versiune `1.0.0-mvp` confirmată în artefact
- [ ] PR de release revizuit și făcut merge în `main`
- [ ] Tag `v1.0.0-mvp` pe `main`
- [ ] GitHub Release creat manual, cu artefactul din CI atașat și note de release
- [ ] (Post-MVP) Semnare Authenticode a executabilului

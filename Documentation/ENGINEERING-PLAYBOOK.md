# Engineering Playbook — lecții din LogAnalyzer.UI

Decizii și pattern-uri reutilizabile extrase din construcția acestui proiect. Fiecare regulă are motiv și consecință. Documentul se actualizează la fiecare decizie tehnică importantă.

## Desktop .NET / WPF

1. **WPF nu este compatibil cu Native AOT și nici cu trimming agresiv.** Reflection, încărcarea XAML și DI dinamic se rup la runtime. Pentru export: self-contained + single-file cu `PublishTrimmed=false`.
2. **SQLCipher / SQLitePCLRaw în single-file:** `IncludeNativeLibrariesForSelfExtract=true`, altfel bibliotecile native lipsesc din bundle și aplicația crape la prima deschidere a bazei.
3. **Self-contained pentru stații țintă controlate** (medii fără internet / fără runtime instalat): elimină dependența de .NET-ul din sistem.
4. **Fișierele de date (JSON/CSV knowledge base) se verifică explicit în output-ul de publish** — SDK-ul nu le copiază decât dacă sunt marcate corespunzător. Pas dedicat de verificare în CI.

## Arhitectură

5. **Un singur proiect la root cu subproiecte ca foldere copii cere excluderi `Compile Remove`.** Pe viitor: layout `src/<Proiect>/` — elimină o clasă întreagă de coliziuni la build.
6. **Nu duplica servicii între layere** (ex. `Services/` în UI vs. `Core/Services/`). O singură sursă de adevăr; UI-ul referă Core prin ProjectReference, nu prin copiere.
7. **God objects:** `MainWindow.xaml` (~131 KB) și `MainViewModel` (~72 KB) sunt acceptabile pentru MVP, dar se sparg pe UserControl-uri + ViewModel-uri per tab la prima iterație post-MVP.

## Securitate aplicată

8. **Licențiere offline:** ținta este semnătură asimetrică (RSA-PSS cu cheie publică embedded, cheia privată offline). Hash-ul cu salt partajat — varianta MVP — oprește doar copierea casuală; de tratat ca placeholder, nu protecție reală.
9. **DPAPI pentru secrete per-utilizator pe Windows; SQLCipher pentru date la rest.** Cheia bazei se protejează prin DPAPI, nu se hardcodează.
10. **Chain of custody pentru probe:** jurnal append-only cu hash-chain SHA-256 și verificare integrală la fiecare deschidere.
11. **Controalele de aplicație nu înlocuiesc certificarea** (ORNISS, ISO/IEC 27037, Common Criteria) — limita se documentează explicit, nu se lasă la interpretare.

## CI/CD și release

12. **Build fără teste nu este gate.** Pipeline minim: restore → build → test → publish → artifact.
13. **`actions/upload-artifact@v4`** pentru artefacte, cu retenție explicită (30 zile pentru MVP).
14. **Release-urile se fac manual la început** (tag + note + artefact din CI); automatizarea pe tag-uri vine după validarea artefactului pe mașini curate.
15. **Fără push direct pe `main` pentru release:** branch `release/*` → PR → review (inclusiv automat) → merge.

## Proces și tooling

16. **Repo privat prin API:** dacă citirea directă a fișierelor nu returnează conținut, patch-urile commit-urilor (`full_patch`) oferă conținutul fișierelor-cheie.
17. **Scanare de secrete pe orice conținut generat, înainte de push** (GHAS nu este activ pe repo privat — alternativă locală: `gitleaks`).
18. **Documentația și codul derivă.** PHASE1-STATUS declara licențe RSA-PSS; generatorul real produce hash cu salt. Orice afirmație din documentație se verifică în cod înainte de release.

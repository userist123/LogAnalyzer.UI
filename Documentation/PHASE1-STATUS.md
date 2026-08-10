# Faza 1 — Secure Foundation

## Implementat până acum

- Hardware identity deterministă bazată pe identificatori disponibili fără WMI (`HardwareIdentityService`).
- Validarea offline a unei licențe semnate RSA-PSS cu cheie publică (`LicenseService`).
- Calcul SHA-256 pentru fișiere de probă (`SecurePathService`).
- Jurnal de custodie append-only cu hash-chain și verificare integrală (`ChainOfCustodyService`).
- Verificare de bază pentru fișiere reparse-point înainte de import.
- Flux de import probă cu SHA-256 și hash-ul auditului (`EvidenceIntakeService`).
- Bootstrap local pentru compunerea serviciilor de securitate (`SecurityBootstrap`), integrat în `App.xaml.cs` prin Dependency Injection.
- Protecție locală a secretelor cu Windows DPAPI (`ProtectedSecretStore`).
- Persistența materialului de licență criptat local (`LicenseKeyStore`).
- Workflow GitHub Actions pentru build și teste .NET.
- Fundație SQLCipher pentru baza de date IOC, cu cheie AES-256 generată aleator și protejată prin DPAPI.
- Operații IOC parametrizate prin ADO.NET, fără EF Core și fără date sensibile în repository.

## Important

SQLCipher este pregătit ca strat de infrastructură, dar nu este încă conectat la DI/UI și nu trebuie considerat validat până când workflow-ul CI nu confirmă restore/build/test pe repository.

Aceste controale nu reprezintă singure certificare ORNISS, ISO/IEC 27037, Common Criteria sau un mecanism juridic automat de inalterabilitate.

## Următorii pași

1. Verificarea compatibilității pachetelor SQLCipher cu target-ul proiectului și runner-ul CI.
2. Teste de integrare pentru deschiderea bazei criptate, schema IOC și query-uri parametrizate.
3. Integrarea serviciului în DI și în fluxul de analiză.
4. Profil de publicare și test separat pentru Native AOT.
5. Semnare Authenticode și verificarea artefactelor de release.

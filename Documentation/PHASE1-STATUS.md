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
- Teste de integrare pentru creare, redeschidere, inserare, căutare și respingerea unei chei SQLCipher greșite.
- Dependențe declarate explicit pentru `Microsoft.Data.Sqlite.Core`, `SQLitePCLRaw.bundle_e_sqlcipher` și `System.Security.Cryptography.ProtectedData`.

## Important

Rezultatul testelor CI este autoritatea pentru compatibilitatea efectivă a pachetelor cu target-ul proiectului. Testele de integrare nu reprezintă certificare ORNISS, ISO/IEC 27037, Common Criteria sau un mecanism juridic automat de inalterabilitate.

## Următorii pași

1. Verificarea restore/build/test în CI.
2. Integrarea operațiilor de adăugare, actualizare și ștergere IOC cu audit obligatoriu.
3. Integrarea filtrării IOC în ViewModel și UI.
4. Profil de publicare și test separat pentru Native AOT.
5. Semnare Authenticode și verificarea artefactelor de release.

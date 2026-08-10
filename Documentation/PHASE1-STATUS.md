# Faza 1 — Secure Foundation

## Implementat până acum

- Hardware identity deterministă bazată pe identificatori disponibili fără WMI (`HardwareIdentityService`).
- Validarea offline a unei licențe semnate RSA-PSS cu cheie publică (`LicenseService`).
- Calcul SHA-256 pentru fișiere de probă (`SecurePathService`).
- Jurnal de custodie append-only cu hash-chain și verificare integrală (`ChainOfCustodyService`).
- Verificare de bază pentru fișiere reparse-point înainte de import.
- Flux de import probă care produce un receipt cu SHA-256 și hash-ul auditului (`EvidenceIntakeService`).
- Bootstrap local pentru compunerea serviciilor de securitate (`SecurityBootstrap`), integrat în `App.xaml.cs` prin Dependency Injection.
- Protecție locală a secretelor cu Windows DPAPI (`ProtectedSecretStore`).
- Persistența materialului de licență criptat local, fără stocare în clar (`LicenseKeyStore`).
- Workflow GitHub Actions pentru validarea automată a build-ului .NET.

## Important

Aceste controale oferă integritate și trasabilitate la nivel de aplicație; nu reprezintă singure certificare ORNISS, ISO/IEC 27037, Common Criteria sau un mecanism juridic automat de inalterabilitate.

## Următorii pași

1. Teste unitare pentru `ChainOfCustodyService`, `LicenseService` și `ProtectedSecretStore`.
2. Alegerea și integrarea explicită a providerului SQLCipher pentru baza de date IOC.
3. Profil de publicare și test separat pentru Native AOT; WPF și dependințele dinamice trebuie validate înainte de activare.
4. Semnare Authenticode și verificarea artefactelor de release.
5. Evaluarea unei soluții comerciale de ofuscare, după ce Native AOT este validat.

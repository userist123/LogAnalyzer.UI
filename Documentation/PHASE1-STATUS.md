# Faza 1 — Secure Foundation

## Implementat în acest commit

- Hardware identity deterministă bazată pe identificatori disponibili fără WMI.
- Validarea offline a unei licențe semnate RSA-PSS cu cheie publică.
- Calcul SHA-256 pentru fișiere de probă.
- Jurnal de custodie append-only cu hash-chain și verificare integrală.
- Verificare de bază pentru fișiere reparse-point înainte de import.

## Important

Aceste controale oferă integritate și trasabilitate la nivel de aplicație; nu reprezintă singure certificare ORNISS, ISO/IEC 27037, Common Criteria sau un mecanism juridic automat de inalterabilitate.

## Următorii pași

1. Teste unitare și build CI pentru branch.
2. Integrarea serviciilor în DI și App.xaml.cs.
3. Protejarea materialului secret prin Windows DPAPI/CNG.
4. Alegerea și integrarea explicită a providerului SQLCipher.
5. Profil de publicare și test separat pentru Native AOT; WPF și dependințele dinamice trebuie validate înainte de activare.
6. Semnare Authenticode și verificarea artefactelor de release.

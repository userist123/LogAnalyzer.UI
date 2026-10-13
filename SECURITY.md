# Politica de securitate

## Raportarea vulnerabilităților

Nu deschide issue-uri publice pentru vulnerabilități. Contactează direct maintainerul repository-ului și include: versiunea afectată, pași de reproducere și impactul estimat.

## Modelul de securitate al aplicației

- **Date la rest:** bază de date criptată SQLCipher; materialul secret protejat cu Windows DPAPI (per utilizator Windows).
- **Integritatea probelor:** hash SHA-256 la intake; jurnal chain-of-custody append-only cu hash-chain verificabil.
- **Licențiere offline:** chei legate de Hardware ID-ul stației. În versiunea MVP mecanismul oprește doar copierea casuală; upgrade la semnătură asimetrică este planificat post-MVP (`Documentation/MVP-DECISIONS.md`, decizia 9).
- **CI/CD:** artefacte cu retenție limitată (30 zile); scanare de secrete locală înainte de release (`gitleaks`).

## Limitări cunoscute

Conform `Documentation/PHASE1-STATUS.md`, controalele oferă integritate și trasabilitate la nivel de aplicație și nu reprezintă certificare ORNISS, ISO/IEC 27037, Common Criteria sau un mecanism juridic automat de inalterabilitate.

- Executabilul MVP nu este semnat Authenticode — SmartScreen poate afișa avertisment la prima rulare.
- DPAPI leagă secretele de contul de utilizator Windows curent; migrarea între conturi sau stații necesită reactivare.

## Versiuni suportate

| Versiune | Suport |
|----------|--------|
| 1.0.0-mvp | MVP — remedieri pe baza efortului rezonabil |

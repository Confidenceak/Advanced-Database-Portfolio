# Data Sources

Real, public datasets used in this portfolio. Downloaded on **11 November 2026**.

## 1. CISA Known Exploited Vulnerabilities (KEV) catalog
- **File:** `kev/known_exploited_vulnerabilities.csv` (unchanged from source)
- **Publisher:** U.S. Cybersecurity and Infrastructure Security Agency (CISA)
- **Source:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  (GitHub mirror: https://github.com/cisagov/kev-data)
- **Contents:** 1,779 CVEs confirmed as exploited in the wild, 294 vendors, added between 2021-11-03 and 2026-11-10; 361 marked as used in ransomware campaigns.
- **Columns:** `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes, cwes`
- **Used in:** `vulnerability`, `vulnerability_cwe` (Portfolio 1)

## 2. MITRE ATT&CK Enterprise
- **Files:** `mitre/mitre_tactics.csv`, `mitre/mitre_techniques.csv`, `mitre/mitre_technique_tactics.csv`
- **Publisher:** The MITRE Corporation — ATT&CK Enterprise **version 20.1**
- **Source:** STIX 2.1 bundle `enterprise-attack.json` from
  https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack
- **How the CSVs were made:** `scripts/prepare_mitre.py` reads the STIX bundle, removes revoked and deprecated objects, and writes the three CSV files:
  ```
  python scripts/prepare_mitre.py enterprise-attack.json mitre
  ```
  The original JSON (≈55 MB) is not committed because it exceeds GitHub's browser upload limit; download it from the link above to reproduce the CSVs.
- **Contents:** 15 tactics, 227 techniques, 479 sub-techniques, 881 technique–tactic links.
- **Used in:** `mitre_tactic`, `mitre_technique`, `technique_tactic` (Portfolio 1)
- *MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. Data © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation.*

## 3. NIST National Vulnerability Database (NVD)
- CVSS v3.x base scores for the 7 CVEs found on client assets, entered in `portfolio-1-database-design/sample_data.sql`.
- **Source:** https://nvd.nist.gov

## 4. Loghub — OpenSSH server log *(Portfolio 2)*
- 655,146 real log lines from an OpenSSH server over 28 days.
- **Source:** https://github.com/logpai/loghub
- **Citation:** Zhu, J., He, S., He, P., Liu, J. and Lyu, M.R. (2023) 'Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics', *IEEE ISSRE 2023*, pp. 355–366. doi:10.1109/ISSRE59848.2023.00071

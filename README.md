# Advanced Database Systems Portfolio

**Course:** MIT 8103 Advanced Database Systems, Miva Open University
**Student:** Ekeh Confidence Ifeoma — 2026/A/MIT/0507
**Session:** 2026/2027, First Semester (September 2026 cohort)

## Case Study
**CyberAce Tech Security Ltd** — a simulated global Managed Security Service Provider headquartered in Lagos, Nigeria.
The portfolio builds the database behind its 24/7 Security Operations Centre (SOC): security events, alerts,
incidents, vulnerabilities and remediation tasks for clients across Africa, Europe and the Middle East.

The operational data (clients, assets, incidents) is simulated. The threat-intelligence reference data is **real**:
the CISA Known Exploited Vulnerabilities catalog and MITRE ATT&CK Enterprise, plus CVSS scores from NIST NVD.
See [`data/README.md`](data/README.md).

## Portfolio Contents
| # | Activity | Folder | Status |
|---|---|---|---|
| 1 | Database Design and Modelling | [portfolio-1-database-design](portfolio-1-database-design/) | Complete |
| 2 | Query Processing and Optimisation | [portfolio-2-query-optimisation](portfolio-2-query-optimisation/) | Complete |
| 3 | Transactions and Concurrency | [portfolio-3-transactions-concurrency](portfolio-3-transactions-concurrency/) | Complete |
| 4 | NoSQL and Advanced Data Models | [portfolio-4-nosql](portfolio-4-nosql/) | Complete |
| 5 | Distributed and Cloud Database | [portfolio-5-distributed-cloud](portfolio-5-distributed-cloud/) | Complete |

## Repository Structure
```
Advanced-Database-Portfolio/
├── README.md                        ← this file
├── data/                            ← real public datasets + conversion script
│   ├── README.md
│   ├── kev/known_exploited_vulnerabilities.csv
│   ├── mitre/*.csv
│   └── scripts/prepare_mitre.py
└── portfolio-1-database-design/
    ├── README.md                    ← case study, design, normalisation, how to run
    ├── erd.dbml / erd.png
    ├── schema.sql
    ├── import_real_data.sql
    ├── sample_data.sql
    ├── constraint_tests.sql
    └── screenshots/
portfolio-2-query-optimisation/      ← p2_query_optimisation.sql
portfolio-3-transactions-concurrency/← p3_transactions.sql
portfolio-4-nosql/                   ← p4_document_model.sql, mongodb_equivalent.js
portfolio-5-distributed-cloud/       ← p5_distributed_partitioning.sql
```

**Run order:** Portfolio 1 (`schema.sql` → `import_real_data.sql` → `sample_data.sql` → `constraint_tests.sql`), then `p2` → `p3` → `p4` → `p5`. Every script is re-runnable.

## Tools
PostgreSQL, pgAdmin 4, dbdiagram.io, Python, GitHub
*(Portfolio 4 uses PostgreSQL JSONB as the document store, with equivalent MongoDB commands provided)*

## AI Use Declaration
*Use of Claude ai tool to gather information, for a better grammatical structure, to verify data and proper implemetation of my idea*

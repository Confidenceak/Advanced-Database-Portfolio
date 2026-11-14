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

## References
*Arkko, J., Cotton, M. and Vegoda, L. (2010) IPv4 Address Blocks Reserved for Documentation. RFC 5737. IETF.
Berenson, H. et al. (1995) 'A Critique of ANSI SQL Isolation Levels', Proceedings of ACM SIGMOD 1995, pp. 1–10.
CISA (2026) Known Exploited Vulnerabilities Catalog. Available at: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (Accessed: 11 November 2026).
Codd, E.F. (1970) 'A Relational Model of Data for Large Shared Data Banks', Communications of the ACM, 13(6), pp. 377–387.
Elmasri, R. and Navathe, S.B. (2016) Fundamentals of Database Systems. 7th edn. Pearson.
Gilbert, S. and Lynch, N. (2002) 'Brewer's Conjecture and the Feasibility of Consistent, Available, Partition-Tolerant Web Services', ACM SIGACT News, 33(2), pp. 51–59.
Kleppmann, M. (2017) Designing Data-Intensive Applications. Sebastopol, CA: O'Reilly Media.
MITRE (2026) MITRE ATT&CK® Enterprise Matrix, v20.1. Available at: https://attack.mitre.org (Accessed: 11 November 2026).
NIST (2026) National Vulnerability Database. Available at: https://nvd.nist.gov (Accessed: 11 November 2026).
Nigeria Data Protection Act 2023.
PostgreSQL Global Development Group (2026) PostgreSQL 18 Documentation: Using EXPLAIN; Indexes; Transaction Isolation; JSON Types; Table Partitioning. Available at: https://www.postgresql.org/docs/18/ (Accessed: 12 November 2026).
Sadalage, P.J. and Fowler, M. (2012) NoSQL Distilled. Upper Saddle River, NJ: Addison-Wesley.
Strom, B.E., Applebaum, A., Miller, D.P., Nickels, K.C., Pennington, A.G. and Thomas, C.B. (2020) MITRE ATT&CK: Design and Philosophy. Revised March 2020. McLean, VA: The MITRE Corporation.
Software and tools: PostgreSQL 18 and pgAdmin 4; dbdiagram.io (Holistics); Python 3; GitHub. MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*

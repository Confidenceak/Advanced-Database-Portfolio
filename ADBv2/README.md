# Advanced Database Systems Portfolio

**Course:** MIT 8103 Advanced Database Systems, Miva Open University
**Student:** [Your full name] — [Matric number]
**Session:** 2026/2027, First Semester (September 2026 cohort)

## Case Study
**CyberAce Tech Security Ltd** — a simulated global Managed Security Service Provider headquartered in Lagos, Nigeria.
The portfolio builds the database behind its 24/7 Security Operations Centre (SOC): security events, alerts,
incidents, vulnerabilities and remediation tasks for clients across Africa, Europe and the Middle East.

The operational data (clients, assets, incidents) is simulated. The threat-intelligence reference data is **real**:
the CISA Known Exploited Vulnerabilities catalog, MITRE ATT&CK Enterprise and, from Portfolio 2, real server logs
from the Loghub dataset. See [`data/README.md`](data/README.md).

## Portfolio Contents
| # | Activity | Folder | Status |
|---|---|---|---|
| 1 | Database Design and Modelling | [portfolio-1-database-design](portfolio-1-database-design/) | Complete |
| 2 | Query Processing and Optimisation | portfolio-2-query-optimisation | Not started |
| 3 | Transactions and Concurrency | portfolio-3-transactions-concurrency | Not started |
| 4 | NoSQL and Advanced Data Models | portfolio-4-nosql | Not started |
| 5 | Distributed and Cloud Database | portfolio-5-distributed-cloud | Not started |

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
```

## Tools
PostgreSQL, pgAdmin 4, dbdiagram.io, Python, GitHub
*(later portfolios: MongoDB, Redis, Neo4j, Docker)*

## AI Use Declaration
*[To complete in your own words — tool used, what it was used for, and how you reviewed, tested and verified the output.]*

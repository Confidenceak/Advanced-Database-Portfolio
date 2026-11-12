# Portfolio 4 — NoSQL and Advanced Data Models

**Scripts:**
- [`p4_document_model.sql`](p4_document_model.sql) — document model implemented and run in PostgreSQL using **JSONB** (binary JSON documents with indexing)
- [`mongodb_equivalent.js`](mongodb_equivalent.js) — the same collections, indexes and queries in **MongoDB** (`mongosh`) syntax

## Why NoSQL for a SOC
Security logs come from many products: firewalls, IDS, endpoint agents, authentication servers and cloud services. **Each has a different structure**, and new sources appear all the time. In a relational table this means dozens of mostly empty columns, or a schema change for every new log type. A **document model** stores each log in its natural shape.

## What was implemented
| Part | Concept | Implementation |
|---|---|---|
| `raw_log_document` | **Schema flexibility** | 5 log documents from 5 sources, each with different fields, including nested objects (`process.parent`) and arrays (`tags`, `dst_ports`) |
| `incident_document` | **Embedding** (aggregate design) | Each incident stored as one document with its client, alerts and tasks embedded, built from the relational tables with `jsonb_build_object` / `jsonb_agg` |
| `idx_rawlog_gin` | **Document indexing** | GIN index supporting containment (`@>`) queries, equivalent to MongoDB's multikey indexes |
| Q1–Q5 | **Document queries** | Containment, nested-field, aggregation (`$group` equivalent), array membership, and listing the different keys per log type |
| Q6 | **Graph traversal** | Recursive query walking the real MITRE technique tree (T1059 → 13 sub-techniques), the kind of query graph databases such as Neo4j specialise in |

## Embedding vs referencing
| | Embedding (document) | Referencing (relational) |
|---|---|---|
| Read an incident with its alerts and tasks | **1 lookup** | 4 joined tables |
| Update one alert shared by many views | Must update every copy | Update once |
| Best for | Read-heavy views: incident dashboards, case files | Data that changes often or is shared |

**Decision:** CyberAce keeps the **relational model as the system of record** (Portfolio 1: integrity, transactions) and uses **documents** for raw log ingestion and read-optimised incident views. This is *polyglot persistence*.

## Relational vs NoSQL for this case study
| Requirement | Better fit | Reason |
|---|---|---|
| Incident assignment, audit trail | Relational | ACID transactions and constraints (Portfolio 3) |
| Raw multi-source logs | Document | Flexible schema, high write volume |
| IP blocklist with expiry | Key-value (e.g. Redis) | Fast lookups, automatic expiry (TTL) |
| Attack paths / technique hierarchy | Graph (e.g. Neo4j) | Relationship traversal |

## Evidence
| Screenshot | Shows |
|---|---|
| [p4-01-queries.png](screenshots/p4-01-queries.png) | Messages: document queries Q1–Q6 results |
| [p4-02-embedded-document.png](screenshots/p4-02-embedded-document.png) | Data Output: incident 2 as one embedded JSON document |

*Limitation: due to time, the model was executed in PostgreSQL JSONB rather than a running MongoDB server; `mongodb_equivalent.js` gives the equivalent MongoDB implementation for deployment.*

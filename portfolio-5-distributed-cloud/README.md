# Portfolio 5 — Distributed and Cloud Database

**Script:** [`p5_distributed_partitioning.sql`](p5_distributed_partitioning.sql) — run in the pgAdmin Query Tool after Portfolios 1–2.

## Scenario
CyberAce monitors clients in **Africa, Europe and the Middle East**. A single database in Lagos would mean slow access for European analysts, a single point of failure, and client data stored outside its home region, which matters for data-protection laws such as the NDPA (Nigeria) and GDPR (EU).

## Design: shard by region
| Shard (partition) | Planned node | Clients |
|---|---|---|
| `shard_africa` | Lagos, Nigeria | Zenora Microfinance Bank, Kestrel Pay |
| `shard_europe` | Frankfurt, Germany | Nordlicht Logistik, Harbourline Health |
| `shard_middle_east` | Dubai, UAE | Al Waha Retail, Qamar Energy |

**Shard key = `region`**, because almost every SOC query is about one client, and every client belongs to exactly one region. Regional queries therefore touch one node only; data stays in its home region; and the load is split evenly (about 33% per shard in the test run).

## What the script demonstrates
1. `security_event_dist` is **partitioned by LIST (region)** into three shards.
2. ~500,000 events are inserted and **automatically routed** to the correct shard.
3. **Partition pruning:** the plan for an Africa-only query scans only `shard_africa`; a global report scans all three shards (`Parallel Append`). In a real cluster this means only the Lagos node works for an African query.
4. **Data residency:** inserting a European event directly into the Africa shard is rejected by the partition constraint.

*On a single PostgreSQL server the partitions model the shards; in production each partition would live on its own regional node (e.g. using the Citus extension, or PostgreSQL foreign tables).*

## Replication and availability
Each regional primary would stream its write-ahead log (WAL) to a **replica** in a second availability zone:
- **Read scaling:** dashboards and reports read from the replica.
- **Failover:** if the primary fails, the replica is promoted.
- **Synchronous replication** for the incident and audit tables (no committed incident lost); **asynchronous** for raw logs (faster; a few seconds of logs at risk is acceptable).

## CAP trade-offs
During a network partition a distributed system must choose **Consistency** or **Availability**:
| Data | Choice | Reason |
|---|---|---|
| Incident assignment, audit log | **CP** | Two analysts must never both own an incident (Portfolio 3); better to briefly refuse writes than to accept conflicting ones |
| Raw security logs, dashboards | **AP** | Ingestion must never stop during an attack; logs can be reconciled later (eventual consistency) |

## Cloud option
A managed service (e.g. Amazon RDS / Aurora PostgreSQL or Azure Database for PostgreSQL) would provide automated backups, Multi-AZ replicas and regional deployments. The trade-offs are cost, vendor lock-in and the need to choose regions that satisfy data-residency rules (an Africa region for Nigerian clients).

## Evidence
| Screenshot | Shows |
|---|---|
| [p5-01-shards.png](screenshots/p5-01-shards.png) | Data Output: rows per shard / planned node |
| [p5-02-pruning.png](screenshots/p5-02-pruning.png) | Messages: partition pruning plans and residency test |

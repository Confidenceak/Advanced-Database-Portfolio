# Portfolio 3 — Transactions and Concurrency Control

**Script:** [`p3_transactions.sql`](p3_transactions.sql) — run in the pgAdmin Query Tool after Portfolio 1.
Narration of each step appears in the **Messages** tab; the final state appears in **Data Output**.

## Scenario
Escalating an incident at CyberAce is **one business operation made of several writes**: claim the incident, create a remediation task and record an audit entry. Either all of them happen or none do. Incidents 4 and 5 are new and unassigned, so several analysts may try to claim them at the same moment.

## Demonstrations
| Demo | ACID / concurrency concept | What happens |
|---|---|---|
| 1 | **Atomicity — commit** | Claim incident 4 + create task + audit entry, committed together |
| 2 | **Atomicity — rollback** | Claim incident 5 and write an audit entry, then the task insert fails (`due_date` NULL). The whole unit is rolled back, so incident 5 is still unassigned |
| 3 | **Savepoint** | An audit entry is kept while a later invalid change (severity `Extreme`) is rolled back to the savepoint only |
| 4a | **Lost update** (the problem) | Two analysts both read incident 5 as free, both write; the second write silently overwrites the first |
| 4b | **Optimistic concurrency** (the fix) | `UPDATE … WHERE assigned_analyst_id IS NULL`: the first claim updates 1 row, the second updates 0 rows and is rejected |
| 5 | **Pessimistic locking** | `SELECT … FOR UPDATE` locks the incident row; shows the default isolation level (`read committed`) |

**Consistency** is enforced by the Portfolio 1 constraints (the failures in demos 2 and 3 are `NOT NULL` and `CHECK` violations). **Durability**: once `COMMIT` returns, PostgreSQL has written the change to its write-ahead log (WAL), so it survives a crash.

## Two-session locking demo (optional, run manually)
Open **two Query Tool tabs** on `cyberace_soc`:

| Step | Tab A (Fatima) | Tab B (Kwame) |
|---|---|---|
| 1 | `BEGIN;` | |
| 2 | `SELECT * FROM incident WHERE incident_id = 4 FOR UPDATE;` | |
| 3 | | `BEGIN;` |
| 4 | | `UPDATE incident SET assigned_analyst_id = 4 WHERE incident_id = 4;` → **waits (blocked)** |
| 5 | `UPDATE incident SET assigned_analyst_id = 3 WHERE incident_id = 4; COMMIT;` | Tab B now continues |
| 6 | | `COMMIT;` |

## Isolation levels in this case study
| Level | Prevents | Use at CyberAce |
|---|---|---|
| Read Committed (default) | Dirty reads | Dashboards and alert lists, where slightly changing data is acceptable |
| Repeatable Read | + non-repeatable reads | Monthly SLA reports: totals must not change mid-report |
| Serializable | + phantoms / write skew | Incident assignment and analyst on-call rules, where correctness matters more than speed |

Higher levels are safer but cause more waiting and transaction retries, so the level is chosen per operation rather than globally.

## Evidence
| Screenshot | Shows |
|---|---|
| [p3-01-messages.png](screenshots/p3-01-messages.png) | Messages: demos 1–5 narration (commit, rollback, savepoint, lost update and fix) |
| [p3-02-final-state.png](screenshots/p3-02-final-state.png) | Data Output: final state of incidents 4 and 5 |

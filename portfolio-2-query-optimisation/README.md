# Portfolio 2 — Query Processing and Optimisation

**Script:** [`p2_query_optimisation.sql`](p2_query_optimisation.sql) — run in the pgAdmin Query Tool after Portfolio 1.

## What it does
1. Loads **500,000 high-volume security events** (generated across 18 assets over 30 days; ~10% failed logins from 200 external IPs) so that query cost is measurable. With only 66 rows every query is instant and indexes make no visible difference.
2. Runs three queries a SOC analyst uses constantly, **before** any index, with `EXPLAIN ANALYZE` (3 runs, warm cache, last run recorded).
3. Creates three indexes designed for those queries and runs the **same** queries again.
4. Creates three analytical views using joins, aggregation, `FILTER`, a window function (`RANK() OVER`) and a 5-table join across the real MITRE ATT&CK data.
5. Prints full execution plans to the **Messages** tab and a before/after comparison to **Data Output**.

## Queries and indexes
| # | Business question | Index created | Why this index |
|---|---|---|---|
| Q1 | All activity on one asset in a 24-hour window (incident investigation) | `idx_event_asset_time (asset_id, event_time)` | Composite B-tree: equality column first, range column second, so one index range scan finds the rows already in time order |
| Q2 | Everything one suspicious IP did in the last 7 days (threat hunting) | `idx_event_srcip_time (source_ip, event_time)` | Very selective: one IP out of 500,000 rows |
| Q3 | Top 10 IPs by failed logins (brute-force detection) | `idx_event_failed_login (source_ip) WHERE event_type = 'login_failed'` | **Partial** index: only ~10% of rows, so it is small and cheap to maintain |

## Results (test run — your own timings will differ slightly)
| Query | Plan before | Plan after | Before (ms) | After (ms) | Speed-up |
|---|---|---|---|---|---|
| Q1 | Parallel Seq Scan | Bitmap Heap Scan | 29.2 | 1.2 | ~25× |
| Q2 | Parallel Seq Scan | Index Scan | 33.9 | 0.01 | >1,000× |
| Q3 | Seq Scan | Bitmap Heap Scan | 50.9 | 25.8 | ~2× |

## Analysis
- **Without indexes** PostgreSQL must read every one of the ~500,000 rows (*sequential scan*), even when only a handful match. It uses parallel workers to share the work, but the total work is unchanged.
- **Q1 and Q2** become index lookups: the optimiser estimates very few matching rows, so reading the index and fetching only those rows is far cheaper than scanning the table. Q2 shows the biggest gain because one IP is highly selective.
- **Q3** improves least. It must still visit every failed login (~50,000 rows) to count them, so the index only removes the 90% of rows that are not failed logins. This shows that **indexes help most for selective queries**; for large aggregations a pre-computed summary (materialised view) would be the next step.
- **Trade-off:** every index slows down `INSERT`s and uses disk space. For a log table that receives constant writes, only indexes that serve frequent queries should be kept; this is why Q3 uses a small partial index rather than a full index on `event_type`.
- `ANALYZE` is run after loading data and after creating indexes so the optimiser's statistics (row counts, value distributions) are accurate. Without it the planner may choose a poor plan.

## Analytical views
| View | Technique demonstrated |
|---|---|
| `v_alerts_by_tactic` | 5-table join across simulated alerts and real MITRE tactics; `COUNT(DISTINCT)` |
| `v_client_exposure` | Joins to real CISA KEV data; conditional aggregation with `FILTER`; `RANK() OVER` window function |
| `v_mttr` | Date arithmetic and aggregation: mean time to resolve incidents |

Query them with e.g. `SELECT * FROM v_client_exposure;`

## Evidence
| Screenshot | Shows |
|---|---|
| [p2-01-before-after.png](screenshots/p2-01-before-after.png) | Data Output: before/after comparison table |
| [p2-02-plans.png](screenshots/p2-02-plans.png) | Messages: EXPLAIN ANALYZE plans showing Seq Scan → Index Scan |

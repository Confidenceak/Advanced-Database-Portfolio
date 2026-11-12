-- =====================================================================
-- MIT 8103 — Portfolio 2: Query Processing and Optimisation
-- Case study: CyberAce Tech Security Ltd (SOC database)
-- Run AFTER Portfolio 1 scripts, in the pgAdmin Query Tool (F5).
--   * Data Output tab  -> before/after performance comparison
--   * Messages tab     -> full EXPLAIN ANALYZE plans, before and after
-- Re-runnable: removes its own bulk rows and indexes first.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Reset: drop the indexes this script creates, remove old bulk rows
-- ---------------------------------------------------------------------
DROP INDEX IF EXISTS idx_event_asset_time;
DROP INDEX IF EXISTS idx_event_srcip_time;
DROP INDEX IF EXISTS idx_event_failed_login;
DELETE FROM security_event WHERE raw_message LIKE 'BULK:%';

-- ---------------------------------------------------------------------
-- 1. Load 500,000 high-volume events so indexes make a measurable
--    difference. Generated (simulated) log traffic spread over 30 days
--    across all 18 assets; ~10% are failed logins from 200 external IPs
--    (RFC 5737 documentation ranges).
-- ---------------------------------------------------------------------
INSERT INTO security_event (asset_id, event_time, event_type, source_ip,
                            destination_ip, destination_port, username, raw_message)
SELECT 1 + (n % 18),
       TIMESTAMP '2026-10-12 00:00' + (random() * INTERVAL '30 days'),
       CASE WHEN n % 10 = 0 THEN 'login_failed'
            WHEN n % 10 IN (1,2) THEN 'login_success'
            WHEN n % 10 = 3 THEN 'port_scan'
            ELSE 'outbound_connection' END,
       CASE WHEN n % 10 = 0
            THEN ('203.0.113.' || (n % 200 % 254 + 1))::inet
            ELSE ('10.' || (10 * (1 + (n % 18) / 3)) || '.' || (n % 250) || '.' || (n % 253 + 1))::inet END,
       ('10.' || (10 * (1 + (n % 18) / 3)) || '.1.' || (n % 50 + 1))::inet,
       (ARRAY[22, 80, 443, 445, 3389, 8080])[1 + n % 6],
       'user' || (n % 300),
       'BULK: generated event ' || n
FROM generate_series(1, 500000) AS n;

ANALYZE security_event;

-- ---------------------------------------------------------------------
-- 2. Helper: run EXPLAIN ANALYZE on a query, print the plan to the
--    Messages tab and record the execution time.
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS p2_results;
CREATE TABLE p2_results (
    query_no   INT,
    query_name TEXT,
    stage      TEXT,
    exec_ms    NUMERIC,
    plan_type  TEXT
);

CREATE OR REPLACE FUNCTION p2_measure(q_no INT, q_name TEXT, q_stage TEXT, q_sql TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    line TEXT; ms NUMERIC; first_node TEXT := NULL; run INT;
BEGIN
    -- run 3 times and keep the last (warm cache) measurement
    FOR run IN 1..3 LOOP
        IF run = 3 THEN
            RAISE NOTICE '====== Q% % — % ======', q_no, q_name, q_stage;
        END IF;
        FOR line IN EXECUTE 'EXPLAIN (ANALYZE, BUFFERS OFF) ' || q_sql LOOP
            IF run = 3 THEN
                RAISE NOTICE '%', line;
                IF first_node IS NULL AND (line ~ 'Scan' ) THEN
                    first_node := substring(line from '((Parallel )?(Seq|Index Only|Index|Bitmap Heap|Bitmap Index) Scan)');
                END IF;
                IF line LIKE 'Execution Time:%' THEN
                    ms := substring(line from '([0-9.]+) ms')::NUMERIC;
                END IF;
            END IF;
        END LOOP;
    END LOOP;
    INSERT INTO p2_results VALUES (q_no, q_name, q_stage, ms, first_node);
END $$;

-- ---------------------------------------------------------------------
-- 3. The three slow queries a SOC analyst runs constantly
-- ---------------------------------------------------------------------
-- Q1: all activity on one asset in a 24-hour window (incident investigation)
-- Q2: everything one suspicious IP did in the last 7 days (threat hunting)
-- Q3: top 10 IPs by failed logins (brute-force detection)

-- BEFORE indexes
SELECT p2_measure(1, 'Asset activity in 24h window', 'BEFORE index',
 $q$SELECT event_time, event_type, source_ip FROM security_event
    WHERE asset_id = 5 AND event_time BETWEEN '2026-11-01' AND '2026-11-02'
    ORDER BY event_time$q$);

SELECT p2_measure(2, 'One IP over 7 days', 'BEFORE index',
 $q$SELECT asset_id, event_time, event_type FROM security_event
    WHERE source_ip = '203.0.113.45' AND event_time >= '2026-11-04'$q$);

SELECT p2_measure(3, 'Top 10 brute-force IPs', 'BEFORE index',
 $q$SELECT source_ip, COUNT(*) AS failures FROM security_event
    WHERE event_type = 'login_failed'
    GROUP BY source_ip ORDER BY failures DESC LIMIT 10$q$);

-- ---------------------------------------------------------------------
-- 4. Create indexes designed for those queries
-- ---------------------------------------------------------------------
-- composite B-tree: equality column first, range column second
CREATE INDEX idx_event_asset_time  ON security_event (asset_id, event_time);
-- composite B-tree for IP + time range lookups
CREATE INDEX idx_event_srcip_time  ON security_event (source_ip, event_time);
-- PARTIAL covering index: only failed logins (~10% of rows), so it is small
CREATE INDEX idx_event_failed_login ON security_event (source_ip)
    WHERE event_type = 'login_failed';
ANALYZE security_event;

-- AFTER indexes (identical queries)
SELECT p2_measure(1, 'Asset activity in 24h window', 'AFTER index',
 $q$SELECT event_time, event_type, source_ip FROM security_event
    WHERE asset_id = 5 AND event_time BETWEEN '2026-11-01' AND '2026-11-02'
    ORDER BY event_time$q$);

SELECT p2_measure(2, 'One IP over 7 days', 'AFTER index',
 $q$SELECT asset_id, event_time, event_type FROM security_event
    WHERE source_ip = '203.0.113.45' AND event_time >= '2026-11-04'$q$);

SELECT p2_measure(3, 'Top 10 brute-force IPs', 'AFTER index',
 $q$SELECT source_ip, COUNT(*) AS failures FROM security_event
    WHERE event_type = 'login_failed'
    GROUP BY source_ip ORDER BY failures DESC LIMIT 10$q$);

-- ---------------------------------------------------------------------
-- 5. Analytical views (joins, aggregation, window functions)
-- ---------------------------------------------------------------------
-- Alerts per MITRE tactic (5-table join over REAL ATT&CK data)
CREATE OR REPLACE VIEW v_alerts_by_tactic AS
SELECT ta.name AS tactic, COUNT(DISTINCT a.alert_id) AS alerts
FROM   alert a
JOIN   detection_rule   r  ON r.rule_id      = a.rule_id
JOIN   technique_tactic tt ON tt.technique_id = r.technique_id
JOIN   mitre_tactic     ta ON ta.tactic_id    = tt.tactic_id
GROUP  BY ta.name;

-- Client exposure: unpatched KEV vulnerabilities, ranked with a window function
CREATE OR REPLACE VIEW v_client_exposure AS
SELECT c.name AS client, c.region,
       COUNT(*) FILTER (WHERE av.patch_status = 'Unpatched')               AS unpatched_cves,
       COUNT(*) FILTER (WHERE v.known_ransomware_use AND av.patch_status = 'Unpatched') AS ransomware_cves,
       MAX(v.cvss_score)                                                   AS worst_cvss,
       RANK() OVER (ORDER BY COUNT(*) FILTER (WHERE av.patch_status = 'Unpatched') DESC,
                             MAX(v.cvss_score) DESC NULLS LAST)            AS risk_rank
FROM   client c
JOIN   asset a                ON a.client_id = c.client_id
JOIN   asset_vulnerability av ON av.asset_id = a.asset_id
JOIN   vulnerability v        ON v.cve_id    = av.cve_id
GROUP  BY c.name, c.region;

-- Mean time to resolve closed incidents (subquery + aggregation)
CREATE OR REPLACE VIEW v_mttr AS
SELECT severity, COUNT(*) AS closed_incidents,
       ROUND(AVG(EXTRACT(EPOCH FROM (closed_at - opened_at)) / 3600)::NUMERIC, 2) AS avg_hours_to_close
FROM   incident WHERE status = 'Closed'
GROUP  BY severity;

-- ---------------------------------------------------------------------
-- 6. RESULT: before vs after (Data Output tab)
-- ---------------------------------------------------------------------
SELECT b.query_no                          AS q,
       b.query_name,
       b.plan_type                         AS plan_before,
       a.plan_type                         AS plan_after,
       b.exec_ms                           AS ms_before,
       a.exec_ms                           AS ms_after,
       ROUND(b.exec_ms / NULLIF(a.exec_ms, 0), 1) || 'x faster' AS speed_up
FROM   p2_results b
JOIN   p2_results a ON a.query_no = b.query_no AND a.stage = 'AFTER index'
WHERE  b.stage = 'BEFORE index'
ORDER  BY q;

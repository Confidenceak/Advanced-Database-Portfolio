-- =====================================================================
-- MIT 8103 — Portfolio 4: NoSQL and Advanced Data Models
-- Case study: CyberAce Tech Security Ltd (SOC database)
-- Document (NoSQL) model implemented with PostgreSQL JSONB.
-- The same model in MongoDB syntax is in mongodb_equivalent.js.
-- Run in the pgAdmin Query Tool (F5). Results: Messages + Data Output.
-- =====================================================================

DROP TABLE IF EXISTS raw_log_document;
DROP TABLE IF EXISTS incident_document;

-- ---------------------------------------------------------------------
-- 1. Raw logs as SCHEMA-FLEXIBLE documents
--    Firewall, IDS, endpoint and auth logs all have different fields.
--    In the relational model these would need many NULL columns or
--    separate tables; a document store keeps each log in its natural shape.
-- ---------------------------------------------------------------------
CREATE TABLE raw_log_document (
    doc_id  BIGSERIAL PRIMARY KEY,
    doc     JSONB NOT NULL
);

INSERT INTO raw_log_document (doc) VALUES
('{"source":"firewall","vendor":"Fortinet","host":"kp-vpn01","client":"Kestrel Pay Ltd","region":"Africa",
  "ts":"2026-11-02T02:14:00","action":"deny","src_ip":"203.0.113.45","dst_port":443,
  "policy":{"id":17,"name":"SSL-VPN-Inbound"},"tags":["brute-force","T1110"]}'),
('{"source":"ids","vendor":"Suricata","host":"nl-wms-app01","client":"Nordlicht Logistik GmbH","region":"Europe",
  "ts":"2026-11-09T23:00:02","signature":"ET SCAN Nmap SYN Scan","sid":2009582,"severity":2,
  "src_ip":"10.30.7.3","dst_ports":[21,22,23,25,80,135,139,443,445],"tags":["discovery","T1046"]}'),
('{"source":"endpoint","vendor":"EDR","host":"zmb-ws-teller12","client":"Zenora Microfinance Bank","region":"Africa",
  "ts":"2026-11-10T09:10:30","process":{"name":"powershell.exe","pid":4412,
  "cmdline":"powershell.exe -NoP -W Hidden -Enc SQBFAFgA...","parent":{"name":"winword.exe","pid":3120}},
  "user":"teller12","tags":["execution","T1059.001"]}'),
('{"source":"auth","vendor":"OpenSSH","host":"kp-api-gw01","client":"Kestrel Pay Ltd","region":"Africa",
  "ts":"2026-11-08T16:42:00","result":"success","user":"j.mwangi","src_ip":"198.51.100.200",
  "geo":{"country":"BR","city":"Sao Paulo"},"previous_login":{"geo":{"country":"KE"},"minutes_ago":32},
  "tags":["impossible-travel","T1078"]}'),
('{"source":"cloud","vendor":"AWS CloudTrail","host":"aw-pay-app01","client":"Al Waha Retail LLC","region":"Middle East",
  "ts":"2026-11-05T14:25:00","event_name":"ConsoleLogin","mfa_used":false,
  "request":{"user_agent":"curl/7.88","ip":"198.51.100.77"},"tags":["T1071"]}');

-- ---------------------------------------------------------------------
-- 2. EMBEDDING: an incident stored as ONE aggregate document with its
--    alerts, tasks and timeline embedded (read in a single lookup)
--    — versus 4+ joined tables in the relational model.
-- ---------------------------------------------------------------------
CREATE TABLE incident_document (
    incident_id INT PRIMARY KEY,
    doc         JSONB NOT NULL
);

INSERT INTO incident_document (incident_id, doc)
SELECT i.incident_id,
       jsonb_build_object(
         'title',    i.title,
         'severity', i.severity,
         'status',   i.status,
         'client',   jsonb_build_object('name', c.name, 'region', c.region, 'sla', c.sla_tier),
         'assigned_to', an.full_name,
         'alerts', (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'alert_id', a.alert_id, 'rule', r.rule_name,
                        'technique', r.technique_id, 'host', s.hostname)), '[]'::jsonb)
                    FROM alert a JOIN detection_rule r ON r.rule_id = a.rule_id
                                 JOIN asset s ON s.asset_id = a.asset_id
                    WHERE a.incident_id = i.incident_id),
         'tasks',  (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'description', t.description, 'status', t.status)), '[]'::jsonb)
                    FROM remediation_task t WHERE t.incident_id = i.incident_id))
FROM   incident i
JOIN   client c ON c.client_id = i.client_id
LEFT   JOIN analyst an ON an.analyst_id = i.assigned_analyst_id;

-- ---------------------------------------------------------------------
-- 3. Indexing documents: GIN index supports containment (@>) searches
-- ---------------------------------------------------------------------
CREATE INDEX idx_rawlog_gin ON raw_log_document USING GIN (doc jsonb_path_ops);

-- ---------------------------------------------------------------------
-- 4. Document queries (results printed to the Messages tab)
-- ---------------------------------------------------------------------
DO $$
DECLARE r RECORD;
BEGIN
    RAISE NOTICE '--- Q1 containment (like MongoDB find): all logs tagged T1110 ---';
    FOR r IN SELECT doc->>'host' AS host, doc->>'source' AS src FROM raw_log_document
             WHERE doc @> '{"tags":["T1110"]}' LOOP
        RAISE NOTICE '  host=%  source=%', r.host, r.src;
    END LOOP;

    RAISE NOTICE '--- Q2 nested field: endpoint processes launched by Word (macro malware) ---';
    FOR r IN SELECT doc->>'host' AS host, doc#>>'{process,name}' AS proc
             FROM raw_log_document WHERE doc#>>'{process,parent,name}' = 'winword.exe' LOOP
        RAISE NOTICE '  host=%  process=%', r.host, r.proc;
    END LOOP;

    RAISE NOTICE '--- Q3 aggregation (like MongoDB $group): log documents per region ---';
    FOR r IN SELECT doc->>'region' AS region, COUNT(*) AS n FROM raw_log_document
             GROUP BY 1 ORDER BY 2 DESC LOOP
        RAISE NOTICE '  %: %', r.region, r.n;
    END LOOP;

    RAISE NOTICE '--- Q4 array query: IDS scans that probed port 445 (SMB) ---';
    FOR r IN SELECT doc->>'host' AS host FROM raw_log_document
             WHERE doc->'dst_ports' @> '445' LOOP
        RAISE NOTICE '  host=%', r.host;
    END LOOP;

    RAISE NOTICE '--- Q5 schema flexibility: distinct top-level keys across log types ---';
    FOR r IN SELECT doc->>'source' AS src, string_agg(k, ', ' ORDER BY k) AS keys
             FROM raw_log_document, jsonb_object_keys(doc) k GROUP BY 1 LOOP
        RAISE NOTICE '  %: %', r.src, r.keys;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 5. GRAPH-STYLE query: walk the MITRE technique hierarchy
--    (recursive CTE = graph traversal, the kind of query Neo4j specialises in)
-- ---------------------------------------------------------------------
DO $$
DECLARE r RECORD;
BEGIN
    RAISE NOTICE '--- Q6 graph traversal: T1059 and all its sub-techniques ---';
    FOR r IN WITH RECURSIVE tree AS (
                 SELECT technique_id, name, 0 AS depth FROM mitre_technique WHERE technique_id = 'T1059'
                 UNION ALL
                 SELECT t.technique_id, t.name, tree.depth + 1
                 FROM mitre_technique t JOIN tree ON t.parent_technique_id = tree.technique_id)
             SELECT * FROM tree ORDER BY technique_id LOOP
        RAISE NOTICE '  % %', repeat('   ', r.depth) || r.technique_id, r.name;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 6. RESULT (Data Output): one incident read as a single embedded document
-- ---------------------------------------------------------------------
SELECT incident_id, jsonb_pretty(doc) AS incident_document
FROM   incident_document
WHERE  incident_id = 2;

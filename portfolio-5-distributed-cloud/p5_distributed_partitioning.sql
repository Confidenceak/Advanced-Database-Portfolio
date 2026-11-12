-- =====================================================================
-- MIT 8103 — Portfolio 5: Distributed and Cloud Database
-- Case study: CyberAce Tech Security Ltd (clients in 3 regions)
-- Horizontal partitioning (sharding) of security events BY REGION.
-- Each partition represents the data a regional node (Lagos, Frankfurt,
-- Dubai) would hold in a distributed deployment.
-- Run in the pgAdmin Query Tool (F5). Results: Messages + Data Output.
-- =====================================================================

DROP TABLE IF EXISTS security_event_dist CASCADE;

-- ---------------------------------------------------------------------
-- 1. Partitioned (sharded) table — partition key = client region
-- ---------------------------------------------------------------------
CREATE TABLE security_event_dist (
    event_id    BIGINT       NOT NULL,
    region      VARCHAR(20)  NOT NULL,
    client_id   INTEGER      NOT NULL,
    asset_id    INTEGER      NOT NULL,
    event_time  TIMESTAMP    NOT NULL,
    event_type  VARCHAR(50)  NOT NULL,
    source_ip   INET,
    PRIMARY KEY (region, event_id)        -- partition key must be in the PK
) PARTITION BY LIST (region);

-- One partition ("shard") per regional data centre
CREATE TABLE shard_africa      PARTITION OF security_event_dist FOR VALUES IN ('Africa');       -- node: Lagos
CREATE TABLE shard_europe      PARTITION OF security_event_dist FOR VALUES IN ('Europe');       -- node: Frankfurt
CREATE TABLE shard_middle_east PARTITION OF security_event_dist FOR VALUES IN ('Middle East');  -- node: Dubai

-- ---------------------------------------------------------------------
-- 2. Distribute existing events: rows are ROUTED automatically to the
--    correct shard from the client's region
-- ---------------------------------------------------------------------
INSERT INTO security_event_dist
SELECT e.event_id, c.region, c.client_id, e.asset_id, e.event_time, e.event_type, e.source_ip
FROM   security_event e
JOIN   asset  a ON a.asset_id  = e.asset_id
JOIN   client c ON c.client_id = a.client_id;

CREATE INDEX ON security_event_dist (client_id, event_time);   -- created on every shard
ANALYZE security_event_dist;

-- ---------------------------------------------------------------------
-- 3. PARTITION PRUNING: a query for one region touches ONLY that shard
--    (in a real cluster: only the Lagos node does any work)
-- ---------------------------------------------------------------------
DO $$
DECLARE line TEXT;
BEGIN
    RAISE NOTICE '--- Query for Africa only: plan scans ONE shard ---';
    FOR line IN EXECUTE $q$EXPLAIN SELECT COUNT(*) FROM security_event_dist
                           WHERE region = 'Africa' AND event_type = 'login_failed'$q$ LOOP
        RAISE NOTICE '%', line;
    END LOOP;
    RAISE NOTICE '--- Query across all regions (global report): plan scans ALL shards ---';
    FOR line IN EXECUTE $q$EXPLAIN SELECT region, COUNT(*) FROM security_event_dist
                           GROUP BY region$q$ LOOP
        RAISE NOTICE '%', line;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 4. Data-residency check: a row can never land in the wrong shard
-- ---------------------------------------------------------------------
DO $$
BEGIN
    INSERT INTO shard_africa (event_id, region, client_id, asset_id, event_time, event_type)
    VALUES (-1, 'Europe', 3, 7, now(), 'test');
    RAISE NOTICE 'Residency test FAILED: European row stored on the Africa shard';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Residency test PASSED: European row rejected by Africa shard (%)', SQLERRM;
END $$;

-- ---------------------------------------------------------------------
-- 5. RESULT (Data Output): how the data is spread across the shards
-- ---------------------------------------------------------------------
SELECT tableoid::regclass                     AS shard,
       CASE tableoid::regclass::text
            WHEN 'shard_africa'      THEN 'Lagos, Nigeria'
            WHEN 'shard_europe'      THEN 'Frankfurt, Germany'
            WHEN 'shard_middle_east' THEN 'Dubai, UAE' END AS planned_node,
       COUNT(*)                               AS events,
       COUNT(DISTINCT client_id)              AS clients,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_of_data
FROM   security_event_dist
GROUP  BY tableoid
ORDER  BY shard;

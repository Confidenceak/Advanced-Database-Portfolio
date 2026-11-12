// MIT 8103 — Portfolio 4: the same document model in MongoDB (mongosh syntax)
// Database: cyberace_soc   Collections: raw_logs, incidents

use("cyberace_soc");

// 1. Schema-flexible raw logs (each source keeps its own shape)
db.raw_logs.insertMany([
  { source: "firewall", vendor: "Fortinet", host: "kp-vpn01", client: "Kestrel Pay Ltd", region: "Africa",
    ts: ISODate("2026-11-02T02:14:00Z"), action: "deny", src_ip: "203.0.113.45", dst_port: 443,
    policy: { id: 17, name: "SSL-VPN-Inbound" }, tags: ["brute-force", "T1110"] },
  { source: "ids", vendor: "Suricata", host: "nl-wms-app01", client: "Nordlicht Logistik GmbH", region: "Europe",
    ts: ISODate("2026-11-09T23:00:02Z"), signature: "ET SCAN Nmap SYN Scan", sid: 2009582, severity: 2,
    src_ip: "10.30.7.3", dst_ports: [21, 22, 23, 25, 80, 135, 139, 443, 445], tags: ["discovery", "T1046"] },
  { source: "endpoint", vendor: "EDR", host: "zmb-ws-teller12", client: "Zenora Microfinance Bank", region: "Africa",
    ts: ISODate("2026-11-10T09:10:30Z"),
    process: { name: "powershell.exe", pid: 4412, cmdline: "powershell.exe -NoP -W Hidden -Enc SQBFAFgA...",
               parent: { name: "winword.exe", pid: 3120 } },
    user: "teller12", tags: ["execution", "T1059.001"] }
]);

// 2. Indexes
db.raw_logs.createIndex({ tags: 1 });                  // multikey index on array
db.raw_logs.createIndex({ region: 1, ts: -1 });        // compound index; region is also the shard key

// 3. Queries
db.raw_logs.find({ tags: "T1110" }, { host: 1, source: 1 });                 // Q1 containment
db.raw_logs.find({ "process.parent.name": "winword.exe" });                  // Q2 nested field
db.raw_logs.aggregate([{ $group: { _id: "$region", n: { $sum: 1 } } },       // Q3 aggregation
                       { $sort: { n: -1 } }]);
db.raw_logs.find({ dst_ports: 445 });                                         // Q4 array match

// 4. Embedded incident document (one read returns alerts + tasks)
db.incidents.insertOne({
  _id: 2, title: "Log4Shell exploitation and C2 beaconing on aw-pay-app01",
  severity: "Critical", status: "In Progress",
  client: { name: "Al Waha Retail LLC", region: "Middle East", sla: "Bronze" },
  assigned_to: "Sarah Whitfield",
  alerts: [ { alert_id: 2, rule: "C2 Beacon to Known Malicious IP", technique: "T1071", host: "aw-pay-app01" },
            { alert_id: 3, rule: "Suspicious Command Execution", technique: "T1059", host: "aw-pay-app01" } ],
  tasks:  [ { description: "Isolate aw-pay-app01 from the network", status: "Done" },
            { description: "Upgrade Log4j to a patched version on the payment application", status: "Pending" } ]
});

// 5. Sharding by region (Portfolio 5 link) — run on a sharded cluster
// sh.enableSharding("cyberace_soc");
// sh.shardCollection("cyberace_soc.raw_logs", { region: 1, ts: 1 });

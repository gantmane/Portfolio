---
name: dba-skills
description: PostgreSQL, MySQL, DynamoDB, Redis architecture, replication, security.
allowed-tools: Read, Grep, Glob, Bash(psql:*), Bash(mysql:*), Bash(redis-cli:*), Bash(aws:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.DS-01, PR.DS-02, PR.DS-06, PR.PS-01, PR.PS-06, PR.AA-05]
mitre_attack_coverage: [T1005, T1565, T1190, T1557, T1110, T1078]
---

# DBA Skills

> **NIST**: PROTECT | PR.DS-01, PR.DS-02, PR.PS-01, PR.PS-06

## Quick Ref
- "PostgreSQL" → Config, optimization, security | "MySQL" → InnoDB, replication | "DynamoDB" → Design | "Encryption" → At-rest, in-transit

## Capabilities

### Relational Database ⇒ PR.PS-01
Shared buffers, index strategy (B-tree, covering, partial), EXPLAIN ANALYZE, connection pooling.
`ALTER SYSTEM SET shared_buffers = '4GB'; CREATE INDEX idx_email ON users(email);`

### NoSQL Patterns ⇒ PR.PS-01
Single-table design, GSI/LSI, conditional writes, Redis cluster.
`table.put_item(Item={'PK': 'USER#123', 'SK': 'PROFILE'}, ConditionExpression='attribute_not_exists(PK)')`

### HA & Replication ⇒ PR.IR-04, RC.RP-02
Streaming/semi-sync replication, multi-AZ, read replicas, failover.
`multi_az = true; storage_encrypted = true; backup_retention = 30; deletion_protection = true`

### Database Security ⇒ PR.DS-01, PR.AA-05
RBAC, TDE/KMS, SSL/TLS, column-level encryption, RLS, audit logging.
`ALTER TABLE users ENABLE ROW LEVEL SECURITY; CREATE POLICY isolation ON users USING (tenant_id = current_setting('app.tenant_id'));`

### Performance Optimization ⇒ PR.PS-01
Covering, partial indexes, query tuning, REINDEX, VACUUM.
`CREATE INDEX idx_covering ON orders(cust_id) INCLUDE (date, amount); CREATE INDEX idx_active ON users(email) WHERE status = 'active';`

### Backup & Recovery ⇒ RC.RP-02
Daily full + hourly incremental, PITR with WAL, cross-region replication.
`pg_restore -d target_db backup.dump; aws rds create-db-snapshot --db-instance-identifier prod-db`

### Migration & Schema ⇒ PR.PS-06
AWS DMS (full-load and CDC), online DDL, Flyway/Liquibase, blue-green.
`aws dms create-replication-task --migration-type full-load-and-cdc --table-mappings file://mappings.json`

### Monitoring ⇒ DE.CM-01
CPU/memory >80%, connections >80%, replication lag >10s, slow queries >5s.
`SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) FROM pg_tables;`

## MITRE: T1005, T1565, T1190, T1557, T1110, T1078

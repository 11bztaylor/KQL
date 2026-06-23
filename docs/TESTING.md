# Palo Alto CEF fan-out — testing runbook

Files in this repo:

| File | Purpose |
|------|---------|
| [`../paloalto/deploy/PaloAlto_CEF.kql`](../paloalto/deploy/PaloAlto_CEF.kql) | The deployable KQL: parser functions, tables, and update policies. |
| [`../paloalto/enrichment/enrichment.kql`](../paloalto/enrichment/enrichment.kql) | Query-time enrichment views (geo, labels, scope, reason descriptions, decoded flags). |
| [`../paloalto/ops/validation.kql`](../paloalto/ops/validation.kql) | Post-deployment monitoring: reconciliation, freshness, catch-all breakdown, parse health, drift check, backfill. |
| [`../paloalto/backfill/SIDEQUEST.kql`](../paloalto/backfill/SIDEQUEST.kql) | One-off historical THREAT + TRAFFIC backfill from CommonSecurityLog. |

---

## Step 1 — Deploy the tables and policies

Run the statements in `README.md` **top to bottom** on your target database:

1. `PaloAlto_CEF_Parsed()` (base function)
2. Each per-table block: `*_parse()` function → `.create table` → `.alter table … policy update`

Notes:
- `.create-or-alter function` is idempotent — safe to re-run.
- `.create table` **fails if the table already exists with a different schema.** On a redeploy where you changed columns, either drop the table first (`.drop table PaloAlto_Traffic ifexists`) or switch that statement to `.create-merge table`. ⚠️ Dropping a table deletes its data.
- Update policies are **forward-only**: they transform data ingested *after* the policy exists.

After deploying, confirm the policies are live:

```kusto
.show table PaloAlto_Traffic policy update
.show table PaloAlto_Threat  policy update
.show table PaloAlto         policy update
```

---

## Step 2 — Verify against live data

Once new Palo Alto syslog has flowed in (give it a few minutes):

1. **Reconciliation** (`validation.kql` #1) — the count of Palo Alto records in `Syslog` should equal the sum across the three tables for the same window. A persistent gap = dropped rows.
2. **Freshness** (`validation.kql` #2) — every table should show a recent `Latest`. A stale table stopped receiving.
3. **Catch-all breakdown** (`validation.kql` #3) — see what `LogType`s are landing in `PaloAlto`. A high-volume type (e.g. `SYSTEM`) is a candidate to promote to its own table.
4. **Parse health** (`validation.kql` #4) — TRAFFIC rows with empty `SourceIP`/`DeviceAction` indicate a malformed message or an undeclared key.

---

## Step 3 (optional) — Backfill existing Syslog data

Update policies don't touch data already in `Syslog`. To populate the tables from history, run the `.set-or-append` templates in `validation.kql` #6, scoped to a time window.

---

## Known caveats

- **Threat subtypes:** validated against the `url` subtype. Other subtypes (`virus`, `wildfire`, `vulnerability`, `file`) may carry a few extra `PanOS*` keys. If you see odd nulls in `PaloAlto_Threat`, grab one of those samples — the fix is to declare the new key(s) in `PaloAlto_CEF_Parsed()`. Any field not promoted to a column is kept in the `UnparsedFields` dynamic bag, so nothing is lost meanwhile.
- **CONFIG / SYSTEM / etc.** currently land in the `PaloAlto` catch-all with the raw extension preserved; promote any of them to a dedicated table by copying the TRAFFIC pattern.
- **Timestamps:** `StartTime` / `ReceiptTime` are stored as strings because PAN's `Mon dd yyyy HH:mm:ss GMT` format isn't `todatetime`-parseable. `TimeGenerated` (real datetime) is the column to query on.

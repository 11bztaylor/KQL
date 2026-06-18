# Palo Alto CEF fan-out — testing runbook

Files in this repo:

| File | Purpose |
|------|---------|
| `README.md` | The deployable KQL: base parser + `PaloAlto_Traffic` / `PaloAlto_Threat` / `PaloAlto` functions, tables, and update policies. |
| `PaloAlto_tests.kql` | **Self-contained** parser test. Runs the parse against the 3 real sample logs and asserts the output. Touches no tables. |
| `validation.kql` | Post-deployment monitoring: reconciliation, freshness, catch-all breakdown, parse health, backfill. |

---

## Step 1 — Test the parser logic (no deployment, zero risk)

Run this **first**. It proves the parsing is correct before anything touches your cluster.

1. Open `PaloAlto_tests.kql`, paste the whole file into an ADX/Kusto query window, run it.
2. **Expected result:** 3 rows, every `Passed == true`, every `Details` empty.
   - `TRAFFIC_drop_13.5`, `TRAFFIC_allow_10.1`, `THREAT_url_10.1`.
3. If any row shows `Passed == false`, the `Details` column names the field(s) that didn't match the expected value.

This requires no tables and deploys nothing — safe to run on any database.

---

## Step 2 — Deploy the tables and policies

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

## Step 3 — Verify against live data

Once new Palo Alto syslog has flowed in (give it a few minutes):

1. **Reconciliation** (`validation.kql` #1) — the count of Palo Alto records in `Syslog` should equal the sum across the three tables for the same window. A persistent gap = dropped rows.
2. **Freshness** (`validation.kql` #2) — every table should show a recent `Latest`. A stale table stopped receiving.
3. **Catch-all breakdown** (`validation.kql` #3) — see what `LogType`s are landing in `PaloAlto`. A high-volume type (e.g. `SYSTEM`) is a candidate to promote to its own table.
4. **Parse health** (`validation.kql` #4) — TRAFFIC rows with empty `SourceIP`/`DeviceAction` indicate a malformed message or an undeclared key.

---

## Step 4 (optional) — Backfill existing Syslog data

Update policies don't touch data already in `Syslog`. To populate the tables from history, run the `.set-or-append` templates in `validation.kql` #6, scoped to a time window.

---

## Known caveats

- **Threat subtypes:** validated against the `url` subtype. Other subtypes (`virus`, `wildfire`, `vulnerability`, `file`) may carry a few extra `PanOS*` keys. If you see odd nulls in `PaloAlto_Threat`, grab one of those samples — the fix is to declare the new key(s) in `PaloAlto_CEF_Parsed()`. The full raw extension is always kept in `AdditionalExtensions`, so nothing is lost meanwhile.
- **CONFIG / SYSTEM / etc.** currently land in the `PaloAlto` catch-all with the raw extension preserved; promote any of them to a dedicated table by copying the TRAFFIC pattern.
- **Timestamps:** `StartTime` / `ReceiptTime` are stored as strings because PAN's `Mon dd yyyy HH:mm:ss GMT` format isn't `todatetime`-parseable. `TimeGenerated` (real datetime) is the column to query on.

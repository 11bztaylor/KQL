# Palo Alto CEF fan-out — testing runbook

Files in this repo:

| File | Purpose |
|------|---------|
| [`../paloalto/deploy/PaloAlto_CEF.kql`](../paloalto/deploy/PaloAlto_CEF.kql) | The deployable KQL: parser functions, tables, and update policies. |
| [`../paloalto/tests/PaloAlto_tests.kql`](../paloalto/tests/PaloAlto_tests.kql) | Parser characterization tests — mirror the deployed routing/header parse on samples; assert fields + the non-PA-excluded invariant. |
| [`../paloalto/enrichment/enrichment.kql`](../paloalto/enrichment/enrichment.kql) | Query-time enrichment views (geo, labels, scope, reason descriptions, decoded flags). |
| [`../paloalto/ops/validation.kql`](../paloalto/ops/validation.kql) | Post-deployment monitoring: reconciliation, freshness, catch-all breakdown, parse health, drift check, backfill. |
| [`../paloalto/backfill/SIDEQUEST.kql`](../paloalto/backfill/SIDEQUEST.kql) | One-off historical THREAT backfill from CommonSecurityLog. |

---

## Step 1 — Test the parser logic (no deployment, zero risk)

The production parser (`PaloAlto_CEF_Parsed`) is a **pure** function that reads `Syslog`
directly — the standard ADX update-policy pattern. A pure parser can't be fed synthetic rows,
so `PaloAlto_tests.kql` is a **characterization test**: it mirrors the deployed routing + `|`
header parse on sample messages and spot-checks field extraction. It deploys nothing.

1. Open `PaloAlto_tests.kql`, paste it into an ADX/Kusto query window, run it. Two tables:
   - **A) Field assertions** — 4 rows, every `Passed == true`, every `Details` empty
     (keyed by `DeviceVersion`: `13.5.60-h10`, `10.1.10-i11`, `10.1.10-h10`, `10.1.11-h5`).
   - **B) Invariant check** — `Passed == true`: the non-Palo-Alto (Cisco) row is dropped and
     exactly the 4 Palo Alto rows survive across 3 log types.
2. If a field assertion fails, `Details` names the field(s) that didn't match. If you change
   the header layout or routing in `PaloAlto_CEF.kql`, update the mirror in the test.

### Full-fidelity option (true end-to-end)

To exercise the *actual* deployed functions, use a **scratch database** (never prod — seeding
`Syslog` fires the update policies and routes the rows into the real tables):

1. Deploy `PaloAlto_CEF.kql` in the scratch DB.
2. `.set-or-append Syslog <| <the sample messages from PaloAlto_tests.kql>`
3. Query `PaloAlto_CEF_Parsed()` / `PaloAlto_Traffic_parse()` / etc. and compare.

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

- **Threat subtypes:** validated against the `url` subtype. Other subtypes (`virus`, `wildfire`, `vulnerability`, `file`) may carry a few extra `PanOS*` keys. If you see odd nulls in `PaloAlto_Threat`, grab one of those samples — the fix is to declare the new key(s) in `PaloAlto_CEF_Parsed()`. Any field not promoted to a column is kept in the `UnparsedFields` dynamic bag, so nothing is lost meanwhile.
- **CONFIG / SYSTEM / etc.** currently land in the `PaloAlto` catch-all with the raw extension preserved; promote any of them to a dedicated table by copying the TRAFFIC pattern.
- **Timestamps:** `StartTime` / `ReceiptTime` are stored as strings because PAN's `Mon dd yyyy HH:mm:ss GMT` format isn't `todatetime`-parseable. `TimeGenerated` (real datetime) is the column to query on.

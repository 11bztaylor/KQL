# Palo Alto CEF → per-log-type tables (ADX / Kusto)

Fans the raw `Syslog` CEF stream from **Palo Alto Networks (PAN-OS)** firewalls out into
vendor- and log-type-specific tables, using Azure Data Explorer **update policies**. The
Data Collection Rule keeps landing raw syslog in `Syslog`; ADX does the parsing and routing.

## Tables produced

| Table | Receives | Status |
|-------|----------|--------|
| `PaloAlto_Traffic` | PAN-OS `TRAFFIC` logs | ✅ validated against real samples (PAN-OS 13.5 + 10.1) |
| `PaloAlto_Threat` | PAN-OS `THREAT` logs (`url`/`virus`/`spyware`/`wildfire`/`file`/…) | ✅ validated against a real `url` sample |
| `PaloAlto_UserID` | PAN-OS `USERID` logs (user-to-IP mapping) | ✅ validated against a real `login` sample |
| `PaloAlto` | every other `$type` — `CONFIG`, `SYSTEM`, `HIPMATCH`, `GLOBALPROTECT`, … | ✅ no-drop catch-all |

Routing is exhaustive and mutually exclusive, so every Palo Alto record lands in exactly
one table and nothing is silently dropped.

## Files

| File | What it is |
|------|------------|
| [`PaloAlto_CEF.kql`](paloalto/deploy/PaloAlto_CEF.kql) | **The deployable KQL** — base parser, per-table projection functions, `.create table`, and update policies. |
| [`PaloAlto_tests.kql`](paloalto/tests/PaloAlto_tests.kql) | Parser tests. Feed synthetic CEF rows into the **real** `PaloAlto_CEF_ParseRows` function (no duplicated logic), assert field values, and check the non-Palo-Alto-excluded invariant. Touches no tables. |
| [`enrichment.kql`](paloalto/enrichment/enrichment.kql) | Query-time enrichment: GeoIP, severity/direction/action labels, internal/external scope, session-end-reason descriptions, decoded session flags. Raw tables stay untouched. |
| [`validation.kql`](paloalto/ops/validation.kql) | Post-deployment reconciliation, freshness, catch-all breakdown, parse-health, and backfill queries. |
| [`TESTING.md`](docs/TESTING.md) | Deploy → test → verify → backfill runbook. |
| [`SIDEQUEST.kql`](paloalto/backfill/SIDEQUEST.kql) | One-off historical backfill: maps a CommonSecurityLog-shaped Search Job table (Palo Alto THREAT only) into `PaloAlto_Threat`, tagged and reversible. |
| [`shared/shared.kql`](shared/shared.kql) | Vendor-agnostic helpers: `Shared_HexToLong`, `Shared_SeverityLabel`, `Shared_Direction`, `Shared_IpScope`. Deploy **before** enrichment. |

## Repository layout

Organized product-first (like Microsoft's Sentinel `Solutions/` layout) so each new vendor
drops in as its own folder. KQL functions resolve by **name**, not path, so this structure is
purely organizational — it doesn't affect deployment or cross-references.

```
README.md
docs/TESTING.md
paloalto/
  deploy/PaloAlto_CEF.kql        functions + tables + update policies (one ordered file)
  enrichment/enrichment.kql      query-time enrichment views
  tests/PaloAlto_tests.kql       parser tests
  ops/validation.kql             monitoring / reconciliation / drift / backfill
  backfill/SIDEQUEST.kql         one-off historical THREAT backfill
shared/shared.kql                vendor-agnostic helpers (hex, severity, direction, ip-scope)
```

## How it works

PAN-OS CEF arrives (the `CEF:` token is stripped upstream), e.g.:

```
0|Palo Alto Networks|PAN-OS|13.5.60-h10|drop|TRAFFIC|1|rt=Jun 15 2026 14:58:03 GMT src=10.20.30.40 dst=203.0.113.45 ...
```

The header is positional after splitting on `|`:

| Index | Field |
|-------|-------|
| `_p[1]` | DeviceVendor — always `Palo Alto Networks` (the routing key) |
| `_p[2]` | DeviceProduct — `PAN-OS` |
| `_p[3]` | DeviceVersion |
| `_p[4]` | `$subtype` (`drop`/`start`/`url`/…) |
| `_p[5]` | `$type` (`TRAFFIC`/`THREAT`/…) — **the value tables are split on** |
| `_p[6]` | Severity |

Routing is keyed off the parsed vendor + `$type`, **not** `ProcessName` — production
messages don't carry the `CEF:` token, and AMA ≥1.41 no longer guarantees `CEF` appears in
`ProcessName`.

A shared `PaloAlto_CEF_Parsed()` function splits the header and runs `parse-kv` in greedy
mode (so values with spaces parse correctly). Greedy mode requires **every** key in the
message to be declared, so all observed `PanOS*`/`Pan*` keys are declared to keep value
boundaries correct.

### Custom-profile field mapping

The `cs*`/`cn*`/`flex*` meanings come from this firewall's custom syslog profile:

| CEF field | Meaning |
|-----------|---------|
| `cs1` | Rule |
| `cs2` | URL Category |
| `cs4` | Source Zone |
| `cs5` | Destination Zone |
| `cs6` | LogProfile |
| `cn1` | SessionID |
| `cn2` | Packets |
| `cn3` | Elapsed time (s) |
| `flexString1` | Flags |
| `flexString2` | Direction |
| `flexNumber1` | Total bytes |
| `externalId` | Sequence Number |

These column names come from each field's `…Label` companion (per the CEF spec, `csNLabel`
*"describes the purpose of the custom field"*). Because ADX column names are fixed schema, the
mapping is baked in from the observed labels rather than generated per-row — `validation.kql`
includes a drift check that flags any record whose labels stop matching.

Every CEF key that **isn't** promoted to a typed column is kept in a `dynamic` column,
`UnparsedFields`, built with `pack_all(true)` (so null/empty keys are dropped) minus the keys
already exposed as columns. No duplication, and nothing is lost — and any unmapped custom field
keeps both its `csN` value and `csNLabel` name, so it stays self-describing.

## Quick start

```bash
git clone https://github.com/11bztaylor/KQL.git
cd KQL
```

1. **Test the parser** (no deployment, zero risk): run [`PaloAlto_tests.kql`](paloalto/tests/PaloAlto_tests.kql) — expect 4 rows, all `Passed = true`.
2. **Deploy**: run [`PaloAlto_CEF.kql`](paloalto/deploy/PaloAlto_CEF.kql) top-to-bottom on your ADX database.
3. **Verify**: once live data flows, run the reconciliation query in [`validation.kql`](paloalto/ops/validation.kql).

See [`TESTING.md`](docs/TESTING.md) for the full runbook, including backfilling existing `Syslog`
data (update policies are forward-only).

## Notes

- `IsTransactional: false` on every update policy is deliberate — `Syslog` is shared across
  vendors, so a Palo Alto parse error must never block ingestion of the whole table.
- `StartTime` / `ReceiptTime` are kept as strings (PAN's `Mon dd yyyy HH:mm:ss GMT` format
  isn't `todatetime`-parseable); query on `TimeGenerated`.
- THREAT was validated on the `url` subtype; other subtypes may add a key or two, which
  belong in `PaloAlto_CEF_Parsed()`. Nothing is lost meanwhile thanks to `UnparsedFields`.
- This is the standard pattern: Microsoft's own ADX firewall-monitoring guidance uses
  raw-table + update-policy + parse-function, and Sentinel **ASIM** parsers split a shared
  table per log type the same way. We keep PAN-native field names (not the ASIM cross-vendor
  schema) to preserve fidelity for long-term storage.

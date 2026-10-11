# Test 07 — Configuration Backup & Recovery
### Project 10 — Cloudflare Edge Security · ransomware-resilience, edge/config form

## Objective
Prove the security configuration can be recovered from an off-platform backup
after a destructive change — the "recover without paying ransom" loop — adapted to
an edge layer whose data-plane is stateless.

## Why config, not data
Cloudflare's edge holds no customer data (the origin does; here that origin is a
disposable Docker container). So the asset that must survive a destructive event is
the **configuration** — specifically the WAF rule that enforces security. That is
what we back up, destroy, and restore.

## The recovery loop (proven)
| # | Step | Result | Evidence |
|---|---|---|---|
| 7A | Back up config off-platform (DNS zone export + WAF rule JSON) | `anyaugo-drs.com.txt` + `waf-rule-backup.json` | Test-7A-dns-export.png |
| 7B | Verify backup integrity (SHA-256) | `10155D68…3032E3` matched | Test-7B-backup-sha256.png |
| 7C | Destructive event — delete `Block-SQLi-Patterns` | rule gone (0/5) | Test-7C-rule-deleted.png |
| 7D | Verify breach — SQLi via edge | **not 403** → `500` at origin | Test-7D-1 / 7D-2 / 7D-3 |
| 7E | Restore rule from backup | rule recreated, Active | Test-7E-rule-restored.png |
| 7F | Verify recovery — SQLi via edge | **403 blocked again** | Test-7F-sqli-blocked-after-restore.png |

With the rule removed and then restored, the same request flips from **500 (reaches
the origin)** back to **403 (blocked at the edge)** — the configuration was recovered
from the off-platform backup, no ransom.

## The breach finding, stated precisely
When the rule was deleted, the malicious request was **no longer blocked at the edge
(403) and reached the origin**, which returned a **database error (500)**. The origin's
own error page — *"OWASP Juice Shop (Express) … 500 Error: `SQLITE_ERROR: incomplete
input`"* — confirms the input was **not sanitised before reaching the database: an
error-based SQL-injection indicator.**

Honest calibration (what this is / is not):
- It **is** proof that unsanitised input reached the database and broke the query.
- It is **not** a demonstrated data-extraction or authentication bypass — those would
  return `200` with unauthorised data. The `' OR 1=1--` payload produced a syntax
  error, i.e. **error-based behaviour**, not a clean bypass.
- The `500` came from the **origin (Juice Shop / Express)**, not from Cloudflare — it
  is visibly a different page from Cloudflare's "you have been blocked" (403) page.
  Cloudflare was simply out of the path once the rule was deleted.

## The second recovery loop — DNS record (proven)
The same recover-from-backup discipline was proven on a different asset: the DNS
record that routes the subdomain to the tunnel.

| # | Step | Result | Evidence |
|---|---|---|---|
| 7G | Destructive event — delete the `juice` DNS record | site **unreachable** — `curl: (6) Could not resolve host` | Test-7G-dns-breach-juice-unreachable.png |
| 7H | Restore the record from backup (`cloudflared tunnel route dns`) | CNAME re-added → tunnel `cdc7d2e1…` | Test-7H-dns-record-restored.png |
| 7I | Verify recovery — request via the edge | **HTTP/2 200** through Cloudflare (HSTS header present) | Test-7I-juice-reachable-again.png |

Deleting the DNS record takes the service fully off the internet — DNS no longer
resolves (`Could not resolve host`). Restoring it from the documented backup brings
it straight back: `HTTP/2 200`, `server: cloudflare`, `cf-ray` present, with the
HSTS policy still enforced. A second, independent proof of the
recover-without-ransom loop — this time at the DNS layer, not the WAF rule.

## Honest boundaries
- Proves the **recovery loop + an off-platform, integrity-verified backup**. It is
  **config disaster recovery**, not a true immutable/air-gapped vault — the backup
  lives on the same machine.
- **True WORM immutability** (AWS S3 Object Lock in a separate account) is built in the
  AWS project. The origin (Juice Shop) is deliberately disposable, so no customer data
  is at stake here — the control plane (the WAF rule) is the recovered asset.

## Scope
All testing performed against infrastructure I own and control, in an isolated lab
environment.

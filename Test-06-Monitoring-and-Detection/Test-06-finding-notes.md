# Test 06 — Monitoring & Detection
### Project 10 — Cloudflare Edge Security · the SOC / blue-team half

## Objective
Prove the detection loop: when the edge blocks an attack, that event is
**collected**, a **detection rule** matches it, and an **alert** is raised — the
core function of a SIEM.

## The pipeline (lightweight, free-tier)
```
Cloudflare WAF blocks the SQLi
  → cf-waf-detector.py polls Cloudflare's GraphQL firewallEventsAdaptive API
    (free tier has no Logpush, so we pull events on an interval)
  → a detection rule flags Action=block carrying SQL-injection signatures
  → an ALERT is raised with the source, rule, path and payload
```
- **Tool:** `cf-waf-detector.py` (stdlib Python; token + zone id read from env vars,
  so no secret is in the file).
- **Roles kept separate:** the detector runs on the **host (defender/SOC)**; the
  attack is fired from **Kali (attacker)**.

## Evidence
- `Test-6-detector-sqli-alert.png` — the detector raises
  **`ALERT [SQL-INJECTION]`**: `action: block (detected by: firewallCustom)`,
  rule `2dec376c…adc8` (the **Block-SQLi-Patterns** custom rule), host
  `juice.anyaugo-drs.com`, path `/rest/products/search`, query `?q=%27+OR+1%3d1--`,
  UA `curl/…`. The **source IP is auto-masked** (`102.90.x.x`) by the detector.

## What this demonstrates
The blue-team skill: **log collection → detection rule → alert**, against a real
provider API, with the output **self-redacting** sensitive data (the senior
data-handling signal). The attack is detected within one poll interval of being
blocked at the edge.

## Honest boundaries (stated plainly, as the report will)
- **Lightweight by choice.** This is a purpose-built detector, not a full SIEM. It
  was chosen deliberately: the host is resource-constrained, and standing up a heavy
  Wazuh server locally (and tearing it down) was not justified here.
- **Full classical Wazuh lands at the AWS project.** That is where a cloud VM has the
  resources to run the Wazuh manager + indexer + dashboard and the agent — the
  "Wazuh where you control real compute" split from the portfolio plan.
- **Free tier → pull, not push.** Cloudflare's free plan has no Logpush, so the
  detector **polls** the GraphQL API on an interval (short ingestion lag). On a paid
  plan, Logpush would stream events to the SIEM in near-real-time.

## Scope
All testing performed against infrastructure I own and control, in an isolated lab
environment.

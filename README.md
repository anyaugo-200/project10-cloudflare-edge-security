# Project 10 — Cloudflare Edge Security

### Anyaugo Space-Tech Ltd. · Security Training | Lab Evidence

**Put a vulnerable web app behind Cloudflare's free edge, attack it from a separate attacker box, and prove the edge stops what the bare origin cannot — then watch the blocks in a detector, and restore the security configuration from an off-platform backup after it is wiped.** The engagement is run as two roles a company pays for: the **edge architect** (the design, before the build) and the **security engineer** (deploy, attack, defend, monitor, recover). Everything runs on infrastructure the agency owns, against a disposable target, using only synthetic data — no client systems, no production data.

---

## The business question
> A company exposes a web app to the internet. **Can a free CDN/WAF edge stop real attacks before they reach the server, hide the origin so it cannot be bypassed, and can the security configuration be recovered after a destructive change — without paying a ransom?**

## The verified result
**Yes — within the honest limits of the free tier.** A SQL-injection the bare origin happily processes is **blocked at the edge (`HTTP 403`)** by a custom WAF rule, and **Cloudflare's own log confirms the block**; a lightweight detector pulls that event and **raises an alert**. The origin is reached **only through a Cloudflare Tunnel, so it has no public IP** — the WAF cannot be bypassed by hitting the server directly. When the WAF rule is deleted, the same request **reaches the origin and trips a database error (`500`)** — proof the control was doing real work — and the rule is then **restored from an off-platform backup**, flipping the request back to `403`, no ransom. One result is stated as plainly as the wins: **the app's DOM-based XSS cannot be blocked by any WAF**, because the payload lives in the URL fragment the browser never sends to the server — that needs a code-level fix, not an edge rule. Knowing what a WAF is and is not for **is** the finding.

## The report
**[Project 10 — Cloudflare Edge Security — Unified Evidence Portfolio (PDF)](Test-08-Final-Report/Project%2010%20-%20Cloudflare%20Edge%20Security%20-%20Unified%20Evidence%20Portfolio.pdf)** — the cover, the secure-edge architecture, each stage of the build, the before/after attack proof, the monitoring loop, the backup-and-recovery loop, and the evidence limits. Start with the cover and the before/after sections.

---

## How to read the evidence
Each stage is a `Test-NN` folder of self-describing screenshots named by letter (`Test-2A`, `Test-2B`…); every finding stage has a plain-language `Test-NN-finding-notes.md` written record.

| Test | Stage | What it establishes |
|---|---|---|
| [01](Test-01-Scope-Authorization-and-Architecture/) | Scope, Authorization & Architecture | Rules of engagement, Cloudflare's **own-asset testing policy**, and the secure-edge **design** — all fixed before the build |
| [02](Test-02-Target-and-Secure-Origin/) | Target & Secure Origin | Juice Shop served through a **Cloudflare Tunnel — no public origin IP**; edge hardened with visitor **TLS** (Always-HTTPS, HSTS, min TLS 1.2) |
| [03](Test-03-Baseline-Attack-Exposed/) | Baseline Attack (Exposed) | Against the bare origin, **SQLi login bypass** and **DOM XSS** both succeed |
| [04](Test-04-Edge-Defense-Deployed/) | Edge Defense Deployed | One fully-understood custom WAF rule, **`Block-SQLi-Patterns`** (url-decode + lowercase to defeat encoding/case evasion) |
| [05](Test-05-Attack-Blocked-and-Tuned/) | Attack Blocked & Tuned | The same SQLi is now **`403` at the edge**, normal traffic unaffected (`200`), and the block is **logged as a Security Event** |
| [06](Test-06-Monitoring-and-Detection/) | Monitoring & Detection | A detector polls Cloudflare's GraphQL firewall-events API → **alerts** on block events, with the source IP **self-masked** |
| [07](Test-07-Configuration-Backup-and-Recovery/) | Configuration Backup & Recovery | WAF rule + DNS backed up off-platform, destroyed, and **restored** — the recover-without-ransom loop, in edge/config form |
| [08](Test-08-Final-Report/) | Final Report | The unified PDF deliverable |
| [09](Test-09-Privacy-and-Responsible-Use/) | Privacy & Responsible Use | Responsible handling of evidence and AI-assisted work (standalone record page) |

## What the engagement proved
- **The edge stops server-visible attacks.** `?q=' OR 1=1--` → **`403` blocked** through Cloudflare, **`200`** for a normal search, and the bare origin processes the same payload with no WAF — the clean before/after.
- **The origin cannot be bypassed.** The Cloudflare Tunnel gives the origin **no public IP**, so an attacker cannot route around the WAF by hitting the server directly.
- **Blocks are detectable.** Cloudflare's Security Event log and a self-redacting detector turn each block into a SOC-grade **alert** (log → detection rule → alert).
- **The control is recoverable.** The WAF rule and DNS are restored from an integrity-verified off-platform backup after deletion; the request flips `500 → 403` again.
- **Evasion is handled.** The rule **URL-decodes and lowercases** the query first, so `%27`/case tricks don't slip past it.

## Findings & honest limits (stated plainly, not papered over)
| # | Finding / limit | What it means | Status |
|---|---|---|---|
| P10-F1 | **DOM-based XSS is not WAF-blockable** | The search-XSS payload lives in the URL **fragment** (`#/search?q=…`), which browsers never send to the server, so no edge WAF ever sees it | **Documented** — fix is code-level output encoding, not an edge rule |
| P10-L1 | **Free-tier WAF scope** | Free gives zone **custom rules** (5), **one** rate-limit rule, and the **Free Managed Ruleset** only; full Managed/OWASP Core Ruleset, WAF-attack-score and **request-body inspection** are Pro-gated | **Documented residual** — body-based SQLi (e.g. the Test-03 login bypass) needs Pro body inspection |
| P10-L2 | **Error-based ≠ clean exploit** | With the rule removed, the SQLi returns **`500 SQLITE_ERROR` from the origin**, an injection **indicator** — unsanitised input reached the DB — **not** a `200`+data extraction or auth bypass | **Calibrated** — the `500` is the origin erroring, not Cloudflare blocking |

## The platform
**Cloudflare** free tier on the agency-owned domain **`anyaugo-drs.com`**. The origin is **OWASP Juice Shop** (Docker on the Windows host), reached only via a **Cloudflare Tunnel** (`cloudflared`) — outbound-only, no port-forward, no public origin IP. The attacker is a **Kali VM**. The edge enforces a custom WAF rule and visitor-facing TLS (Always-HTTPS, HSTS, min TLS 1.2). The target is deliberately vulnerable and disposable, so the point is not to find its bugs but to **prove the edge defense, monitoring, and recovery around it**. Every record is synthetic (`admin@juice-sh.op`); no real customers, credentials, or production data are involved.

## Tool stack (free / open-source — the real industry stack)
| Used here | Commercial / enterprise equivalents |
|---|---|
| **Cloudflare** WAF custom rules + Tunnel + TLS (edge security) | Akamai, AWS WAF + CloudFront, Imperva |
| **Cloudflare GraphQL Analytics API** + `cf-waf-detector.py` (detection) | Splunk, Datadog, Cloudflare Logpush → SIEM (full **Wazuh** arrives at the AWS project) |
| **OWASP Juice Shop** (Docker) — the target | any internal web app behind the edge |
| `curl` from **Kali** — attack delivery | Burp Suite, sqlmap |
| WAF-rule JSON + DNS export + SHA-256 — config backup / DR | Terraform state, commercial config-backup suites |
| **OWASP Top 10**, **Cloudflare scans & penetration-testing policy** (frameworks) | — |

## Boundary & honesty note
This is a **controlled training-lab portfolio**, not a client assessment or a legal opinion. No client authorization is claimed; all work was done on a Cloudflare zone, domain, and origin the agency owns, on invented data, under **Cloudflare's own policy that permits testing your own assets**. Observed lab results are kept separate from **proposed** client practice, and recommendations are marked as proposed, not completed work. The limits above are stated plainly rather than hidden: the free tier inspects the query string (not request bodies), the detector is a purpose-built poller rather than a full SIEM, and the backup proves the recovery loop but is not yet a true immutable vault (that is the AWS project). See the PDF's *Assurance Boundaries* section for exactly what is and is not established.

---

*References: OWASP Top 10 · Cloudflare Scans & Penetration Testing policy · NIST SP 800-115. Prepared by Anyaugo Space-Tech Ltd., Security Training track.*

*© 2026 Anyaugo Space-Tech Ltd. Licensed under [CC BY-NC-ND 4.0](LICENSE) — share with attribution; no commercial use or derivatives.*

# Test 05 — Attack Blocked & Verified
### Project 10 — Cloudflare Edge Security · the before/after proof

## Objective
Prove that the Cloudflare edge WAF stops a real attack that succeeds against the
bare origin — without breaking legitimate traffic — and that Cloudflare's own log
confirms it.

## The control deployed (Test 04)
A single, fully-understood **custom WAF rule**, `Block-SQLi-Patterns` (Action: Block):

```
lower(url_decode(http.request.uri.query)) contains "union select"
  or lower(url_decode(http.request.uri.query)) contains "' or 1=1"
  or lower(url_decode(http.request.uri.query)) contains "'--"
  or lower(url_decode(http.request.uri.query)) contains "sleep("
```

It blocks requests whose URL query — after **URL-decoding** (defeats `%`-encoding
evasion) and **lowercasing** (defeats case evasion) — contains common SQL-injection
signatures, at the edge, before they reach the origin.

## The before / after (all from Kali, the attacker)
| # | Request | Result | Evidence |
|---|---|---|---|
| 5A | Normal search via edge — `GET /rest/products/search?q=apple` | **HTTP 200** (unaffected) | Test-5A-normal-search-allowed.png |
| 5B | SQLi via edge — `?q=' OR 1=1--` | **HTTP 403 — BLOCKED** | Test-5B-sqli-blocked-403.png |
| 5C | Same SQLi at the direct origin (`192.168.1.116:3000`) | not 403 (app processes it; no WAF) | Test-5C-sqli-reaches-origin-no-waf.png |
| 5D | Cloudflare Security Event for 5B | Action **Block**, Rule **Block-SQLi-Patterns** | Test-5D-cloudflare-security-event-blocked.png |

The Security Event (5D) shows the full request Cloudflare stopped: Host
`juice.anyaugo-drs.com`, Path `/rest/products/search`, Query `?q=%27+OR+1%3d1--`,
User-Agent `curl/…` — matched by the custom rule. That contrast — **succeeds at the
origin, blocked at the edge** — is the finding.

## Honest boundaries (stated plainly, as the report will)
- **Free-tier scope.** Cloudflare's free plan gives zone-level **custom rules** (5),
  **one** rate-limiting rule, and the **Free Managed Ruleset** (Log4j/Shellshock-class)
  only. The full **Cloudflare Managed Ruleset / OWASP Core Ruleset / WAF-attack-score /
  request-body inspection** are **Pro-gated** — documented, not claimed.
- **Query vs body.** This rule inspects the **query string**, so it catches
  query-based SQLi. A SQLi buried in a JSON **request body** (like the Test-03 login
  bypass) needs Pro **body inspection** — out of scope on free.
- **The DOM XSS cannot be WAF-blocked — and that is the lesson.** Juice Shop's search
  XSS lives in the URL **fragment** (`#/search?q=…`), which browsers **never send to
  the server**, so Cloudflare never sees it. No WAF can block a purely client-side
  (DOM) vulnerability; the fix is **code-level output encoding**, not an edge rule.
  A WAF protects the *server* edge — knowing what it is and isn't for is the point.
- **Origin hidden by design.** The Cloudflare Tunnel means the origin has **no public
  IP**, so the WAF cannot be bypassed by hitting the origin directly from the internet.

## Scope
All testing performed against infrastructure I own and control, in an isolated lab
environment.

#!/usr/bin/env python3
# Project 10 - Cloudflare Edge Security | Test 06 - Monitoring & Detection
# Lightweight WAF-event detector: polls Cloudflare's GraphQL firewall-events API
# (firewallEventsAdaptive), applies a detection rule, and raises an ALERT on
# blocked attacks (SQL injection). This is the SOC/detection half of the project:
#   collect (API)  ->  detect (rule)  ->  alert.
#
# Secrets: reads CF_API_TOKEN and CF_ZONE_ID from environment variables, so the
# token never sits in this file or in any screenshot.
# Privacy: source IP, ASN and geo are masked for safe portfolio sharing -
# an internal SOC analyst would see the full detail; the mask is for the report only.

import os, sys, json, time, urllib.request
from datetime import datetime, timedelta, timezone

TOKEN = os.environ.get("CF_API_TOKEN")
ZONE  = os.environ.get("CF_ZONE_ID")
if not TOKEN or not ZONE:
    print("ERROR: set CF_API_TOKEN and CF_ZONE_ID environment variables first.")
    sys.exit(1)

GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"
POLL_SECONDS = 10
LOOKBACK_MIN = 15

QUERY = """
query($zone:String!, $since:Time!) {
  viewer { zones(filter:{zoneTag:$zone}) {
    firewallEventsAdaptive(filter:{datetime_gt:$since}, limit:50, orderBy:[datetime_DESC]) {
      datetime action source ruleId
      clientIP clientASNDescription clientCountryName
      clientRequestHTTPHost clientRequestPath clientRequestQuery userAgent
    }
  } }
}
"""

SQLI_SIGS = ["union select", "' or 1=1", "'--", "sleep(", "%27", "1%3d1", "1=1"]

def mask_ip(ip):
    p = str(ip).split(".")
    return f"{p[0]}.{p[1]}.x.x" if len(p) == 4 else "[ip masked]"

def classify(ev):
    blob = (str(ev.get("clientRequestQuery","")) + " " + str(ev.get("clientRequestPath",""))).lower()
    return "SQL-INJECTION" if any(s in blob for s in SQLI_SIGS) else "WAF-BLOCK"

def query(since):
    body = json.dumps({"query": QUERY, "variables": {"zone": ZONE, "since": since}}).encode()
    req = urllib.request.Request(GRAPHQL, data=body, headers={
        "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def main():
    print("=" * 66)
    print(" CF-WAF-DETECTOR  |  Project 10 - Monitoring & Detection")
    print(" source : Cloudflare GraphQL firewallEventsAdaptive  (zone %s...)" % ZONE[:8])
    print(" rule   : ALERT on Action=block carrying SQL-injection signatures")
    print(" privacy: source IP / ASN / geo masked for safe sharing")
    print("=" * 66)
    seen = set()
    while True:
        since = (datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MIN)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            data = query(since)
            if data.get("errors"):
                print("  API error:", json.dumps(data["errors"])); time.sleep(POLL_SECONDS); continue
            zones = data["data"]["viewer"]["zones"]
            events = zones[0]["firewallEventsAdaptive"] if zones else []
            blocks = [e for e in events if e.get("action") == "block"]
            fresh = []
            for e in blocks:
                key = f'{e["datetime"]}|{e.get("ruleId")}|{e.get("clientRequestQuery")}'
                if key not in seen:
                    seen.add(key); fresh.append(e)
            for e in reversed(fresh):
                sev = classify(e)
                print("\n" + "!" * 66)
                print(f"  ALERT  [{sev}]   {e['datetime']}")
                print(f"  action : {e['action']}   (detected by: {e.get('source')})")
                print(f"  rule   : {e.get('ruleId')}")
                print(f"  src IP : {mask_ip(e.get('clientIP'))}   (origin ASN/geo redacted for sharing)")
                print(f"  host   : {e.get('clientRequestHTTPHost')}")
                print(f"  path   : {e.get('clientRequestPath')}")
                print(f"  query  : {e.get('clientRequestQuery')}")
                print(f"  ua     : {e.get('userAgent')}")
                print("!" * 66)
            if not fresh:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] watching... no new block events")
        except Exception as ex:
            print("  poll error:", ex)
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()

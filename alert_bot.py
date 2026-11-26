#!/usr/bin/env python3
"""
Cyber Alert Bot
---------------
Watches zero-day / critical vulnerability / patch / outage sources and pushes
alerts to Telegram, WhatsApp (Meta Cloud API or Twilio) and/or Microsoft Teams.

Sources:
  * CISA KEV (actively exploited vulnerabilities = zero-days in the wild)
  * NVD API 2.0 (new CRITICAL CVEs, patch / advisory links)
  * RSS: security news, vendor PSIRT / patch feeds, cloud status pages

Usage:
  python alert_bot.py                 # normal run (call every few minutes)
  python alert_bot.py --dry-run       # print alerts, send nothing, save nothing
  python alert_bot.py --seed          # mark everything current as "seen" (no alerts)
  python alert_bot.py --test-message  # send one test message to check delivery
"""
import argparse
import calendar
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import time

import feedparser
import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT, "config.json")
STATE_PATH = os.path.join(ROOT, "state", "seen.json")
UA = "Mozilla/5.0 (cyber-alert-bot; +https://github.com)"
HTTP_TIMEOUT = 25
STATE_RETENTION_DAYS = 30  # every source is limited to <= 7 days old, so this is safe


# --------------------------------------------------------------------------- utils
def log(*a):
    print(f"[{dt.datetime.utcnow():%Y-%m-%d %H:%M:%S}Z]", *a, flush=True)


def load_dotenv(path=os.path.join(ROOT, ".env")):
    """Tiny .env loader (for cron/VPS use). Real env vars take precedence."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env(name, default=""):
    # Unset GitHub secrets arrive as empty strings, so treat "" as "not set".
    return os.environ.get(name, "").strip() or default


def clean(text, limit=None):
    text = re.sub(r"<[^>]+>", " ", text or "")          # strip HTML
    text = re.sub(r"&nbsp;|&#160;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"\s+", " ", text).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def contains_any(text, words, ignore_case=True):
    """Whole-word match (so 'RCE' doesn't match 'source'). Vendor names use exact case
    so 'iOS' doesn't match Cisco 'IOS XE'."""
    t = text or ""
    flags = re.I if ignore_case else 0
    return [w for w in words
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(w) + r"(?![A-Za-z0-9])", t, flags)]


def http_get(url, **kw):
    headers = kw.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, **kw)
    r.raise_for_status()
    return r


class Alert:
    def __init__(self, uid, category, title, summary="", link="", patch="", urgent=False, source=""):
        self.uid, self.category, self.title = uid, category, title
        self.summary, self.link, self.patch = summary, link, patch
        self.urgent, self.source = urgent, source

    ICONS = {"ZERO-DAY": "🚨", "CRITICAL CVE": "🔴", "PATCH": "🩹", "NEWS": "📰", "OUTAGE": "⚠️"}

    def full_text(self):
        lines = [f"{self.ICONS.get(self.category, '🔔')} *{self.category}*  ({self.source})",
                 f"*{self.title}*"]
        if self.summary:
            lines.append(clean(self.summary, 450))
        if self.patch:
            lines.append(f"🩹 Fix: {clean(self.patch, 300)}")
        if self.link:
            lines.append(f"🔗 {self.link}")
        return "\n".join(lines)

    def short_line(self):
        return f"{self.ICONS.get(self.category, '•')} {clean(self.title, 140)} {self.link}".strip()


# --------------------------------------------------------------------------- state
def load_state():
    if not os.path.exists(STATE_PATH):
        return None
    with open(STATE_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    cutoff = time.time() - STATE_RETENTION_DAYS * 86400
    state["seen"] = {k: v for k, v in state["seen"].items() if v >= cutoff}
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=0, sort_keys=True)


# --------------------------------------------------------------------------- sources
def src_cisa_kev(cfg):
    """CISA Known Exploited Vulnerabilities = confirmed exploitation in the wild."""
    c = cfg["sources"]["cisa_kev"]
    if not c.get("enabled", True):
        return []
    data = http_get(c["url"]).json()
    cutoff = dt.date.today() - dt.timedelta(days=c.get("max_age_days", 7))
    out = []
    for v in data.get("vulnerabilities", []):
        try:
            added = dt.date.fromisoformat(v.get("dateAdded", "1970-01-01"))
        except ValueError:
            continue
        if added < cutoff:
            continue
        product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        ransomware = " | Used in ransomware" if v.get("knownRansomwareCampaignUse") == "Known" else ""
        notes_links = [p.strip() for p in (v.get("notes") or "").split(";") if p.strip().startswith("http")]
        patch = v.get("requiredAction", "")
        if notes_links:
            patch += f" {notes_links[0]}"
        out.append(Alert(
            uid=f"kev:{v['cveID']}",
            category="ZERO-DAY",
            title=f"{v['cveID']} – {product}: {v.get('vulnerabilityName', '')}",
            summary=f"{v.get('shortDescription', '')} (Added to KEV {v.get('dateAdded')}, "
                    f"federal due date {v.get('dueDate')}{ransomware})",
            link=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            patch=patch,
            urgent=True,
            source="CISA KEV",
        ))
    return out


def src_nvd(cfg, vendors):
    """New CRITICAL CVEs from NVD (CVSS v3 and v4), with patch/advisory links."""
    c = cfg["sources"]["nvd"]
    if not c.get("enabled", True):
        return []
    now = dt.datetime.utcnow()
    start = now - dt.timedelta(hours=c.get("lookback_hours", 24))
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers = {}
    if env("NVD_API_KEY"):
        headers["apiKey"] = env("NVD_API_KEY")
    vulns = {}
    for sev_param in ("cvssV3Severity", "cvssV4Severity"):
        params = {"pubStartDate": start.strftime(fmt), "pubEndDate": now.strftime(fmt),
                  sev_param: "CRITICAL", "resultsPerPage": 200}
        try:
            data = http_get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=params, headers=headers).json()
        except Exception as e:  # NVD is often slow/rate-limited; don't kill the run
            log(f"NVD ({sev_param}) failed: {e}")
            continue
        for item in data.get("vulnerabilities", []):
            vulns[item["cve"]["id"]] = item["cve"]
        if not env("NVD_API_KEY"):
            time.sleep(6)  # public rate limit: 5 requests / 30 s

    out = []
    for cve_id, cve in vulns.items():
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score = ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            m = cve.get("metrics", {}).get(key)
            if m:
                score = f"CVSS {m[0]['cvssData'].get('baseScore')}"
                break
        refs = cve.get("references", [])
        patch_refs = [r["url"] for r in refs
                      if set(r.get("tags", [])) & {"Patch", "Vendor Advisory", "Mitigation"}]
        haystack = desc + " " + " ".join(r.get("url", "") for r in refs)
        matched = contains_any(haystack, vendors, ignore_case=False)
        exploited = bool(cve.get("cisaExploitAdd"))
        if c.get("require_vendor_match", True) and vendors and not matched and not exploited:
            continue
        out.append(Alert(
            uid=f"nvd:{cve_id}",
            category="ZERO-DAY" if exploited else "CRITICAL CVE",
            title=f"{cve_id} ({score}){' – ' + ', '.join(matched) if matched else ''}",
            summary=desc,
            link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            patch=patch_refs[0] if patch_refs else "No patch link listed yet – check vendor advisory",
            urgent=exploited or bool(matched) or c.get("all_critical_urgent", False),
            source="NVD",
        ))
    return out


def entry_age_hours(e):
    t = e.get("published_parsed") or e.get("updated_parsed")
    if not t:
        return 0
    return (time.time() - calendar.timegm(t)) / 3600


def src_rss(cfg, vendors):
    out = []
    kw = cfg["keywords"]
    for feed in cfg["sources"]["rss"]:
        if not feed.get("enabled", True):
            continue
        try:
            raw = http_get(feed["url"]).content
            parsed = feedparser.parse(raw)
        except Exception as e:
            log(f"RSS '{feed['name']}' failed: {e}")
            continue
        for e in parsed.entries[: feed.get("max_items", 30)]:
            if entry_age_hours(e) > feed.get("max_age_hours", 72):
                continue
            title = clean(e.get("title", ""))
            summary = clean(e.get("summary", ""), 600)
            text = f"{title} {summary}"
            kind = feed["type"]
            exploited_hits = contains_any(text, kw["zero_day"])
            vendor_hits = contains_any(text, vendors, ignore_case=False)

            if kind == "news":
                # Only alert on news about zero-days / active exploitation / emergency patches
                if not exploited_hits and not contains_any(text, kw["critical"]):
                    continue
                category = "ZERO-DAY" if exploited_hits else "NEWS"
                urgent = bool(exploited_hits)
            elif kind == "patch":
                must = feed.get("keywords") or []
                if must and not contains_any(text, must) and not exploited_hits:
                    continue
                category = "ZERO-DAY" if exploited_hits else "PATCH"
                urgent = bool(exploited_hits) or feed.get("urgent", False)
            else:  # outage
                must = feed.get("keywords") or []
                if must and not contains_any(text, must):
                    continue
                if contains_any(title, ["resolved", "completed", "scheduled maintenance"]):
                    continue
                category = "OUTAGE"
                urgent = feed.get("urgent", False)

            uid_base = e.get("id") or e.get("link") or title
            out.append(Alert(
                uid=f"rss:{feed['name']}:{hashlib.sha1(uid_base.encode()).hexdigest()[:16]}",
                category=category,
                title=title + (f" [{', '.join(vendor_hits)}]" if vendor_hits else ""),
                summary=summary,
                link=e.get("link", ""),
                urgent=urgent,
                source=feed["name"],
            ))
    return out


# --------------------------------------------------------------------------- senders
def whatsapp_recipients():
    return [n.strip() for n in env("WHATSAPP_TO").split(",") if n.strip()]


def send_meta(text):
    """Meta WhatsApp Cloud API. Uses an approved template unless META_MODE=text."""
    token, phone_id = env("META_TOKEN"), env("META_PHONE_NUMBER_ID")
    version = env("META_API_VERSION", "v23.0")
    url = f"https://graph.facebook.com/{version}/{phone_id}/messages"
    mode = env("META_MODE", "template")
    ok = True
    for to in whatsapp_recipients():
        if mode == "text":
            payload = {"messaging_product": "whatsapp", "to": to, "type": "text",
                       "text": {"body": text[:4000], "preview_url": False}}
        else:
            # Template variables may not contain newlines/tabs or 4+ spaces in a row.
            param = re.sub(r"\s{2,}", " ", text.replace("\n", " | "))[:900]
            payload = {"messaging_product": "whatsapp", "to": to, "type": "template",
                       "template": {"name": env("META_TEMPLATE_NAME", "security_alert"),
                                    "language": {"code": env("META_TEMPLATE_LANG", "en")},
                                    "components": [{"type": "body",
                                                    "parameters": [{"type": "text", "text": param}]}]}}
        r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT,
                          headers={"Authorization": f"Bearer {token}"})
        if r.status_code >= 300:
            log(f"Meta WhatsApp error for {to}: {r.status_code} {r.text[:300]}")
            ok = False
    return ok


def send_twilio(text):
    sid, tok = env("TWILIO_ACCOUNT_SID"), env("TWILIO_AUTH_TOKEN")
    sender = env("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")  # sandbox number
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    ok = True
    for to in whatsapp_recipients():
        data = {"From": sender, "To": to if to.startswith("whatsapp:") else f"whatsapp:{to}"}
        if env("TWILIO_CONTENT_SID"):  # approved template (needed outside the 24h window)
            data["ContentSid"] = env("TWILIO_CONTENT_SID")
            data["ContentVariables"] = json.dumps(
                {"1": re.sub(r"\s{2,}", " ", text.replace("\n", " | "))[:900]})
        else:
            data["Body"] = text[:1550]
        r = requests.post(url, data=data, auth=(sid, tok), timeout=HTTP_TIMEOUT)
        if r.status_code >= 300:
            log(f"Twilio error for {to}: {r.status_code} {r.text[:300]}")
            ok = False
    return ok


def send_telegram(text):
    """Telegram bot message (free). *bold* markers become HTML bold."""
    token, chat_ids = env("TELEGRAM_BOT_TOKEN"), env("TELEGRAM_CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = re.sub(r"\*(.+?)\*", r"<b>\1</b>", html.escape(text[:3900], quote=False))
    ok = True
    for chat_id in [c.strip() for c in chat_ids.split(",") if c.strip()]:
        r = requests.post(url, timeout=HTTP_TIMEOUT, json={
            "chat_id": chat_id, "text": body, "parse_mode": "HTML",
            "disable_web_page_preview": True})
        if r.status_code >= 300:
            log(f"Telegram error for {chat_id}: {r.status_code} {r.text[:300]}")
            ok = False
    return ok


def send_teams(text):
    """Teams 'Workflows' webhook (Post to a channel when a webhook request is received)."""
    url = env("TEAMS_WEBHOOK_URL")
    if not url:
        return True
    card = {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4",
                    "body": [{"type": "TextBlock", "text": text.replace("\n", "\n\n"), "wrap": True}]}}]}
    r = requests.post(url, json=card, timeout=HTTP_TIMEOUT)
    if r.status_code >= 300:
        log(f"Teams error: {r.status_code} {r.text[:300]}")
        return False
    return True


def deliver(text, dry_run=False):
    if dry_run:
        print("\n----- WOULD SEND -----\n" + text + "\n----------------------")
        return True
    provider = env("WHATSAPP_PROVIDER", "meta").lower()
    ok_wa = True
    if whatsapp_recipients():
        ok_wa = send_twilio(text) if provider == "twilio" else send_meta(text)
    ok_tg = True
    if env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"):
        ok_tg = send_telegram(text)
    ok_teams = send_teams(text)
    return ok_wa and ok_tg and ok_teams  # retry next run if any channel failed


# --------------------------------------------------------------------------- main
def collect(cfg):
    vendors = cfg.get("watch_vendors", [])
    alerts = []
    for name, fn in (("CISA KEV", lambda: src_cisa_kev(cfg)),
                     ("NVD", lambda: src_nvd(cfg, vendors)),
                     ("RSS", lambda: src_rss(cfg, vendors))):
        try:
            got = fn()
            log(f"{name}: {len(got)} candidate alerts")
            alerts.extend(got)
        except Exception as e:
            log(f"{name} failed: {e}")
    # de-duplicate the same CVE coming from KEV and NVD (keep KEV)
    seen_cves, unique = set(), []
    for a in sorted(alerts, key=lambda x: 0 if x.uid.startswith("kev:") else 1):
        cve = re.search(r"CVE-\d{4}-\d+", a.title)
        key = cve.group(0) if cve and a.uid.split(":")[0] in ("kev", "nvd") else a.uid
        if key in seen_cves:
            continue
        seen_cves.add(key)
        unique.append(a)
    return unique


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--seed", action="store_true")
    ap.add_argument("--test-message", action="store_true")
    ap.add_argument("--preview", action="store_true")
    args = ap.parse_args()

    load_dotenv()
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)

    if args.test_message:
        ok = deliver("✅ Cyber Alert Bot test message – delivery works.", args.dry_run)
        sys.exit(0 if ok else 1)

    if args.preview:
        # Send one real recent item per category so you can see the format.
        # Does not touch state, so normal alerting is unaffected.
        alerts = collect(cfg)
        picked, cats = [], set()
        for a in alerts:
            if a.category not in cats:
                cats.add(a.category)
                picked.append(a)
        deliver(f"👀 PREVIEW – {len(picked)} sample alert(s) built from real recent items "
                f"(one per type), plus a sample digest. Real alerts don't have this header.",
                args.dry_run)
        for a in picked:
            deliver(a.full_text(), args.dry_run)
        if alerts:
            deliver("📋 *Security update – sample digest*\n"
                    + "\n".join(a.short_line() for a in alerts[:6]), args.dry_run)
        return

    state = load_state()
    first_run = state is None
    state = state or {"seen": {}}
    alerts = collect(cfg)
    new = [a for a in alerts if a.uid not in state["seen"]]
    log(f"{len(alerts)} total, {len(new)} new")

    now = time.time()
    if args.seed or first_run:
        # First run: don't flood the phone with everything from the past week.
        for a in new:
            state["seen"][a.uid] = now
        if not args.dry_run:
            save_state(state)
            deliver(f"✅ Cyber Alert Bot is live. Watching {len(alerts)} recent items; "
                    f"you'll get alerts for anything new from now on.")
        log("Seeded state; no alerts sent.")
        return

    max_urgent = cfg.get("max_urgent_per_run", 8)
    urgent = [a for a in new if a.urgent]
    digest = [a for a in new if not a.urgent] + urgent[max_urgent:]
    urgent = urgent[:max_urgent]

    for a in urgent:
        if deliver(a.full_text(), args.dry_run):
            state["seen"][a.uid] = now

    if digest and cfg.get("send_digest", True):
        lines = [a.short_line() for a in digest[: cfg.get("max_digest_items", 15)]]
        extra = len(digest) - len(lines)
        msg = f"📋 *Security update – {len(digest)} new item(s)*\n" + "\n".join(lines)
        if extra > 0:
            msg += f"\n…and {extra} more"
        if deliver(msg, args.dry_run):
            for a in digest:
                state["seen"][a.uid] = now
    elif digest:
        for a in digest:
            state["seen"][a.uid] = now

    if not args.dry_run:
        save_state(state)


if __name__ == "__main__":
    main()

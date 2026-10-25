"""Critical vulnerability news -> Discord, with the fix in every alert.

Sources, most urgent first:
  CISA KEV         exploited in the wild (pings @here)
  GitHub Advisory  critical open-source package vulns, with patched versions
  NVD              any new CVE scored >= 9.0, usually before it reaches KEV

Env: DISCORD_WEBHOOK (unset = dry run: print, keep no state), GITHUB_TOKEN, NVD_API_KEY (optional).
"""
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

GHSA_SEVERITIES = {"critical"}
NVD_MIN_SCORE = 9.0
MUTE_WORDS = ("wordpress",)  # matched against NVD descriptions; KEV is never muted
MUTE_CNAS = {"audit@patchstack.com", "security@wordfence.com"}  # WordPress-plugin-only CNAs
LOOKBACK = timedelta(hours=24)  # wide enough to ride out delayed or skipped Actions runs
NVD_LOOKBACK = timedelta(hours=72)  # many CVEs get their score a day or two after publishing
KEEP_SEEN = timedelta(days=30)
FAIL_ALERT_AFTER = 6  # consecutive failed runs (~30 min at */5) before saying a source is down
DIGEST_HOUR_UTC = 2  # 09:00 Asia/Bangkok

HOOK = os.environ.get("DISCORD_WEBHOOK")
STATE = Path(__file__).with_name("state.json")
UA = "DiscordBot (https://github.com/NiraphatK/security-alert, 1)"  # Discord's CDN rejects urllib's default UA
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories?type=reviewed&sort=updated&direction=desc&per_page=100"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FIX_TAGS = {"Patch", "Vendor Advisory", "Mitigation", "Release Notes"}
FIX_CMD = {
    "npm": "npm i {n}@{v}",
    "pip": 'pip install -U "{n}>={v}"',
    "go": "go get {n}@v{v}",
    "rust": "cargo update -p {n}",
    "rubygems": "bundle update {n}",
    "composer": "composer require {n}:^{v}",
}
RED, ORANGE, PURPLE, GREEN, YELLOW = 0xE5484D, 0xF76B15, 0x8E4EC6, 0x30A46C, 0xFFC53D


def ts(s):
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=UTC)  # NVD timestamps carry no zone; they are UTC


def cut(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def md(s):
    """Escape Discord markdown in feed text, so a CVE description can't forge links or formatting."""
    return re.sub(r"([\\*_~`|\[\]()<>#])", r"\\\1", " ".join((s or "").split()))


def fetch(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r), r.headers
        except (OSError, ValueError, http.client.HTTPException):
            if attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


def next_link(link):
    for part in (link or "").split(","):
        url, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            return url.strip(" <>")


# --- sources -------------------------------------------------------------------------------------

def get_ghsa(cutoff):
    h = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {token}"
    items, url = [], GHSA_URL
    for _ in range(20):  # sorted newest-updated first; stop once a page reaches past the cutoff
        page, headers = fetch(url, h)
        items += page
        url = next_link(headers.get("Link"))
        if not page or not url or ts(page[-1]["updated_at"]) < cutoff:
            break
    return items


def get_nvd(now):
    h = {"apiKey": key} if (key := os.environ.get("NVD_API_KEY")) else {}
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    url = f"{NVD_URL}?pubStartDate={(now - NVD_LOOKBACK).strftime(fmt)}&pubEndDate={now.strftime(fmt)}&resultsPerPage=2000"
    cves, start = [], 0
    while True:
        d, _ = fetch(f"{url}&startIndex={start}", h)
        cves += [v["cve"] for v in d["vulnerabilities"]]
        start += len(d["vulnerabilities"])
        if not d["vulnerabilities"] or start >= d["totalResults"]:
            return cves
        time.sleep(6)  # NVD's public rate limit is 5 requests per 30 s


def get_kev():
    return fetch(KEV_URL)[0]["vulnerabilities"]


# --- matchers: pure, return [(keys, embed)] (NVD: lines); keys[0] is the alert's own id, the rest dedupe
# `taken` holds every key already alerted; matchers add to it so later sources skip the same CVE.

def fix_cmd(ecosystem, name, version):
    tpl = FIX_CMD.get(ecosystem)
    return tpl and tpl.format(n=name, v=version.removeprefix("v"))


def match_ghsa(advisories, taken, cutoff):
    out = []
    for a in advisories:
        keys = [f"ghsa:{a['ghsa_id']}"] + ([f"cve:{a['cve_id']}"] if a.get("cve_id") else [])
        fresh = max(ts(a["published_at"]), ts(a.get("github_reviewed_at") or a["published_at"]))
        if a["severity"] not in GHSA_SEVERITIES or a.get("withdrawn_at") or fresh < cutoff or keys[0] in taken:
            continue
        taken.update(keys)
        pkgs, fixes = [], []
        for v in a.get("vulnerabilities") or []:
            eco, name = (v.get("package") or {}).get("ecosystem", "?"), (v.get("package") or {}).get("name", "?")
            fixed = v.get("first_patched_version")
            pkgs.append(f"{eco}/{name}")
            line = f"**{md(f'{eco}/{name}')}** `{v.get('vulnerable_version_range') or '?'}` → " + (f"`{fixed}`" if fixed else "ยังไม่มี patch")
            if fixed and (cmd := fix_cmd(eco, name, fixed)):
                line += f"\n`{cmd}`"
            fixes.append(line)
        pkgs = list(dict.fromkeys(pkgs))
        label = pkgs[0] + (f" +{len(pkgs) - 1}" if len(pkgs) > 1 else "") if pkgs else "package"
        score = max(((s or {}).get("score") or 0 for s in (a.get("cvss_severities") or {}).values()), default=0)
        out.append((keys, {
            "title": cut(f"🩹 CRITICAL{f' {score}' if score else ''} · {label} — {a.get('cve_id') or a['ghsa_id']}", 256),
            "url": a["html_url"],
            "description": cut(md(a.get("summary")), 400),
            "color": PURPLE,
            "fields": [{"name": "แก้ด้วย", "value": cut("\n".join(fixes), 1024) or "-"}],
            "footer": {"text": f"GitHub Advisory · {a['ghsa_id']}"},
            "timestamp": ts(a["published_at"]).isoformat(),
        }))
    return out


def cvss(cve):
    m = cve.get("metrics", {})
    return max((x["cvssData"]["baseScore"] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") for x in m.get(k, [])), default=0)


def match_nvd(cves, taken, cutoff):
    """NVD runs ~25-50 criticals a weekday, so each is one line (packed by `nvd_feed`), not a card."""
    out = []
    for c in cves:
        keys = [f"nvd:{c['id']}", f"cve:{c['id']}"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score = cvss(c)
        if (keys[1] in taken or score < NVD_MIN_SCORE or c.get("vulnStatus") == "Rejected"
                or ts(c["published"]) < cutoff or int(c["id"].split("-")[1]) < cutoff.year - 1  # backfilled old bugs
                or c.get("sourceIdentifier") in MUTE_CNAS or any(w in desc.lower() for w in MUTE_WORDS)):
            continue
        taken.update(keys)
        fix = next((r["url"] for r in c.get("references", []) if FIX_TAGS & set(r.get("tags", []))), None)
        line = f"`{score}` [{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']}) {cut(md(desc), 180)}"
        out.append((keys, line + (f" · [patch]({fix})" if fix else "")))
    return out


def nvd_feed(lines):
    out, keys, text = [], [], ""
    for k, line in lines:
        if text and len(text) + len(line) > 3900:
            out.append((keys, text))
            keys, text = [], ""
        keys, text = keys + k, text + line + "\n"
    if text:
        out.append((keys, text))
    return [(k, {"title": f"🔴 CVE ใหม่ CVSS ≥ {NVD_MIN_SCORE}", "description": t, "color": ORANGE,
                 "footer": {"text": "NVD · กด CVE ดูรายละเอียด/วิธีแก้ · [patch] = ลิงก์แก้จาก vendor"}}) for k, t in out]


def match_kev(vulns, taken, cutoff):
    out, since = [], cutoff.date().isoformat()
    for v in vulns:
        keys = [f"kev:{v['cveID']}"]  # own namespace: a CVE we already reported becoming exploited is news
        if keys[0] in taken or v["dateAdded"] < since:
            continue
        taken.update(keys)
        notes = (s.strip() for s in v.get("notes", "").split(";"))
        links = [u for u in notes if u.startswith("http") and "cisa.gov" not in u]
        fields = [
            {"name": "ต้องทำ", "value": cut(md(v.get("requiredAction")), 300) or "-"},
            {"name": "แพตช์ภายใน", "value": v.get("dueDate") or "-", "inline": True},
        ]
        if v.get("knownRansomwareCampaignUse") == "Known":
            fields.append({"name": "ransomware", "value": "ใช้ในแคมเปญ ransomware แล้ว", "inline": True})
        fields.append({"name": "advisory / patch", "value": cut("\n".join(links[:3]), 1024) or "-"})
        out.append((keys, {
            "title": cut(f"🚨 ถูกโจมตีจริง · {v['vendorProject']} {v['product']} — {v['cveID']}", 256),
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "description": cut(md(v.get("shortDescription")), 500),
            "color": RED,
            "fields": fields,
            "footer": {"text": f"CISA KEV · เพิ่มเมื่อ {v['dateAdded']}"},
        }))
    return out


# --- health & digest -----------------------------------------------------------------------------

def health(fail, name, err=None):
    """Count consecutive failures; speak only on the Nth failure and on recovery, not every run."""
    if err:
        fail[name] = fail.get(name, 0) + 1
        if fail[name] == FAIL_ALERT_AFTER:
            return f"⚠️ ดึงข่าวจาก {name} ไม่ได้ {FAIL_ALERT_AFTER} รอบติด — {cut(repr(err), 300)}", YELLOW
    elif fail.pop(name, 0) >= FAIL_ALERT_AFTER:
        return f"✅ {name} กลับมาใช้ได้แล้ว", GREEN


def digest(state, now):
    """Once a day: what went out in the last 24 h. Doubles as a heartbeat — silence means the watcher is dead."""
    today = now.date().isoformat()
    if now.hour < DIGEST_HOUR_UTC or state.get("digest") == today:
        return None
    state["digest"] = today
    n = Counter(k.split(":")[0] for k, t in state["seen"].items() if ts(t) >= now - timedelta(days=1))
    return f"✅ ยังเฝ้าอยู่ · 24 ชม.ที่ผ่านมาแจ้งไป 🚨 KEV {n['kev']} · 🩹 GHSA {n['ghsa']} · 🔴 NVD {n['nvd']}", GREEN


def prune(seen, now):
    for k in [k for k, t in seen.items() if ts(t) < now - KEEP_SEEN]:
        del seen[k]


# --- discord -------------------------------------------------------------------------------------

def size(e):
    return (len(e.get("title", "")) + len(e.get("description", "")) + len(e.get("footer", {}).get("text", ""))
            + sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", [])))


def batches(alerts):
    """Pack alerts into messages within Discord's limits: 10 embeds and 6000 characters each."""
    batch, total = [], 0
    for a in alerts:
        n = size(a[1])
        if batch and (len(batch) == 10 or total + n > 6000):
            yield batch
            batch, total = [], 0
        batch.append(a)
        total += n
    if batch:
        yield batch


def post(payload):
    if not HOOK:
        print(json.dumps(payload, ensure_ascii=False, indent=1))
        return
    req = urllib.request.Request(HOOK, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": UA})
    for _ in range(5):
        try:
            urllib.request.urlopen(req, timeout=30).close()
            return
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            time.sleep(float(json.loads(e.read() or b"{}").get("retry_after", 2)))
    raise RuntimeError("Discord kept rate-limiting")


def save(state):
    if HOOK:
        STATE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def send(alerts, state, now, ping=False):
    for batch in batches(alerts):
        post({
            "content": "@here" if ping else "",
            "embeds": [e for _, e in batch],
            "allowed_mentions": {"parse": ["everyone"] if ping else []},  # feed text must never ping anyone
        })
        for keys, _ in batch:
            state["seen"].update(dict.fromkeys(keys, now.isoformat(timespec="seconds")))
        save(state)  # after every message, so a crash mid-run neither repeats nor loses alerts


def main():
    now = datetime.now(UTC)
    first = not STATE.exists()
    state = {"seen": {}, "fail": {}, "digest": now.date().isoformat()} if first else json.loads(STATE.read_text())
    taken, news, kev, notices, errors = set(state["seen"]), [], [], [], []
    sources = [
        ("GitHub Advisory", news, lambda: match_ghsa(get_ghsa(now - LOOKBACK), taken, now - LOOKBACK)),
        ("NVD", news, lambda: nvd_feed(match_nvd(get_nvd(now), taken, now - NVD_LOOKBACK))),
        ("CISA KEV", kev, lambda: match_kev(get_kev(), taken, now - LOOKBACK)),
    ]
    for name, bucket, run in sources:
        try:
            bucket += run()
            err = None
        except Exception as e:  # one dead source must not silence the others
            print(f"{name}: {e!r}", file=sys.stderr)
            errors.append(name)
            err = e
        if notice := health(state["fail"], name, err):
            notices.append(notice)

    if first and HOOK:  # seed quietly instead of flooding the channel with the past day
        backdated = (now - LOOKBACK).isoformat(timespec="seconds")  # keeps them out of the first digest
        for keys, _ in news + kev:
            state["seen"].update(dict.fromkeys(keys, backdated))
        notices.append((f"🟢 เริ่มเฝ้าระวังแล้ว — ข้ามข่าวเก่า {len(news) + len(kev)} รายการ จากนี้แจ้งทันทีที่มีของใหม่", GREEN))
        news, kev = [], []

    prune(state["seen"], now)
    try:
        send(kev, state, now, ping=True)
        send(news, state, now)
        if notice := digest(state, now):
            notices.append(notice)
        for text, color in notices:
            post({"embeds": [{"description": text, "color": color}], "allowed_mentions": {"parse": []}})
    finally:
        save(state)
    print(f"sent: kev={len(kev)} news={len(news)} notices={len(notices)} failed_sources={errors}")


if __name__ == "__main__":
    main()

"""Critical vulnerability news -> Discord: what kind of attack it is, how it gets in, and how to fix it.

Sources, most urgent first:
  CISA KEV         exploited in the wild (pings @here)
  GitHub Advisory  critical open-source package vulns, with patched versions
  NVD              any new CVE scored >= 9.0, usually before it reaches KEV

Env: DISCORD_WEBHOOK (unset = dry run: print, keep no state), GITHUB_TOKEN, NVD_API_KEY (optional),
     PREVIEW=true (post one sample of each message type, touch no state).
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

GHSA_SEVERITIES = {"critical"}
NVD_MIN_SCORE = 9.0
MUTE_WORDS = ("wordpress",)  # matched against NVD descriptions; KEV is never muted
MUTE_CNAS = {"audit@patchstack.com", "security@wordfence.com"}  # WordPress-plugin-only CNAs
# How far back each run looks. With the seen set (kept KEEP_SEEN) this rides out skipped runs and source
# outages: anything new inside the window that hasn't gone out yet goes out now.
KEV_LOOKBACK = timedelta(days=7)  # the feed is small, and an exploited-in-the-wild alert must never be lost
GHSA_LOOKBACK = timedelta(days=3)
NVD_LOOKBACK = timedelta(hours=72)  # also: many CVEs get their score a day or two after publishing
KEEP_SEEN = timedelta(days=30)
FAIL_ALERT_AFTER = 6  # consecutive failed runs (~30 min at */5) before saying a source is down
DIGEST_HOUR_UTC = 2  # 09:00 Asia/Bangkok
MIN_RUNS_PER_DAY = 144  # the Worker in trigger/ dispatches 288 a day; under half means it is broken
TRIGGER_STALE = timedelta(minutes=20)  # no dispatch for this long, seen from a GitHub-cron run: the Worker is down

HOOK = os.environ.get("DISCORD_WEBHOOK")
STATE = Path(__file__).with_name("state.json")
UA = "DiscordBot (https://github.com/NiraphatK/security-alert, 1)"  # Discord's CDN rejects urllib's default UA
README = "https://github.com/NiraphatK/security-alert#readme"
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
ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "rust": "Rust", "go": "Go", "maven": "Maven", "composer": "PHP",
              "rubygems": "Ruby", "nuget": ".NET", "pub": "Dart", "swift": "Swift", "erlang": "Erlang", "actions": "GitHub Actions"}
RED, ORANGE, PURPLE, GREEN, YELLOW = 0xE5484D, 0xF76B15, 0x8E4EC6, 0x30A46C, 0xFFC53D
# One name per kind of alert, used on its cards, in the daily summary and in the start notice
EXPLOITED, OPEN_SOURCE, NEW_CVE = "ถูกโจมตีจริง", "Open-source critical", "CVE ร้ายแรงใหม่"

# (CWEs, fallback keywords, attack name, what the attacker gets). A record's own CWE order wins (its first is
# usually the primary); the keywords are only tried against the text when none of its CWEs is listed here.
ATTACKS = [
    (("CWE-94", "CWE-95", "CWE-917", "CWE-1336"), ("remote code execution", "code injection", "template injection"),
     "Remote Code Execution", "รันโค้ดบนเครื่องเป้าหมายได้ = ยึดเครื่องได้"),
    (("CWE-77", "CWE-78", "CWE-88"), ("command injection",), "Command Injection", "สั่งรันคำสั่ง OS บนเซิร์ฟเวอร์ได้"),
    (("CWE-502",), ("deserializ",), "Insecure Deserialization", "ส่งข้อมูลที่ปั้นมาให้ระบบแปลงกลับแล้วรันโค้ดได้"),
    (("CWE-89", "CWE-564"), ("sql injection",), "SQL Injection", "อ่าน แก้ หรือลบข้อมูลในฐานข้อมูลได้"),
    (("CWE-434",), ("file upload",), "Unrestricted File Upload", "อัปโหลดไฟล์อันตราย เช่น web shell แล้วสั่งรันได้"),
    (("CWE-98",), ("file inclusion",), "File Inclusion", "ให้เซิร์ฟเวอร์โหลดไฟล์หรือโค้ดที่ผู้โจมตีกำหนด"),
    (("CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-1390"), ("authentication bypass", "missing authentication"),
     "Authentication Bypass", "เข้าระบบได้โดยไม่ต้องล็อกอิน"),
    (("CWE-798", "CWE-259", "CWE-1392", "CWE-1393"), ("hard-coded", "hardcoded", "default credential"),
     "Hard-coded Credentials", "ใช้รหัสผ่านที่ฝังมากับระบบเข้าใช้งานได้"),
    (("CWE-250", "CWE-266", "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"),
     ("privilege escalation", "elevation of privilege", "missing authorization", "access control"),
     "Privilege Escalation", "ทำสิ่งที่ไม่ได้รับอนุญาตหรือยกระดับสิทธิ์ตัวเองได้"),
    (("CWE-415", "CWE-416"), ("use-after-free", "use after free", "double free"), "Use-After-Free", "ทำให้โปรแกรมล่มหรือรันโค้ดได้"),
    (("CWE-843",), ("type confusion",), "Type Confusion", "ทำให้โปรแกรมล่มหรือรันโค้ดได้"),
    (("CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-131", "CWE-190", "CWE-191", "CWE-680", "CWE-787", "CWE-788", "CWE-805"),
     ("buffer overflow", "out-of-bounds", "heap overflow", "integer overflow", "memory corruption"),
     "Memory Corruption", "ทำให้โปรแกรมล่ม ข้อมูลรั่ว หรือรันโค้ดได้"),
    (("CWE-22", "CWE-23", "CWE-24", "CWE-35", "CWE-36", "CWE-73"), ("path traversal", "directory traversal"),
     "Path Traversal", "อ่านหรือเขียนไฟล์นอกโฟลเดอร์ที่อนุญาตได้"),
    (("CWE-918",), ("server-side request forgery", "ssrf"), "SSRF", "หลอกให้เซิร์ฟเวอร์ส่ง request เข้าระบบภายในได้"),
    (("CWE-611",), ("xml external entit", "xxe"), "XXE", "อ่านไฟล์บนเซิร์ฟเวอร์ผ่าน XML ที่ปั้นมาได้"),
    (("CWE-1321",), ("prototype pollution",), "Prototype Pollution", "แก้ object พื้นฐานของ JavaScript จนพฤติกรรมเปลี่ยนหรือรันโค้ดได้"),
    (("CWE-295", "CWE-297", "CWE-345", "CWE-347"), ("certificate validation", "signature verification", "signature validation"),
     "Signature / Certificate Bypass", "ปลอมตัวหรือแก้ข้อมูลที่ควรถูกป้องกันด้วยลายเซ็นได้"),
    (("CWE-79", "CWE-80"), ("cross-site scripting", "xss"), "Cross-Site Scripting (XSS)", "ฝังสคริปต์ในหน้าเว็บเพื่อขโมย session ของผู้ใช้"),
    (("CWE-352",), ("cross-site request forgery", "csrf"), "CSRF", "หลอกให้ผู้ใช้ที่ล็อกอินอยู่ทำคำสั่งโดยไม่รู้ตัว"),
    (("CWE-200", "CWE-209", "CWE-532", "CWE-538", "CWE-552"), ("information disclosure", "sensitive information"),
     "Information Disclosure", "ข้อมูลสำคัญรั่วไหลได้"),
    (("CWE-400", "CWE-476", "CWE-674", "CWE-770", "CWE-835", "CWE-1333"), ("denial of service", "denial-of-service"),
     "Denial of Service", "ทำให้ระบบล่มหรือใช้งานไม่ได้"),
]
CWE_ATTACK = {cwe: (name, impact) for cwes, _, name, impact in ATTACKS for cwe in cwes}
# CVSS vector metrics -> how the attack is delivered
ATTACK_VECTOR = {"N": "ผ่านอินเทอร์เน็ต", "A": "ต้องอยู่ในเครือข่ายเดียวกัน", "L": "ต้องเข้าเครื่องได้ก่อน", "P": "ต้องเข้าถึงตัวเครื่อง"}
PRIVILEGES = {"N": "ไม่ต้องล็อกอิน", "L": "ต้องมีบัญชีผู้ใช้", "H": "ต้องมีสิทธิ์ admin"}
INTERACTION = {"N": "เหยื่อไม่ต้องทำอะไร", "R": "ต้องหลอกให้เหยื่อกดหรือเปิดไฟล์", "A": "ต้องหลอกให้เหยื่อกดหรือเปิดไฟล์",
               "P": "ต้องให้เหยื่อเปิดดูเนื้อหา"}
VERSION = r"v?\d+(?:\.[0-9A-Za-z-]+)+"
FIXED_IN = re.compile(rf"\b(?:before|prior to|fixed in|patched in|upgrade to|until)\s+(?:versions?\s+)?"
                      rf"({VERSION}(?:(?:,\s*|,?\s+(?:and|or)\s+){VERSION})*)", re.I)


def ts(s):
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=UTC)  # NVD timestamps carry no zone; they are UTC


def cut(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def md(s):
    """Escape Discord markdown in feed text, so a CVE description can't forge links or formatting."""
    return re.sub(r"([\\*_~`|\[\]()<>#])", r"\\\1", " ".join((s or "").split()))


def fetch(url, headers=None, tries=3, timeout=30):
    # gzip: the KEV and NVD feeds are ~1.8 MB each per run, ~10x smaller compressed
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip", **(headers or {})})
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                return json.loads(gzip.decompress(body) if r.headers.get("Content-Encoding") == "gzip" else body), r.headers
        except (OSError, ValueError, http.client.HTTPException):
            if attempt == tries - 1:
                raise
            time.sleep(5 * (attempt + 1))


def next_link(link):
    for part in (link or "").split(","):
        url, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            return url.strip(" <>")


# --- sources -------------------------------------------------------------------------------------

def gh_headers():
    h = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {token}"
    return h


def count_runs(since):
    """How many times the watcher ran since `since` (None outside Actions)."""
    if not (repo := os.environ.get("GITHUB_REPOSITORY")):
        return None
    created = urllib.parse.quote(f">={since:%Y-%m-%dT%H:%M:%SZ}")
    d, _ = fetch(f"https://api.github.com/repos/{repo}/actions/workflows/watch.yml/runs?created={created}&per_page=1", gh_headers())
    return d["total_count"]


def get_ghsa(cutoff):
    items, url = [], GHSA_URL
    for _ in range(20):  # sorted newest-updated first; stop once a page reaches past the cutoff
        page, headers = fetch(url, gh_headers())
        items += page
        url = next_link(headers.get("Link"))
        if not page or not url or ts(page[-1]["updated_at"]) < cutoff:
            break
    return items


def nvd_headers():
    return {"apiKey": key} if (key := os.environ.get("NVD_API_KEY")) else {}


def get_nvd(now):
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    url = f"{NVD_URL}?pubStartDate={(now - NVD_LOOKBACK).strftime(fmt)}&pubEndDate={now.strftime(fmt)}&resultsPerPage=2000"
    cves, start = [], 0
    while True:
        d, _ = fetch(f"{url}&startIndex={start}", nvd_headers())
        cves += [v["cve"] for v in d["vulnerabilities"]]
        start += len(d["vulnerabilities"])
        if not d["vulnerabilities"] or start >= d["totalResults"]:
            return cves
        time.sleep(6)  # NVD's public rate limit is 5 requests per 30 s


def nvd_lookup():
    """KEV carries no CVSS, so look each new KEV CVE up in NVD. Best effort: after one failure it stops
    asking, so an exploited-in-the-wild alert never waits on NVD being down."""
    down = False

    def lookup(cve_id):
        nonlocal down
        if down:
            return None
        try:
            d, _ = fetch(f"{NVD_URL}?cveId={cve_id}", nvd_headers(), tries=1, timeout=20)
            time.sleep(6)  # NVD's public rate limit is 5 requests per 30 s
            return d["vulnerabilities"][0]["cve"] if d["vulnerabilities"] else None
        except Exception as e:
            print(f"NVD lookup {cve_id}: {e!r}", file=sys.stderr)
            down = True
    return lookup


def get_kev():
    return fetch(KEV_URL)[0]["vulnerabilities"]


# --- summary helpers: attack type, attack path and fix, in Thai, derived from the feeds' own data ---------

def cwe_url(cwe):
    return f"https://cwe.mitre.org/data/definitions/{cwe.removeprefix('CWE-')}.html"


def nvd_url(cve):
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def main_cwe(cwes):
    """The CWE the attack type came from (else the record's first), so the CWE link matches the label."""
    return next((c for c in cwes if c in CWE_ATTACK), cwes[0] if cwes else None)


def classify(cwes, text):
    """(attack name, what the attacker gets) or None."""
    if hit := next((CWE_ATTACK[c] for c in cwes if c in CWE_ATTACK), None):
        return hit
    text = (text or "").lower()
    return next(((name, impact) for _, words, name, impact in ATTACKS if any(w in text for w in words)), None)


def attack_type(cwes, text, names=None):
    """Field value: the attack's name in bold, what the attacker gets on the line below."""
    if hit := classify(cwes, text):
        return f"**{hit[0]}**\n{hit[1]}"
    if cwes:  # no plain-language name for it; the CWE page explains it
        return f"[{cwes[0]}{' ' + names[cwes[0]] if (names or {}).get(cwes[0]) else ''}]({cwe_url(cwes[0])})"


def attack_path(vector):
    """CVSS vector -> how the attack gets in, e.g. ['ผ่านอินเทอร์เน็ต', 'ไม่ต้องล็อกอิน', 'เหยื่อไม่ต้องทำอะไร']."""
    m = dict(p.split(":", 1) for p in (vector or "").split("/") if ":" in p)
    return [t[m[k]] for k, t in (("AV", ATTACK_VECTOR), ("PR", PRIVILEGES), ("UI", INTERACTION)) if m.get(k) in t]


def fixed_in(text):
    """Fixed versions named in free text: 'before 1.0.8', 'prior to 36.0.19 and 43.0.0', 'fixed in 2.1.4'."""
    return list(dict.fromkeys(v.removeprefix("v") for m in FIXED_IN.findall(text or "") for v in re.findall(VERSION, m)))[:4]


def kev_fix(action):
    """CISA's required action as steps."""
    a = (action or "").lower()
    if "vendor instructions" in a:
        return ["ติดตั้งอัปเดตหรือทำตามวิธีแก้ของ vendor (ลิงก์ด้านล่าง)"] + (
            ["ถ้ายังไม่มีวิธีแก้ ให้หยุดใช้หรือปิดไม่ให้เข้าถึงจากอินเทอร์เน็ตชั่วคราว"] if "discontinue" in a else [])
    # requiredAction can trail CISA directive boilerplate; the first clause is the actual instruction
    return [cut(md(re.split(r"\.\s|, ensuring", action or "")[0]), 300)]


def numbered(items):
    items = [i for i in items if i]
    return "\n".join(f"{n}. {s}" for n, s in enumerate(items, 1)) if len(items) > 1 else (items[0] if items else "-")


def attack_fields(kind, path):
    """Attack type and attack path, side by side."""
    return ([{"name": "ประเภทการโจมตี", "value": kind, "inline": True}] if kind else []) + (
        [{"name": "ช่องทางโจมตี", "value": "\n".join(path), "inline": True}] if path else [])


def links(*pairs):
    return {"name": "ลิงก์", "value": " · ".join(f"[{label}]({url})" for label, url in pairs if url)}


def when(t):
    return f"<t:{int(t.timestamp())}:D>\n<t:{int(t.timestamp())}:R>"  # Discord renders date + "in 2 days" locally


def id_fields(cve, score, time_name, time_value):
    """The same inline row on every card: CVE, CVSS, then the date that matters for that kind of alert."""
    return [{"name": "CVE", "value": f"`{cve}`" if cve else "-", "inline": True},
            {"name": "CVSS", "value": f"**{score}**" if score else "-", "inline": True},
            {"name": time_name, "value": time_value or "-", "inline": True}]


# --- matchers: pure, return [(keys, embed)] (NVD: entries); keys[0] is the alert's own id, the rest dedupe
# `taken` holds every key already alerted; matchers add to it so later sources skip the same CVE.

def fix_cmd(ecosystem, name, version):
    tpl = FIX_CMD.get(ecosystem)
    return tpl and tpl.format(n=name, v=version.removeprefix("v"))


def package_field(eco, name, ranges):
    """One fix field per package: each affected range and its fixed version, then the upgrade commands to copy."""
    lines = [f"`{r or '?'}` → " + (f"อัปเป็น **{f}**" if f else "ยังไม่มี patch") for r, f in ranges]
    cmds = list(dict.fromkeys(c for _, f in ranges if f and (c := fix_cmd(eco, name, f))))
    if cmds:
        lines.append(f"```sh\n{chr(10).join(cmds)}\n```")
    elif not any(f for _, f in ranges):
        lines.append("ระหว่างนี้ให้หยุดใช้หรือจำกัดการใช้งาน แล้วติดตาม advisory")
    return {"name": cut(f"วิธีแก้: {name} ({ECOSYSTEMS.get(eco, eco)})", 256), "value": cut("\n".join(lines), 1024)}


def match_ghsa(advisories, taken, cutoff):
    out = []
    for a in advisories:
        keys = [f"ghsa:{a['ghsa_id']}"] + ([f"cve:{a['cve_id']}"] if a.get("cve_id") else [])
        fresh = max(ts(a["published_at"]), ts(a.get("github_reviewed_at") or a["published_at"]))
        if a["severity"] not in GHSA_SEVERITIES or a.get("withdrawn_at") or fresh < cutoff or keys[0] in taken:
            continue
        taken.update(keys)
        packages = {}
        for v in a.get("vulnerabilities") or []:
            p = v.get("package") or {}
            packages.setdefault((p.get("ecosystem", "?"), p.get("name", "?")), []).append(
                (v.get("vulnerable_version_range"), v.get("first_patched_version")))
        best = max((s for s in (a.get("cvss_severities") or {}).values() if s and s.get("score")), key=lambda s: s["score"], default={})
        cwes = [c["cwe_id"] for c in a.get("cwes") or []]
        body = " ".join(l for l in (a.get("description") or "").splitlines() if not l.lstrip().startswith("#"))
        kind = attack_type(cwes, f"{a.get('summary')} {body}", {c["cwe_id"]: c.get("name") for c in a.get("cwes") or []})
        names = [f"{name} ({ECOSYSTEMS.get(eco, eco)})" for eco, name in packages]
        out.append((keys, {
            "author": {"name": f"{OPEN_SOURCE} · GitHub Advisory"},
            "title": cut(a.get("summary"), 256),
            "url": a["html_url"],
            "description": cut(md(body), 220),
            "color": PURPLE,
            "fields": attack_fields(kind, attack_path(best.get("vector_string")))
                      + [package_field(eco, name, ranges) for (eco, name), ranges in list(packages.items())[:5]]
                      + ([{"name": "package อื่น", "value": f"และอีก {len(packages) - 5} package ดูทั้งหมดที่ GitHub Advisory"}]
                         if len(packages) > 5 else [])
                      + id_fields(a.get("cve_id"), best.get("score"), "เผยแพร่", when(ts(a["published_at"])))
                      + [links(("GitHub Advisory", a["html_url"]), ("NVD", a.get("cve_id") and nvd_url(a["cve_id"])),
                               (cwe := main_cwe(cwes), cwe and cwe_url(cwe)))],
            # footer on every card: what is affected
            "footer": {"text": cut((names[0] + (f" และอีก {len(names) - 1} package" if len(names) > 1 else "")) if names
                                   else a["ghsa_id"], 200)},
        }))
    return out


def cvss(cve):
    """Highest-scoring CVSS entry (NVD's own or the CNA's; v4, v3.1, v3.0) as (score, vector)."""
    m = cve.get("metrics", {})
    best = max((x["cvssData"] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") for x in m.get(k, [])),
               key=lambda d: d["baseScore"], default={})
    return best.get("baseScore", 0), best.get("vectorString", "")


def nvd_cwes(cve):
    return list(dict.fromkeys(d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                              if d["value"].startswith("CWE-")))


def nvd_fix(desc, patch):
    versions = fixed_in(desc)
    if versions:
        text = f"อัปเดตเป็น {' / '.join(versions)} ขึ้นไป" + (" (ตามสายเวอร์ชันที่ใช้)" if len(versions) > 1 else "")
        return text + (f" · [patch]({patch})" if patch else "")
    return f"[ติดตั้ง patch ของ vendor]({patch})" if patch else "ยังไม่ระบุ ดูรายละเอียดที่ NVD"


def match_nvd(cves, taken, cutoff):
    """NVD runs ~25-50 criticals a weekday, so each is a few-line entry (packed by `nvd_feed`), not a card."""
    out = []
    for c in cves:
        keys = [f"nvd:{c['id']}", f"cve:{c['id']}"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score, vector = cvss(c)
        if (keys[1] in taken or score < NVD_MIN_SCORE or c.get("vulnStatus") == "Rejected"
                or ts(c["published"]) < cutoff or int(c["id"].split("-")[1]) < cutoff.year - 1  # backfilled old bugs
                or c.get("sourceIdentifier") in MUTE_CNAS or any(w in desc.lower() for w in MUTE_WORDS)):
            continue
        taken.update(keys)
        cwes = nvd_cwes(c)
        kind = classify(cwes, desc)
        label = kind[0] if kind else (f"[{cwes[0]}]({cwe_url(cwes[0])})" if cwes else "")
        patch = next((r["url"] for r in c.get("references", []) if FIX_TAGS & set(r.get("tags", []))), None)
        lines = [f"**[{c['id']}]({nvd_url(c['id'])})** · CVSS **{score}**" + (f" · {label}" if label else ""),
                 cut(md(desc), 140)]
        if path := attack_path(vector):
            lines.append(f"**ช่องทางโจมตี** {' · '.join(path)}")
        lines.append(f"**วิธีแก้** {nvd_fix(desc, patch)}")
        out.append((score, keys, "\n".join(lines)))
    return [(keys, entry) for _, keys, entry in sorted(out, key=lambda x: -x[0])]  # worst first


def nvd_feed(entries):
    out, keys, batch = [], [], []
    for k, entry in entries:
        if batch and len("\n\n".join(batch + [entry])) > 3900:
            out.append((keys, batch))
            keys, batch = [], []
        keys, batch = keys + k, batch + [entry]
    if batch:
        out.append((keys, batch))
    return [(k, {
        "author": {"name": f"{NEW_CVE} · NVD"},
        "title": f"{len(b)} รายการ · CVSS ≥ {NVD_MIN_SCORE}",
        "description": "\n\n".join(b),
        "color": ORANGE,
        "footer": {"text": "กดเลข CVE เพื่อดูรายละเอียดเต็ม"},
    }) for k, b in out]


def match_kev(vulns, taken, cutoff, lookup=lambda cve: None):
    """`lookup(cve_id)` returns the NVD record (for CVSS and the attack path) or None."""
    out, since = [], cutoff.date().isoformat()
    for v in vulns:
        keys = [f"kev:{v['cveID']}"]  # own namespace: a CVE we already reported becoming exploited is news
        if keys[0] in taken or v["dateAdded"] < since:
            continue
        taken.update(keys)
        detail = lookup(v["cveID"]) or {}
        score, vector = cvss(detail)
        cwes = v.get("cwes") or nvd_cwes(detail)
        notes = (s.strip() for s in v.get("notes", "").split(";"))
        vendor = [u for u in notes if u.startswith("http") and not any(h in u for h in ("cisa.gov", "nvd.nist.gov"))]
        due = v.get("dueDate")
        kind = attack_type(cwes, f"{v.get('vulnerabilityName')} {v.get('shortDescription')}")
        out.append((keys, {
            "author": {"name": f"🚨 {EXPLOITED} · CISA KEV"},  # the one alert that pings, so the one with an emoji
            "title": cut(v.get("vulnerabilityName") or f"{v['vendorProject']} {v['product']}", 256),
            "url": nvd_url(v["cveID"]),
            "description": cut(md(v.get("shortDescription")), 220),
            "color": RED,
            "fields": attack_fields(kind, attack_path(vector)) + [
                {"name": "วิธีแก้", "value": numbered(kev_fix(v.get("requiredAction")))},
            ] + id_fields(v["cveID"], score, "ต้องแพตช์ภายใน", due and when(ts(due))) + (
                [{"name": "Ransomware", "value": "**ถูกใช้ในแคมเปญ ransomware แล้ว**"}]
                if v.get("knownRansomwareCampaignUse") == "Known" else []) + [
                links(*[((urllib.parse.urlsplit(u).hostname or "advisory").removeprefix("www."), u) for u in vendor[:2]],
                      ("NVD", nvd_url(v["cveID"])), (cwe := main_cwe(cwes), cwe and cwe_url(cwe))),
            ],
            "footer": {"text": f"{v['vendorProject']} · {v['product']}"},
        }))
    return out


# --- watcher health ------------------------------------------------------------------------------
# Notices are (embed, commit). `commit` records that the notice went out and runs only once Discord has
# accepted it, so a notice whose post failed is sent again next run instead of being lost.

def health(fail, name, err=None):
    """Count consecutive failures per source; speak once when it reaches FAIL_ALERT_AFTER and once on recovery.
    The count stops at the threshold, so a long outage doesn't rewrite state.json every run."""
    n = fail.get(name, 0)
    if err:
        if n < FAIL_ALERT_AFTER - 1:
            fail[name] = n + 1
        elif n == FAIL_ALERT_AFTER - 1:
            return ({"title": f"ดึงข่าวจาก {name} ไม่ได้", "color": YELLOW,
                     "description": f"ล้มเหลว {FAIL_ALERT_AFTER} รอบติดกัน (ประมาณ {FAIL_ALERT_AFTER * 5} นาที)\n"
                                    f"แหล่งอื่นยังทำงานปกติ\n```{cut(repr(err), 300)}```"},
                    lambda: fail.__setitem__(name, FAIL_ALERT_AFTER))
    elif n >= FAIL_ALERT_AFTER:
        return {"title": f"{name} กลับมาใช้ได้แล้ว", "color": GREEN}, lambda: fail.pop(name, None)
    else:
        fail.pop(name, None)


def digest(state, now, runs=lambda since: None):
    """Once a day: what went out in the last 24 h. Doubles as a heartbeat (silence means the watcher is dead),
    and a low run count means the 5-minute trigger is (GitHub's own cron alone fires every few hours)."""
    today = now.date().isoformat()
    if now.hour < DIGEST_HOUR_UTC or state.get("digest") == today:
        return None
    since = now - timedelta(days=1)
    n = Counter(k.split(":")[0] for k, t in state["seen"].items() if ts(t) >= since)
    try:
        count = runs(since)
    except Exception as e:  # the summary still goes out without the count
        print(f"run count: {e!r}", file=sys.stderr)
        count = None
    embed = {
        "title": "สรุป 24 ชั่วโมงที่ผ่านมา",
        "description": "ตัวเฝ้ายังทำงานปกติ",
        "color": GREEN,
        "fields": [
            {"name": EXPLOITED, "value": f"**{n['kev']}**", "inline": True},
            {"name": OPEN_SOURCE, "value": f"**{n['ghsa']}**", "inline": True},
            {"name": NEW_CVE, "value": f"**{n['nvd']}**", "inline": True},
        ] + ([{"name": "รอบตรวจ", "value": f"**{count}** รอบ", "inline": True}] if count is not None else []),
        "footer": {"text": "ถ้าวันไหนไม่มีข้อความนี้ แปลว่าตัวเฝ้าหยุดทำงาน"},
    }
    if count is not None and count < MIN_RUNS_PER_DAY:
        embed["color"] = YELLOW
        embed["description"] = (f"**รอบตรวจน้อยผิดปกติ: {count} รอบ (ปกติประมาณ 288)**\n"
                                "ตัวสั่งรันทุก 5 นาทีใน Cloudflare อาจหยุดทำงาน หรือ GitHub token หมดอายุ\n"
                                "ข่าวยังมาตามปกติ แต่จะช้าลงหลายชั่วโมง")
    return embed, lambda: state.__setitem__("digest", today)


def last_dispatch():
    """When this workflow was last dispatched (by the Worker in trigger/), or None if never."""
    repo = os.environ.get("GITHUB_REPOSITORY", "NiraphatK/security-alert")
    d, _ = fetch(f"https://api.github.com/repos/{repo}/actions/workflows/watch.yml/runs?event=workflow_dispatch&per_page=1",
                 gh_headers())
    return ts(d["workflow_runs"][0]["created_at"]) if d["workflow_runs"] else None


def trigger_check(state, now, event, dispatched=last_dispatch):
    """GitHub's own cron is only the fallback. When it is what started this run and the Worker hasn't dispatched
    for TRIGGER_STALE, the 5-minute trigger is down (most often its GitHub token expired): say so once."""
    if event == "workflow_dispatch" and state.get("trigger_down"):
        return {"title": "ตัวสั่งรันทุก 5 นาทีกลับมาทำงานแล้ว", "color": GREEN}, lambda: state.pop("trigger_down", None)
    if event != "schedule" or state.get("trigger_down"):
        return None
    try:
        last = dispatched()
    except Exception as e:  # can't tell; don't cry wolf
        print(f"last dispatch: {e!r}", file=sys.stderr)
        return None
    if last and now - last < TRIGGER_STALE:
        return None
    gap = f"{int((now - last).total_seconds() // 60)} นาที" if last else "นานแล้ว"
    return ({"title": "ตัวสั่งรันทุก 5 นาทีหยุดทำงาน", "url": README, "color": YELLOW,
             "description": f"Cloudflare Worker ไม่ได้สั่งรันมา {gap}\n"
                            "ตอนนี้เหลือแค่รอบสำรองของ GitHub ซึ่งห่างกันหลายชั่วโมง ข่าวจะมาช้า\n\n"
                            "**สาเหตุที่พบบ่อย** GitHub token ของ Worker หมดอายุ\n"
                            "**วิธีแก้** กดหัวข้อนี้ แล้วทำตามหัวข้อเปลี่ยน token ใน README"},
            lambda: state.__setitem__("trigger_down", True))


def prune(seen, now):
    for k in [k for k, t in seen.items() if ts(t) < now - KEEP_SEEN]:
        del seen[k]


# --- discord -------------------------------------------------------------------------------------

class Rejected(Exception):
    """Discord refused the message (a 4xx other than 429): sending the same thing again won't help."""


def size(e):
    return (len(e.get("title") or "") + len(e.get("description") or "") + len(e.get("footer", {}).get("text", ""))
            + len(e.get("author", {}).get("name", "")) + sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", [])))


def fit(e, limit=5900):
    """Drop fields from the end, keeping the last one (the links), until the embed is under Discord's 6000 cap."""
    while size(e) > limit and len(e.get("fields", [])) > 1:
        del e["fields"][-2]
    return e


def batches(alerts):
    """Pack alerts into messages within Discord's limits: 10 embeds and 6000 characters each."""
    batch, total = [], 0
    for a in alerts:
        n = size(fit(a[1]))
        if batch and (len(batch) == 10 or total + n > 6000):
            yield batch
            batch, total = [], 0
        batch.append(a)
        total += n
    if batch:
        yield batch


def post(payload):
    """Send one message, retrying rate limits, Discord-side errors and timeouts. Raises Rejected on a 4xx."""
    if not HOOK:
        print(json.dumps(payload, ensure_ascii=False, indent=1))
        return
    req = urllib.request.Request(HOOK, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": UA})
    for attempt in range(5):
        try:
            urllib.request.urlopen(req, timeout=30).close()
            return
        except urllib.error.HTTPError as e:
            body = e.read()
            if e.code == 429:
                try:
                    time.sleep(float(json.loads(body)["retry_after"]))
                except (ValueError, KeyError, TypeError):
                    time.sleep(2)
                continue
            if e.code < 500:
                raise Rejected(f"Discord {e.code}: {body[:500].decode(errors='replace')}") from None
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(5 * (attempt + 1))
    raise RuntimeError("Discord unreachable after 5 tries")


def save(state):
    if HOOK:
        STATE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def send(alerts, state, now, ping=False):
    """Post alerts, marking each seen once Discord has it. A message Discord rejects is retried one alert at a
    time, and an alert it still rejects goes out as a bare link to its source and is marked seen, so one bad
    alert can't hold back the rest run after run. Returns the rejections, for the log."""
    def message(embeds):
        return {"content": "@here" if ping else "", "embeds": embeds,
                "allowed_mentions": {"parse": ["everyone"] if ping else []}}  # feed text must never ping anyone

    rejected = []
    for batch in batches(alerts):
        try:
            post(message([e for _, e in batch]))
        except Rejected as err:
            if len(batch) > 1:
                for alert in batch:
                    rejected += send([alert], state, now, ping)
                continue
            keys, e = batch[0]
            rejected.append(f"{keys[0]}: {err}")
            bare = {"title": cut(e.get("title") or keys[0], 256), "url": e.get("url"), "color": e.get("color"),
                    "description": "ข้อความเต็มส่งไม่ได้ (Discord ปฏิเสธ)\nกดหัวข้อเพื่อดูรายละเอียดที่ต้นทาง"}
            try:
                post(message([{k: v for k, v in bare.items() if v}]))
            except Rejected:
                pass
        for keys, _ in batch:
            state["seen"].update(dict.fromkeys(keys, now.isoformat(timespec="seconds")))
        save(state)  # after every message, so a crash mid-run neither repeats nor loses alerts
    return rejected


def main():
    now = datetime.now(UTC)
    first = not STATE.exists()
    state = {"seen": {}, "fail": {}, "digest": now.date().isoformat()} if first else json.loads(STATE.read_text())
    taken, news, kev, notices, errors = set(state["seen"]), [], [], [], []
    sources = [  # KEV first so a slow NVD can't hold it up; GitHub before NVD so NVD skips CVEs it covered
        ("CISA KEV", kev, lambda: match_kev(get_kev(), taken, now - KEV_LOOKBACK, nvd_lookup())),
        ("GitHub Advisory", news, lambda: match_ghsa(get_ghsa(now - GHSA_LOOKBACK), taken, now - GHSA_LOOKBACK)),
        ("NVD", news, lambda: nvd_feed(match_nvd(get_nvd(now), taken, now - NVD_LOOKBACK))),
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

    if first and HOOK:  # seed quietly instead of flooding the channel with the past days
        backdated = (now - timedelta(days=1)).isoformat(timespec="seconds")  # keeps them out of the first digest
        for keys, _ in news + kev:
            state["seen"].update(dict.fromkeys(keys, backdated))
        notices.append(({
            "title": "เริ่มเฝ้าระวังแล้ว", "color": GREEN,
            "description": f"ข้ามข่าวเก่า {len(news) + len(kev)} รายการ\nจากนี้แจ้งทันทีที่มีของใหม่\n\n"
                           f"- **{EXPLOITED}** แจ้งพร้อม @here\n- **{OPEN_SOURCE}** พร้อมคำสั่งอัปเกรด\n- **{NEW_CVE}** ทุก vendor",
        }, lambda: None))
        news, kev = [], []

    prune(state["seen"], now)
    rejected = []
    try:
        rejected += send(kev, state, now, ping=True)
        rejected += send(news, state, now)
        for notice in (digest(state, now, count_runs), trigger_check(state, now, os.environ.get("GITHUB_EVENT_NAME"))):
            if notice:
                notices.append(notice)
        if notices:
            post({"embeds": [fit(e) for e, _ in notices], "allowed_mentions": {"parse": []}})
            for _, commit in notices:
                commit()
    finally:
        save(state)
    print(f"sent: kev={len(kev)} news={len(news)} notices={len(notices)} failed_sources={errors}")
    if rejected:  # fail this one run, so the workflow's failure notice points at a log naming what Discord refused
        sys.exit("Discord rejected:\n" + "\n".join(rejected))


def preview(now):
    """PREVIEW=true: post one real sample of each message type from the past week; state is untouched."""
    week = now - timedelta(days=7)
    latest_kev = max(get_kev(), key=lambda v: v["dateAdded"])
    samples = (match_kev([latest_kev], set(), week, nvd_lookup()) + match_ghsa(get_ghsa(week), set(), week)[:1]
               + nvd_feed(match_nvd(get_nvd(now), set(), now - NVD_LOOKBACK)[:4]))
    samples.append(([], digest({"seen": {}}, now.replace(hour=12))[0]))
    for i, batch in enumerate(batches(samples)):
        post({"content": "ตัวอย่างหน้าตาข้อความ (ข้อมูลจริงจากสัปดาห์นี้)" if i == 0 else "",
              "embeds": [e for _, e in batch], "allowed_mentions": {"parse": []}})


if __name__ == "__main__":
    preview(datetime.now(UTC)) if os.environ.get("PREVIEW") == "true" else main()

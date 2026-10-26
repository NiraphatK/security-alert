"""Offline checks for watch.py: python3 test_watch.py"""
from datetime import UTC, datetime, timedelta

import watch

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)
CUT = NOW - watch.LOOKBACK
NET_NOAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def ghsa(id, severity="critical", published="2026-10-25T10:00:00Z", reviewed=None, cve=None, withdrawn=None):
    return {
        "ghsa_id": id, "cve_id": cve, "severity": severity, "published_at": published, "github_reviewed_at": reviewed,
        "updated_at": "2026-10-25T11:00:00Z", "withdrawn_at": withdrawn, "html_url": f"https://github.com/advisories/{id}",
        "summary": "RCE in next",
        "cvss_severities": {"cvss_v3": {"score": 9.8, "vector_string": NET_NOAUTH}, "cvss_v4": {"score": None, "vector_string": None}},
        "cwes": [{"cwe_id": "CWE-94", "name": "Code Injection"}],
        "description": "## Summary\n\nCrafted *headers* reach eval.\n\n### Impact\nFull takeover.",
        "vulnerabilities": [
            {"package": {"ecosystem": "npm", "name": "next"}, "vulnerable_version_range": ">= 15.0.0, < 15.2.3", "first_patched_version": "15.2.3"},
            {"package": {"ecosystem": "npm", "name": "next"}, "vulnerable_version_range": "< 14.2.25", "first_patched_version": "14.2.25"},
            {"package": {"ecosystem": "maven", "name": "org.x:y"}, "vulnerable_version_range": "<= 1.0", "first_patched_version": None},
        ],
    }


def nvd(id, score=9.8, metric="cvssMetricV31", desc="SQL injection in foo before 1.0.8", published="2026-10-24T10:15:30.123",
        status="Received", tags=("Patch",), cna="cna@example.com", cwes=("CWE-89",), vector=NET_NOAUTH):
    return {
        "id": id, "published": published, "vulnStatus": status, "sourceIdentifier": cna,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {metric: [{"cvssData": {"baseScore": score, "vectorString": vector}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": c} for c in cwes]}],
        "references": [{"url": "https://blog.example/post"}, {"url": "https://example.com/patch", "tags": list(tags)}],
    }


def kev(id, added="2026-10-25", ransomware="Unknown", cwes=("CWE-787",)):
    return {
        "cveID": id, "vendorProject": "Apple", "product": "macOS", "dateAdded": added, "dueDate": "2026-11-15",
        "vulnerabilityName": "Apple macOS Kernel Vulnerability", "shortDescription": "Kernel bug",
        "requiredAction": "Apply mitigations per vendor instructions, ensuring compliance with BOD 26-04. Follow applicable "
                          "guidance or discontinue use of the product if mitigations are unavailable.",
        "knownRansomwareCampaignUse": ransomware, "cwes": list(cwes),
        "notes": "https://support.apple.com/1234 ; ; BOD 26-04: https://www.cisa.gov/bod ; https://nvd.nist.gov/vuln/detail/" + id,
    }


def test_classify():
    assert watch.classify(["NVD-CWE-noinfo", "CWE-89", "CWE-79"], "") == watch.CWE_ATTACK["CWE-89"]  # record's own order
    assert watch.classify(["CWE-79", "CWE-1336"], "")[0] == "Cross-Site Scripting (XSS)"  # primary CWE beats table order
    assert watch.classify([], "A heap buffer overflow in foo")[0] == "Memory Corruption"  # keyword fallback
    assert watch.classify(["CWE-1284"], "nothing recognisable") is None
    assert watch.main_cwe(["CWE-197", "CWE-843"]) == "CWE-843" and watch.main_cwe(["CWE-1284"]) == "CWE-1284"
    assert watch.main_cwe([]) is None
    assert watch.attack_type(["CWE-1284"], "", {"CWE-1284": "Bad Quantity"}) == \
        "[CWE-1284 Bad Quantity](https://cwe.mitre.org/data/definitions/1284.html)"


def test_attack_path():
    assert watch.attack_path(NET_NOAUTH) == ["ผ่านอินเทอร์เน็ต", "ไม่ต้องล็อกอิน", "เหยื่อไม่ต้องทำอะไร"]
    v4 = "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert watch.attack_path(v4) == ["ต้องเข้าเครื่องได้ก่อน", "ต้องมีสิทธิ์ admin", "ต้องหลอกให้เหยื่อกดหรือเปิดไฟล์"]
    assert watch.attack_path("") == [] and watch.attack_path(None) == []


def test_fixed_in():
    assert watch.fixed_in("mem0 0.1.117 before 1.0.8 contains an sql injection") == ["1.0.8"]
    assert watch.fixed_in("Prior to 36.0.19, 48.0.7, and 49.0.4, the backend…") == ["36.0.19", "48.0.7", "49.0.4"]
    assert watch.fixed_in("From 1.4.0-beta.18 until 1.7.7, deployments…") == ["1.7.7"]
    assert watch.fixed_in("This issue is fixed in version v2.1.4.") == ["2.1.4"]
    assert watch.fixed_in("YOOtheme Pro 5.0.0-5.0.52 allows RCE before authentication") == []


def test_kev_fix():
    steps = watch.kev_fix(kev("x")["requiredAction"])
    assert len(steps) == 2 and steps[0].startswith("ติดตั้งอัปเดตหรือทำตามวิธีแก้ของ vendor") and "หยุดใช้" in steps[1]
    assert watch.kev_fix("Apply updates per vendor instructions.") == ["ติดตั้งอัปเดตหรือทำตามวิธีแก้ของ vendor (ลิงก์ด้านล่าง)"]
    assert watch.kev_fix("Remove the device from the network, ensuring compliance with BOD.") == ["Remove the device from the network"]
    assert watch.numbered(["a", "b"]) == "1. a\n2. b" and watch.numbered(["only"]) == "only" and watch.numbered([]) == "-"


def test_ghsa():
    taken = {"ghsa:GHSA-seen"}
    out = watch.match_ghsa([
        ghsa("GHSA-new", cve="CVE-1"),
        ghsa("GHSA-high", severity="high"),
        ghsa("GHSA-gone", withdrawn="2026-10-25T11:00:00Z"),
        ghsa("GHSA-old", published="2026-09-01T00:00:00Z"),
        ghsa("GHSA-late", published="2026-09-01T00:00:00Z", reviewed="2026-10-25T09:00:00Z"),  # old CVE, reviewed just now
        ghsa("GHSA-seen"),
    ], taken, CUT)
    assert [k[0] for k, _ in out] == ["ghsa:GHSA-new", "ghsa:GHSA-late"], out
    keys, e = out[0]
    assert keys == ["ghsa:GHSA-new", "cve:CVE-1"] and "cve:CVE-1" in taken
    assert e["author"]["name"] == "CRITICAL 9.8 · GitHub Advisory" and e["title"] == "RCE in next"
    assert e["description"] == r"Crafted \*headers\* reach eval. Full takeover.", e["description"]  # headings dropped
    assert e["footer"]["text"] == "CVE-1 · GHSA-new"
    kind, path, nxt, maven, link = e["fields"]  # ranges of one package share a field
    assert kind == {"name": "ประเภทการโจมตี", "value": "**Remote Code Execution**\nรันโค้ดบนเครื่องเป้าหมายได้ = ยึดเครื่องได้", "inline": True}
    assert path == {"name": "ช่องทางโจมตี", "value": "ผ่านอินเทอร์เน็ต\nไม่ต้องล็อกอิน\nเหยื่อไม่ต้องทำอะไร", "inline": True}
    assert nxt["name"] == "วิธีแก้: next (npm)" and nxt["value"].startswith("`>= 15.0.0, < 15.2.3` → อัปเป็น **15.2.3**\n")
    assert nxt["value"].endswith("```sh\nnpm i next@15.2.3\nnpm i next@14.2.25\n```"), nxt["value"]
    assert maven["name"] == "วิธีแก้: org.x:y (Maven)" and maven["value"] == (
        "`<= 1.0` → ยังไม่มี patch\nระหว่างนี้ให้หยุดใช้หรือจำกัดการใช้งาน แล้วติดตาม advisory")
    assert link["value"] == ("[GitHub Advisory](https://github.com/advisories/GHSA-new) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-1)"
                             " · [CWE-94](https://cwe.mitre.org/data/definitions/94.html)"), link["value"]
    assert "[NVD]" not in out[1][1]["fields"][-1]["value"]  # no CVE id, no NVD link


def test_nvd():
    taken = {"cve:CVE-2026-9"}
    out = watch.match_nvd([
        nvd("CVE-2026-1"),
        nvd("CVE-2025-2", score=9.3, metric="cvssMetricV40", tags=(), cwes=("NVD-CWE-noinfo",), desc="Bad thing in bar"),
        nvd("CVE-2026-3", score=8.8),
        nvd("CVE-2026-4", desc="SQLi in the Foo plugin for WordPress"),
        nvd("CVE-2026-5", cna="audit@patchstack.com"),
        nvd("CVE-2026-6", status="Rejected"),
        nvd("CVE-2026-7", published="2026-10-01T00:00:00.000"),
        nvd("CVE-2026-8", score=0),
        nvd("CVE-2026-9"),  # already alerted by GitHub Advisory
        nvd("CVE-2021-10"),  # old bug backfilled this week
    ], taken, NOW - watch.NVD_LOOKBACK)
    assert [k[0] for k, _ in out] == ["nvd:CVE-2026-1", "nvd:CVE-2025-2"], out  # sorted worst first
    assert out[0][1] == (
        "**[CVE-2026-1](https://nvd.nist.gov/vuln/detail/CVE-2026-1)** · CVSS **9.8** · SQL Injection\n"
        "SQL injection in foo before 1.0.8\n"
        "**ช่องทาง** ผ่านอินเทอร์เน็ต · ไม่ต้องล็อกอิน · เหยื่อไม่ต้องทำอะไร\n"
        "**วิธีแก้** อัปเดตเป็น 1.0.8 ขึ้นไป · [patch](https://example.com/patch)"), out[0][1]
    assert out[1][1].startswith("**[CVE-2025-2](https://nvd.nist.gov/vuln/detail/CVE-2025-2)** · CVSS **9.3**\n")  # no label
    assert out[1][1].endswith("\n**วิธีแก้** ยังไม่ระบุ ดูรายละเอียดที่ NVD")
    feed = watch.nvd_feed(out * 40)
    assert len(feed) > 1 and all(len(e["description"]) <= 4096 for _, e in feed)
    assert sum(len(k) for k, _ in feed) == 2 * 2 * 40  # every CVE's keys land in some message
    assert feed[0][1]["title"] == f"{feed[0][1]['description'].count('**[')} รายการ · CVSS ≥ 9.0"


def test_nvd_fix():
    assert watch.nvd_fix("foo before 1.2.3", None) == "อัปเดตเป็น 1.2.3 ขึ้นไป"
    assert watch.nvd_fix("prior to 1.2.3 and 2.0.1", None) == "อัปเดตเป็น 1.2.3 / 2.0.1 ขึ้นไป (ตามสายเวอร์ชันที่ใช้)"
    assert watch.nvd_fix("no versions", "https://v.example/fix") == "[ติดตั้ง patch ของ vendor](https://v.example/fix)"


def test_md():
    assert watch.md("click [here](https://evil)\n**now**") == r"click \[here\]\(https://evil\) \*\*now\*\*"


def test_kev():
    taken = {"kev:CVE-seen", "cve:CVE-again"}
    lookup = {"CVE-new": nvd("CVE-new", score=9.8, vector=NET_NOAUTH)}.get
    vulns = [kev("CVE-new", ransomware="Known"), kev("CVE-old", added="2026-10-01"), kev("CVE-seen"), kev("CVE-again", cwes=())]
    out = watch.match_kev(vulns, taken, CUT, lookup)
    assert [k[0] for k, _ in out] == ["kev:CVE-new", "kev:CVE-again"], out  # reported CVE now exploited = alert again
    e = out[0][1]
    assert e["title"] == "Apple macOS Kernel Vulnerability" and e["author"]["name"] == "🚨 ถูกโจมตีจริง · CISA KEV"
    assert e["description"] == "Kernel bug"
    names = [f["name"] for f in e["fields"]]
    assert names == ["ประเภทการโจมตี", "ช่องทางโจมตี", "วิธีแก้", "CVE", "CVSS", "ต้องแพตช์ภายใน", "Ransomware", "ลิงก์"], names
    fields = {f["name"]: f["value"] for f in e["fields"]}
    assert fields["ประเภทการโจมตี"] == "**Memory Corruption**\nทำให้โปรแกรมล่ม ข้อมูลรั่ว หรือรันโค้ดได้"
    assert fields["ช่องทางโจมตี"] == "ผ่านอินเทอร์เน็ต\nไม่ต้องล็อกอิน\nเหยื่อไม่ต้องทำอะไร"
    assert fields["วิธีแก้"].startswith("1. ติดตั้งอัปเดต") and "\n2. ถ้ายังไม่มีวิธีแก้" in fields["วิธีแก้"]
    assert fields["Ransomware"] == "**ถูกใช้ในแคมเปญ ransomware แล้ว**"
    assert fields["CVSS"] == "**9.8**" and fields["ต้องแพตช์ภายใน"] == "<t:1794700800:D>\n<t:1794700800:R>"  # 2026-11-15 UTC
    assert fields["ลิงก์"] == ("[support.apple.com](https://support.apple.com/1234) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-new)"
                               " · [CWE-787](https://cwe.mitre.org/data/definitions/787.html)"), fields["ลิงก์"]
    # NVD lookup failed or had nothing: still a complete alert, just without CVSS or attack path
    again = out[1][1]
    again_fields = {f["name"]: f["value"] for f in again["fields"]}
    assert again_fields["CVSS"] == "-" and "ช่องทางโจมตี" not in again_fields and "Ransomware" not in again_fields


def test_fix_cmd():
    assert watch.fix_cmd("go", "golang.org/x/net", "v0.33.0") == "go get golang.org/x/net@v0.33.0"
    assert watch.fix_cmd("pip", "django", "5.1.4") == 'pip install -U "django>=5.1.4"'
    assert watch.fix_cmd("maven", "org.x:y", "1.1") is None


def test_batches():
    small = [([str(i)], {"title": "x"}) for i in range(25)]
    assert [len(b) for b in watch.batches(small)] == [10, 10, 5]
    big = [([str(i)], {"description": "x" * 2500}) for i in range(5)]
    assert [len(b) for b in watch.batches(big)] == [2, 2, 1]


def test_health():
    fail = {}
    said = [watch.health(fail, "NVD", OSError("down")) for _ in range(watch.FAIL_ALERT_AFTER + 3)]
    assert [s is not None for s in said].count(True) == 1 and said[watch.FAIL_ALERT_AFTER - 1]["title"] == "ดึงข่าวจาก NVD ไม่ได้"
    assert watch.health(fail, "NVD")["title"] == "NVD กลับมาใช้ได้แล้ว" and "NVD" not in fail
    watch.health(fail, "KEV", OSError("blip"))
    assert watch.health(fail, "KEV") is None  # a short blip recovers silently


def test_digest_and_prune():
    iso = lambda d: d.isoformat(timespec="seconds")
    state = {"digest": "2026-10-24", "seen": {
        "kev:A": iso(NOW - timedelta(hours=1)), "ghsa:B": iso(NOW - timedelta(hours=2)), "cve:B": iso(NOW - timedelta(hours=2)),
        "nvd:C": iso(NOW - timedelta(days=2)), "nvd:D": iso(NOW - timedelta(days=31)),
    }}
    assert watch.digest(state, NOW.replace(hour=1), ) is None  # before 09:00 Bangkok
    counts = [f["value"] for f in watch.digest(state, NOW)["fields"]]
    assert counts == ["**1**", "**1**", "**0**"], counts  # kev, ghsa, nvd
    assert watch.digest(state, NOW) is None  # once a day
    watch.prune(state["seen"], NOW)
    assert "nvd:D" not in state["seen"] and "nvd:C" in state["seen"]


def test_digest_run_count():
    fresh = lambda: {"digest": "2026-10-24", "seen": {}}
    ok = watch.digest(fresh(), NOW, lambda since: 286)
    assert ok["color"] == watch.GREEN and ok["description"] == "ตัวเฝ้ายังทำงานปกติ" and ok["fields"][-1]["value"] == "**286** รอบ"
    slow = watch.digest(fresh(), NOW, lambda since: 7)  # Worker dead: only GitHub's own sparse cron ran
    assert slow["color"] == watch.YELLOW and "7 รอบ" in slow["description"]

    def broken(since):
        raise OSError("api down")
    quiet = watch.digest(fresh(), NOW, broken)  # no count, but the heartbeat still goes out
    assert quiet["color"] == watch.GREEN and [f["name"] for f in quiet["fields"]] == ["ถูกโจมตีจริง", "Open-source", "CVE ใหม่"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)

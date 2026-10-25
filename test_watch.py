"""Offline checks for watch.py: python3 test_watch.py"""
from datetime import UTC, datetime, timedelta

import watch

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)
CUT = NOW - watch.LOOKBACK


def ghsa(id, severity="critical", published="2026-10-25T10:00:00Z", reviewed=None, cve=None, withdrawn=None):
    return {
        "ghsa_id": id, "cve_id": cve, "severity": severity, "published_at": published, "github_reviewed_at": reviewed,
        "updated_at": "2026-10-25T11:00:00Z", "withdrawn_at": withdrawn, "html_url": f"https://github.com/advisories/{id}",
        "summary": "RCE in next", "cvss_severities": {"cvss_v3": {"score": 9.8}, "cvss_v4": {"score": None}},
        "description": "## Summary\n\nCrafted *headers* reach eval.\n\n### Impact\nFull takeover.",
        "vulnerabilities": [
            {"package": {"ecosystem": "npm", "name": "next"}, "vulnerable_version_range": ">= 15.0.0, < 15.2.3", "first_patched_version": "15.2.3"},
            {"package": {"ecosystem": "npm", "name": "next"}, "vulnerable_version_range": "< 14.2.25", "first_patched_version": "14.2.25"},
            {"package": {"ecosystem": "maven", "name": "org.x:y"}, "vulnerable_version_range": "<= 1.0", "first_patched_version": None},
        ],
    }


def nvd(id, score=9.8, metric="cvssMetricV31", desc="Overflow in foo", published="2026-10-24T10:15:30.123", status="Received",
        tags=("Patch",), cna="cna@example.com"):
    return {
        "id": id, "published": published, "vulnStatus": status, "sourceIdentifier": cna,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {metric: [{"cvssData": {"baseScore": score}}]},
        "references": [{"url": "https://blog.example/post"}, {"url": "https://example.com/patch", "tags": list(tags)}],
    }


def kev(id, added="2026-10-25", ransomware="Unknown"):
    return {
        "cveID": id, "vendorProject": "Apple", "product": "macOS", "dateAdded": added, "dueDate": "2026-11-15",
        "vulnerabilityName": "Apple macOS Kernel Vulnerability", "shortDescription": "Kernel bug",
        "requiredAction": "Apply updates per vendor instructions, ensuring compliance with BOD 26-04 (see URL in Notes). Follow guidance.",
        "knownRansomwareCampaignUse": ransomware,
        "notes": "https://support.apple.com/1234 ; ; BOD 26-04: https://www.cisa.gov/bod ; https://nvd.nist.gov/vuln/detail/" + id,
    }


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
    assert e["author"]["name"] == "🩹 CRITICAL 9.8 · GitHub Advisory" and e["title"] == "RCE in next"
    assert e["description"] == r"Crafted \*headers\* reach eval. Full takeover.", e["description"]  # headings dropped
    assert e["footer"]["text"] == "CVE-1 · GHSA-new"
    nxt, maven = e["fields"]  # ranges of one package share a field
    assert nxt["name"] == "📦 next · npm" and nxt["value"].count("โดน") == 2
    assert nxt["value"].endswith("```sh\nnpm i next@15.2.3\nnpm i next@14.2.25\n```"), nxt["value"]
    assert maven["name"] == "📦 org.x:y · Maven" and "ยังไม่มี patch" in maven["value"] and "```" not in maven["value"]


def test_nvd():
    taken = {"cve:CVE-2026-9"}
    out = watch.match_nvd([
        nvd("CVE-2026-1"),
        nvd("CVE-2025-2", score=9.3, metric="cvssMetricV40", tags=()),
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
    assert out[0][1] == "`9.8`  **[CVE-2026-1](https://nvd.nist.gov/vuln/detail/CVE-2026-1)** · [🩹 patch](https://example.com/patch)\nOverflow in foo"
    assert "patch" not in out[1][1]
    feed = watch.nvd_feed(out * 40)
    assert len(feed) > 1 and all(len(e["description"]) <= 4096 for _, e in feed)
    assert sum(len(k) for k, _ in feed) == 2 * 2 * 40  # every CVE's keys land in some message
    assert feed[0][1]["title"] == f"{feed[0][1]['description'].count('**[')} รายการ · CVSS ≥ 9.0"


def test_md():
    assert watch.md("click [here](https://evil)\n**now**") == r"click \[here\]\(https://evil\) \*\*now\*\*"


def test_kev():
    taken = {"kev:CVE-seen", "cve:CVE-again"}
    out = watch.match_kev([kev("CVE-new", ransomware="Known"), kev("CVE-old", added="2026-10-01"), kev("CVE-seen"), kev("CVE-again")], taken, CUT)
    assert [k[0] for k, _ in out] == ["kev:CVE-new", "kev:CVE-again"], out  # reported CVE now exploited = alert again
    e = out[0][1]
    assert e["title"] == "Apple macOS Kernel Vulnerability" and e["author"]["name"] == "🚨 ถูกโจมตีจริง · CISA KEV"
    fields = {f["name"]: f["value"] for f in e["fields"]}
    assert fields["🔗 วิธีแก้"] == "[support.apple.com](https://support.apple.com/1234) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-new)"
    assert fields["🛠️ ต้องทำ"] == "Apply updates per vendor instructions"  # directive boilerplate trimmed
    assert fields["⏰ แพตช์ภายใน"] == "<t:1794700800:D>\n<t:1794700800:R>"  # 2026-11-15 00:00 UTC
    assert fields["🦠 Ransomware"] == "⚠️ ใช้แล้ว" and {f["name"]: f["value"] for f in out[1][1]["fields"]}["🦠 Ransomware"] == "ยังไม่พบ"


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
    assert [s is not None for s in said].count(True) == 1 and said[watch.FAIL_ALERT_AFTER - 1]["title"].startswith("⚠️")
    assert watch.health(fail, "NVD")["title"].startswith("✅") and "NVD" not in fail
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


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)

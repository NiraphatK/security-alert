# Broader tech security coverage

The user selected security news across developer tools, AI, extensions/packages, cloud,
operating systems, browsers, and breaches, and explicitly asked to implement the
recommended multi-source approach without another design review.

Add OpenSourceMalware, BleepingComputer, The Hacker News, and SecurityWeek RSS feeds
alongside the existing KEV, critical GHSA, and NVD feeds. Verified all four feeds live.
Reports need no CVE or CVSS. Keep reports tied to their publisher, with a source link;
do not invent impact, remediation, or Thai translations of English source content.

Use the existing Python standard library watcher, delivery, seen-state pruning,
health reporting, and preview path. No new dependency, service, credential, or AI API.
Support RSS and Atom; filter for incident/vulnerability news and explicit promotional
content, sanitize HTML and links, and skip individual invalid entries.

News lookback is 24 hours, including on the first run after enabling these feeds in
an existing installation. Normal first-install startup continues to seed quietly.
Deduplicate normalized article URLs across feeds and runs; different reports of the
same incident can still appear. News must not suppress later official CVE/KEV alerts.
Include news in the daily summary, startup notice, preview, and README.

## Approaches

Selected: multiple security news feeds plus existing vulnerability databases, for
early coverage of malware and supply-chain incidents. Vendor-only feeds were
considered but require many integrations and miss early researcher reports.

## Limits

No finite feed list guarantees complete coverage. Keyword filtering can miss reports,
publishers can delay or truncate feeds, and English headlines/summaries remain English.
No deploy, shared-branch push, or live Discord test is part of the local implementation.

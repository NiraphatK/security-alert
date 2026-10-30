# Tech Security News Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Alert on tech security reports even when no CVE or CVSS exists.

**Architecture:** Add RSS/Atom parsing to the standard-library watcher and feed its
news cards through existing delivery, deduplication, and per-source health handling.
Keep vulnerability database selection and exploitation mentions intact.

**Tech Stack:** Python 3.11+ standard library, existing assert-based offline suite.

**Spec:** `docs/superpowers/specs/2026-10-30-tech-security-news-design.md`

## Global Constraints

- No new dependency, service, credential, or AI API.
- Four verified feeds; 24-hour news lookback; no CVE requirement.
- Article URL deduplication must not suppress official CVE/KEV alerts.
- Reuse delivery, health, state pruning, preview, and daily summary.
- User authorized direct execution; work on a feature branch in this clean checkout.

## Review Focus

- Mixed feeds must exclude unrelated tech releases and explicit advertisements.
- Invalid dates, empty links, and non-HTTP URLs must not discard healthy entries.
- RSS HTML and Atom XHTML must render as plain text, without forged Discord links.
- Canonical URLs must retain identity-bearing query parameters.
- A failed news source must not prevent other sources from delivering alerts.

### Task 1: News parsing, delivery integration, and documentation

**Files:** Modify `watch.py`, `test_watch.py`, and `README.md`.

**Interfaces:** `get_news(url)` returns normalized article dictionaries;
`parse_news(root)` parses RSS/Atom XML; `match_news(articles, taken, cutoff, source)`
returns existing `(keys, embed)` alert tuples using `news:` keys only.
`fetch(..., decode=json.loads)` allows XML decoding with existing gzip/retry handling.

- [x] Add fixtures/tests for no-CVE Claude Code backdoor reports, RSS/Atom parsing,
  filtering, URL deduplication, malformed entries, HTML safety, and gzip XML.
- [x] Run `python3 -B test_watch.py`; confirm the new tests fail before production edits.
- [x] Implement minimal parsing/matching and add the four sources to `main()`;
  include news in `digest()`, startup, and `preview()`.
- [x] Test main integration with one failed feed, multiple successful feeds, delivery
  state recording, repeat-run suppression, and preview state preservation.
- [x] Update coverage, first-run behavior, source settings, and limits in README.
- [x] Run the complete offline suite and `git diff --check`; live-read all four
  feeds without posting or saving state and confirm the Claude report matches.
- [x] Have one fresh reviewer inspect the diff, then fix important findings with
  regression tests. Leave changes local for user review; no automatic push/deploy.

## Execution record

- Baseline: 23 offline tests passed before edits.
- Red: new no-CVE report test failed because `match_news` did not exist.
- Red: bracketed sponsored content and exposed API-key/secret headlines reproduced
  missing filter cases before the respective fixes.
- Green: 29 offline tests pass, including live-shaped HTTP integration covering a
  failed source, six-run health threshold, recovery, state persistence, first-install
  seeding, no-ping delivery, and state-preserving preview.
- Live read: all four feeds parsed; the OpenSourceMalware Claude Code backdoor story
  matched the actual watcher. No messages posted and no delivery state changed.
- Ruling: work in the clean checkout on `codex/tech-security-news` rather than creating
  another worktree, following the user's request to choose and proceed directly.
- Local-only finish: leave product changes uncommitted and do not deploy or push.
- Final review: one important finding, reparsing normalized HTML text could truncate
  literal code and filter out valid security reports. Reproduced RED, then fixed by
  honoring RSS/Atom content types and normalizing once. RSS, Atom XHTML, and Atom
  plain-text regression cases now pass; complete suite is green (29/29).
- Review exclusions remain as documented: no live Discord/deployment check; no
  exhaustive keyword coverage or incident clustering; no changes to existing
  delivery rejection handling. Cost: publisher delays/omissions and duplicate
  coverage of one incident from different publishers remain possible.

### Task 2: Confirmed delivery and urgent KEV ordering

User explicitly authorized fixing the three reliability findings from the follow-up
review. Keep the existing watcher and feature branch; no additional design questions.

**Files:** `watch.py`, `test_watch.py`, `README.md`.
**Interfaces:** `post(payload)` returns only after a confirmed Discord message;
`send(...)` retains its rejected-error list and records only delivered alerts.

- [x] Write/run failing regressions for fully rejected alerts remaining unseen,
  healthy alerts continuing, recovery delivery, webhook query preservation with
  `wait=true`, and empty/malformed message acknowledgements not marking seen.
- [x] Fix `post()` and `send()` with no new dependencies; update HTTP fixtures to
  return real-shaped Discord message acknowledgements; run the complete suite.
- [x] Write/run failing regressions for KEV POST before GHSA/NVD/RSS fetches and
  first-install seeding staying quiet; include state preservation on a later failure.
- [x] Send KEV immediately after matching, outside source-fetch error handling;
  retain one outer `finally` for state persistence and run the complete suite.
- [x] Document confirmed delivery and retry limits. Independently review the final
  changes, fix important findings, run full offline checks and `git diff --check`.

Task 2 evidence: all five added regression checks failed against the old behavior
before production changes. The complete suite passes 34/34 after fixes. Urgent
delivery is acknowledged and saved before later source calls; later cancellation
preserves health state, and Discord failure does not count as a CISA source failure.
Existing first-install quiet seeding and preview no-save checks still pass. Dry-run
urgent output also leaves state unchanged. Log counts now say `matched`, not `sent`,
because rejected cards are not confirmed deliveries.

Final Task 2 review: no important findings; independent reviewer reran eight scoped
delivery/integration checks and verified real state bytes were unchanged. During
the initial RED run, one new test wrote a fake local state entry; its STATE path is
now isolated in a TemporaryDirectory and the previously clean tracked state was
restored exactly from HEAD. Final verification wraps the complete suite with a
byte-for-byte state-preservation assertion. No live Discord calls or deployment.

### Task 3: Remediation and workflow review fixes

The user authorized the repository recheck findings: avoid sequential upgrade
commands across release branches, remove Rust lockfile-only remediation advice,
ignore cancelled/skipped runs when deciding workflow health transitions, and add
Worker dispatch behavior tests. Follow existing code and add no dependencies.

**Files:** `watch.py`, `test_watch.py`, `.github/workflows/watch.yml`, new
`test_workflow.py`, `trigger/src/index.ts`, `trigger/package.json`, new
`trigger/test/index.test.js`, CI and README.

- [x] Prove old remediation output fails branch-alternative and manifest-guidance
  checks, then split command blocks and replace version-less Rust/Ruby commands
  with explicit manifest/lockfile guidance. Add a RED→GREEN overflow regression so
  Discord field truncation never leaves a partial executable command. Watcher
  suite: 37 checks pass.
- [x] Prove actual workflow shell scripts fail cancelled-run transition cases;
  select only success/failure from the latest 100 completed runs. Five offline
  shell regression tests pass with stub gh/curl and real jq.
- [x] Add Worker success/request-shape, GitHub rejection, and network-failure tests
  before the minimal handler change. Use native handler env argument so the real
  TS entrypoint imports in Node 24 without a Cloudflare-specific test dependency.
  Three Node checks and generated-type checking pass on Node 24.22.1.
- [x] Wire workflow and Worker behavior checks into CI; update README.
- [x] Independently review all Task 3 changes, then run complete watcher/workflow/
  Worker tests, typecheck, dependency audit, deployment dry-run and diff checks.

Task 3 scope ruling: Ruby's `bundle update` had the same version-less template as
Rust; remove both rather than leave the same root cause in another caller. Both
ecosystems retain exact patched-version guidance. Cost: users edit the manifest
explicitly instead of copying a command that may leave the vulnerable version.

Task 3 final verification: 37 watcher + 5 workflow + 3 Worker checks pass (45 total),
Node 24.22.1 typecheck passes, dependency audit reports zero vulnerabilities, and
deployment dry-run completes. Independent reviewer reran all tests and typecheck
and found no important issues. Actual delivery history remains byte-for-byte
unchanged. No package dependencies/lockfile changed, no live Discord, no deploy.
The existing harmless Docker-socket warning also appears during the successful
dry-run; this Worker has no container configuration.

## Publication

The user explicitly requested `Push` after final verification. Commit and push
`codex/tech-security-news`; this supersedes the earlier local-only finish. Merge
to main and production deployment remain separate from this push.

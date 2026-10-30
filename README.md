# security-alert

Send tech security news and critical vulnerability alerts to Discord. Follow malware, supply-chain attacks, developer tools, AI, cloud, operating systems, browsers, and data breaches alongside CISA KEV, GitHub Security Advisories, and NVD. Alerts include attack types, attack paths, remediation details, and source links when available.

A Cloudflare Worker requests a GitHub Actions run every five minutes. Discord labels and operational notifications use Thai; news headlines and summaries retain the publisher's language.

## Alert coverage

| Alert | Source | Default behavior |
| --- | --- | --- |
| Actively exploited vulnerabilities | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Notify on newly added entries, with an `@here` mention. |
| Critical open-source vulnerabilities | [GitHub Security Advisories](https://github.com/advisories) | Report reviewed critical advisories, including affected versions, patched versions, and upgrade commands where available. |
| New critical CVEs | [NVD](https://nvd.nist.gov) | Report recent CVEs with CVSS scores of at least 9.0, across vendors. WordPress-related descriptions and selected WordPress plugin CNAs are filtered by default. |
| Tech security news | [OpenSourceMalware](https://opensourcemalware.com/rss.xml), [BleepingComputer](https://www.bleepingcomputer.com/feed/), [The Hacker News](https://feeds.feedburner.com/TheHackersNews), [SecurityWeek](https://www.securityweek.com/feed/) | Report recent security incidents and vulnerabilities, including backdoors, malicious extensions/packages, stolen credentials, and breaches. No CVE or CVSS is required. |

NVD messages contain up to three CVEs per card, with separate sections for the attack type and its impact in Thai, attack conditions, and remediation. Missing details are marked explicitly. CVEs already covered by GitHub advisories are skipped in the NVD feed; a later KEV listing still generates an exploitation alert.

When a package has several patched release branches, upgrade commands are separate alternatives: choose only the one matching the affected version range you use. Rust and Ruby advisories direct you to update `Cargo.toml` or `Gemfile` to the patched release and then update the lockfile; a lockfile-only update may retain a vulnerable version allowed by the manifest.

News cards contain a headline, a short publisher summary, the publication date, and a source link. They do not infer remediation or severity from a headline. News does not suppress later database or KEV alerts, and does not ping `@here`.

News feeds are filtered using incident/vulnerability keywords, with explicit sponsored, webinar, and promotional content excluded. Normalized article URLs prevent repeated delivery of the same article across feeds and runs. Different publishers' articles about the same incident can still appear. Keywords and finite RSS feeds cannot guarantee every relevant story is caught.

KEV alerts are sent after matching and optional NVD enrichment, before fetching GitHub advisories, bulk NVD results, or news feeds. A slow later source cannot hold a ready KEV alert back.

Discord requests use `wait=true` and must return a message ID before alerts are recorded as delivered. Rejected batches are split into individual alerts, with a bare-link fallback for rejected cards. If both forms fail, the alert remains unseen and eligible on later runs while it is still available within its source's lookback window. Other accepted alerts are saved normally. A lost acknowledgement after Discord accepts a message can cause a duplicate when retried; delivery is not exactly once.

## How it works

```text
Cloudflare Worker (trigger/, every 5 minutes)
  -> GitHub Actions (workflow_dispatch)
     -> watch.py
        -> Discord
        -> state.json (delivery history and health status)
```

The [watch workflow](.github/workflows/watch.yml) also has a GitHub Actions schedule as a fallback. Scheduled runs can be delayed, so the five-minute interval is a target, not a delivery guarantee.

The workflow commits `state.json` back to `main` to track delivered alerts across runs. A failed push is retried up to three attempts, waiting five then ten seconds and pulling/rebasing before each attempt. This retries state persistence without sending alerts again; pull/rebase failures or three failed pushes still fail the run. On a first run without state, the watcher records existing matches and sends a startup notice instead of posting the backlog.

When enabling news feeds on an existing installation, the first run includes matching articles published in the past 24 hours. Subsequent runs send unseen articles in that window. A long outage can miss news that has aged out of that window or disappeared from a publisher's feed.

## Quick start

### Requirements

- Python 3.11 or later for the watcher; it uses only the Python standard library.
- A Discord channel webhook and a GitHub repository with Actions enabled.
- [GitHub CLI](https://cli.github.com/) authenticated with access to the repository.
- A Cloudflare account and Node.js 24/npm for the trigger and its native test runner.
- `jq` for offline workflow notification tests (already available on GitHub's Ubuntu runners).

The commands below target `NiraphatK/security-alert`. For a fork, replace the repository in CLI commands and the dispatch URL in [trigger/src/index.ts](trigger/src/index.ts). Review the existing `state.json` before choosing whether to retain its delivery history.

### Run locally

Clone the repository and run the offline watcher tests:

```bash
git clone https://github.com/NiraphatK/security-alert.git
cd security-alert
python3 -B test_watch.py
python3 -B test_workflow.py
```

Preview live data locally without sending Discord messages:

```bash
env -u DISCORD_WEBHOOK PREVIEW=true python3 watch.py
```

Without `DISCORD_WEBHOOK`, messages are printed to stdout and state is not saved. Live previews require network access.

### Send a Discord preview

Set the repository's Discord webhook using the interactive prompt:

```bash
gh secret set DISCORD_WEBHOOK -R NiraphatK/security-alert
```

Optionally, [request an NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for a higher request allowance, then store it:

```bash
gh secret set NVD_API_KEY -R NiraphatK/security-alert
```

Dispatch a preview:

```bash
gh workflow run watch.yml -R NiraphatK/security-alert -f preview=true
```

This sends samples from live source data to the configured Discord channel, including one recent matching article per available news feed. It suppresses mentions and leaves `state.json` unchanged. Check the [Actions runs](https://github.com/NiraphatK/security-alert/actions/workflows/watch.yml) for errors.

## Secrets reference

| Location | Name | Purpose |
| --- | --- | --- |
| GitHub repository secret | `DISCORD_WEBHOOK` | Required for Discord delivery. |
| GitHub repository secret | `NVD_API_KEY` | Optional; increases the NVD API request allowance. |
| Cloudflare Worker secret | `GITHUB_TOKEN` | Fine-grained token used to dispatch the workflow; requires **Actions: Read and write** on this repository. |
| GitHub Actions | `GITHUB_TOKEN` | Supplied automatically by GitHub. The workflow grants `contents: write` to save state and `actions: read` for health checks. |

Keep webhook URLs and tokens in their respective secret stores. Do not commit them to the repository.

## Operations and troubleshooting

### Rotate the GitHub token

Rotate the Worker's token before it expires, or when Discord reports that the five-minute trigger has stopped. Check its expiration under [Personal access tokens](https://github.com/settings/personal-access-tokens).

1. Create a replacement fine-grained token with access only to this repository and **Actions: Read and write** permission.
2. From `trigger/`, authenticate with `npx cf auth login`.
3. In a **Bash** shell, run the following commands. The prompt hides your input:

```bash
read -r -s -p "GitHub token: " trigger_token
printf '\n'
npx cf workers secrets update GITHUB_TOKEN --worker security-alert-trigger --text "$trigger_token"
unset trigger_token
```

Verify that new workflow runs appear after the update. Cloudflare Workers Logs record dispatch errors, including GitHub authorization failures.

### Replace the Discord webhook

Run the following command and paste the replacement webhook at the prompt:

```bash
gh secret set DISCORD_WEBHOOK -R NiraphatK/security-alert
```

### Understand health notifications

Notification descriptions below are English summaries of the Thai messages sent to Discord.

| Notification | Meaning and next step |
| --- | --- |
| Daily summary | Sent on the first run at or after 09:00 Asia/Bangkok (02:00 UTC) each day, after initial setup. A missing summary can indicate that the watcher has stopped. Yellow means fewer than 144 runs were recorded in the past 24 hours; the expected five-minute cadence is about 288. |
| Source unavailable / recovered | A source failed for six consecutive runs, approximately 30 minutes at the expected cadence. Other sources continue running. |
| Five-minute trigger stopped / recovered | A fallback run detected no dispatch within the last 20 minutes. Check Cloudflare Workers Logs and the Worker's token expiration and permissions. |
| Watcher failed / recovered | The workflow failed. Open the notification's linked Actions run to inspect the logs. Repeated failures are suppressed until recovery. |

## Customize alert volume

Edit the constants near the top of [watch.py](watch.py):

| Setting | Default | Effect |
| --- | --- | --- |
| `GHSA_SEVERITIES` | `{"critical"}` | Add `"high"` to include high-severity GitHub advisories. |
| `NVD_MIN_SCORE` | `9.0` | Set the minimum NVD CVSS score. |
| `MUTE_WORDS` | `("wordpress",)` | Filter NVD descriptions containing these words. |
| `MUTE_CNAS` | Patchstack and Wordfence identifiers | Filter NVD entries from these assigning authorities. |
| `NEWS_FEEDS` | Four security publishers | Add or remove RSS/Atom sources. |
| `NEWS_LOOKBACK` | 24 hours | Look back for unseen security news, including when enabling news on an existing installation. |
| `NEWS_TERMS` | Incident/vulnerability keywords | Select security reports from mixed feeds, without requiring a CVE or a product allowlist. |

NVD filters do not mute KEV alerts.

## Development

Run `python3 -B test_watch.py` and `python3 -B test_workflow.py` from the repository root for offline watcher and workflow tests. Workflow tests require `jq` (available on GitHub's Ubuntu runners); they execute the actual notification scripts against local command stubs. Use the [local preview](#run-locally) to inspect live data. If you set `DISCORD_WEBHOOK` when running a local preview, it sends samples to Discord.

To check the Cloudflare trigger:

```bash
cd trigger
npm ci --ignore-scripts
npm test
npm run typecheck
npx cf deploy --dry-run
```

To deploy the trigger from `trigger/`:

```bash
npx cf auth login
npx cf deploy
```

The Worker's `GITHUB_TOKEN` must be configured for dispatches to succeed; see [token rotation](#rotate-the-github-token) for updating an existing Worker. Its name and five-minute schedule are defined in [trigger/cloudflare.config.ts](trigger/cloudflare.config.ts). It has no public HTTP endpoint.

The [test workflow](.github/workflows/test.yml) runs watcher and workflow notification tests, mocked Worker dispatch tests, a dependency audit, trigger type checks, and a deployment dry run on pushes and pull requests.

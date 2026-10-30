// GitHub fires the watch workflow's own */5 cron only every few hours, so this Worker's cron asks
// GitHub to run it every 5 minutes. GITHUB_TOKEN: fine-grained token, this repo only, Actions read/write.
const DISPATCH = "https://api.github.com/repos/NiraphatK/security-alert/actions/workflows/watch.yml/dispatches";

export default {
	async scheduled(_controller, env) {
		const res = await fetch(DISPATCH, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${env.GITHUB_TOKEN}`,
				Accept: "application/vnd.github+json",
				"User-Agent": "security-alert-trigger",
			},
			body: JSON.stringify({ ref: "main" }),
		});
		// throwing marks this cron run as failed in the Cloudflare dashboard
		if (!res.ok) throw new Error(`GitHub workflow dispatch failed: ${res.status} ${await res.text()}`);
	},
} satisfies ExportedHandler<Env>;

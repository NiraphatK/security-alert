import { bindings, defineConfig, triggers } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

export default defineConfig({
	worker: {
		name: "security-alert-trigger",
		compatibilityDate: "2026-10-06",
		entrypoint,
		workersDev: false, // runs on cron only, so no public URL
		env: {
			GITHUB_TOKEN: bindings.secret(),
		},
		triggers: [triggers.scheduled({ schedule: "*/5 * * * *" })],
	},
});

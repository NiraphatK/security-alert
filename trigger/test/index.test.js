import assert from "node:assert/strict";
import test from "node:test";
import worker from "../src/index.ts";

const env = { GITHUB_TOKEN: "test-only-token" };

test("scheduled dispatch posts the configured workflow and ref with authentication", async (t) => {
	const fetch = t.mock.method(globalThis, "fetch", async () => new Response(null, { status: 204 }));

	await worker.scheduled({}, env);

	assert.equal(fetch.mock.callCount(), 1);
	assert.deepEqual(fetch.mock.calls[0].arguments, [
		"https://api.github.com/repos/NiraphatK/security-alert/actions/workflows/watch.yml/dispatches",
		{
			method: "POST",
			headers: {
				Authorization: "Bearer test-only-token",
				Accept: "application/vnd.github+json",
				"User-Agent": "security-alert-trigger",
			},
			body: '{"ref":"main"}',
		},
	]);
});

test("scheduled dispatch rejects a failed GitHub response", async (t) => {
	t.mock.method(globalThis, "fetch", async () => new Response("Forbidden", { status: 403 }));

	await assert.rejects(worker.scheduled({}, env), {
		message: "GitHub workflow dispatch failed: 403 Forbidden",
	});
});

test("scheduled dispatch propagates a network failure", async (t) => {
	const failure = new Error("Network unavailable");
	t.mock.method(globalThis, "fetch", async () => { throw failure; });

	await assert.rejects(worker.scheduled({}, env), (error) => error === failure);
});

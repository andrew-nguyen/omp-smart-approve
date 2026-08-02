import { describe, expect, test } from "bun:test";
import type { Model } from "@oh-my-pi/pi-ai";
import { smartApproveConfigSchema } from "../src/config.ts";
import { type JudgePorts, selectJudgeModel } from "../src/judge.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function fakeModel(provider: string, id: string): Model {
	return {
		id,
		name: id,
		api: "anthropic-messages",
		provider,
		baseUrl: "https://judge.invalid",
		reasoning: false,
		input: ["text"],
		cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
		contextWindow: 200_000,
		maxTokens: 8_000,
		compat: undefined,
	};
}

const SESSION = fakeModel("anthropic", "claude-session");
const ANTHROPIC_FAST = fakeModel("anthropic", "claude-fast");
const OPENAI_FAST = fakeModel("openai", "gpt-fast");
const GOOGLE_FAST = fakeModel("google", "gemini-fast");

const CATALOG = [SESSION, ANTHROPIC_FAST, OPENAI_FAST, GOOGLE_FAST];

function config(authorizedModels: string[], preferContrastingFamily = true) {
	return smartApproveConfigSchema.parse({ judge: { authorizedModels, preferContrastingFamily } });
}

function ports(overrides: Partial<JudgePorts> = {}): JudgePorts {
	const base: JudgePorts = {
		listModels: () => CATALOG,
		currentModel: () => SESSION,
		resolveModel: spec => CATALOG.find(m => `${m.provider}/${m.id}` === spec || m.id === spec),
		// Provider stands in for the lineage token the host computes.
		family: model => model.provider,
		hasConfiguredAuth: () => true,
		getApiKey: async () => "unused",
		complete: async () => {
			throw new Error("selection tests never reach the provider");
		},
		now: () => 0,
	};
	return { ...base, ...overrides };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("selectJudgeModel", () => {
	test("prefers an authorized model from a family that contrasts with the session model", () => {
		// Anthropic is listed first, but the session already runs Anthropic, so a
		// contrasting family wins over config order.
		const result = selectJudgeModel(ports(), config(["anthropic/claude-fast", "openai/gpt-fast"]));

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("gpt-fast");
	});

	test("falls back to the configured same-family model when nothing contrasts", () => {
		const result = selectJudgeModel(ports(), config(["anthropic/claude-fast"]));

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("claude-fast");
	});

	test("honours config order when contrasting-family preference is disabled", () => {
		const result = selectJudgeModel(ports(), config(["anthropic/claude-fast", "openai/gpt-fast"], false));

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("claude-fast");
	});

	test("uses config order when the session has no current model", () => {
		const result = selectJudgeModel(
			ports({ currentModel: () => undefined }),
			config(["anthropic/claude-fast", "openai/gpt-fast"]),
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("claude-fast");
	});

	test("picks the first contrasting entry in config order, not the last", () => {
		const result = selectJudgeModel(ports(), config(["openai/gpt-fast", "google/gemini-fast"]));

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("gpt-fast");
	});

	test("authorizes a bare model id as well as provider/id", () => {
		const result = selectJudgeModel(ports(), config(["gpt-fast"]));

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("gpt-fast");
	});

	test("de-duplicates a model listed under both spellings", () => {
		const seen: string[] = [];
		const result = selectJudgeModel(
			ports({
				hasConfiguredAuth: model => {
					seen.push(model.id);
					return true;
				},
			}),
			config(["openai/gpt-fast", "gpt-fast"], false),
		);

		expect(result.ok).toBe(true);
		expect(seen).toEqual(["gpt-fast"]);
	});

	test("an empty allowlist fails closed and names the setup command", () => {
		const result = selectJudgeModel(ports(), config([]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.failure.kind).toBe("no-authorized-model");
		expect(result.failure.detail).toContain("/smart-approve setup");
		expect(result.failure.detail).toContain("authorizedModels");
	});

	test("never falls back to the primary session model when nothing is authorized", () => {
		const result = selectJudgeModel(ports(), config([]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.failure.detail).not.toContain("claude-session");
	});

	test("an allowlist entry that resolves to nothing fails closed", () => {
		const result = selectJudgeModel(ports(), config(["openai/does-not-exist"]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.failure.kind).toBe("no-authorized-model");
		expect(result.failure.detail).toContain("openai/does-not-exist");
	});

	test("rejects a resolver that widens a spec onto an unauthorized provider", () => {
		// A host resolver may fuzzy-match. Authorization is re-checked against the
		// resolved identity so the operator's allowlist is the real boundary.
		const result = selectJudgeModel(ports({ resolveModel: () => GOOGLE_FAST }), config(["openai/gpt-fast"]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.failure.kind).toBe("no-authorized-model");
	});

	test("an authorized model without configured credentials is auth-unavailable, not no-authorized-model", () => {
		const result = selectJudgeModel(ports({ hasConfiguredAuth: () => false }), config(["openai/gpt-fast"]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.failure.kind).toBe("auth-unavailable");
		expect(result.failure.detail).toContain("openai/gpt-fast");
		expect(result.failure.detail).toContain("/smart-approve setup");
	});

	test("skips an authorized model whose credentials are missing and uses the next one", () => {
		const result = selectJudgeModel(
			ports({ hasConfiguredAuth: model => model.id !== "gpt-fast" }),
			config(["openai/gpt-fast", "google/gemini-fast"]),
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("gemini-fast");
	});

	test("does not select an unauthenticated contrasting model over an authenticated same-family one", () => {
		const result = selectJudgeModel(
			ports({ hasConfiguredAuth: model => model.provider === "anthropic" }),
			config(["openai/gpt-fast", "anthropic/claude-fast"]),
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("claude-fast");
	});

	test("contrast is decided by the family token, not by the provider string", () => {
		// Two models from the same provider, different lineages. The session runs
		// the sonnet lineage, so the haiku lineage is the contrasting choice even
		// though it is listed second and shares a provider.
		const result = selectJudgeModel(
			ports({ family: model => (model.id === "claude-fast" ? "haiku-lineage" : "sonnet-lineage") }),
			config(["anthropic/claude-session", "anthropic/claude-fast"]),
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.model.id).toBe("claude-fast");
	});
});

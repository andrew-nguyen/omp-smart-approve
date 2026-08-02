import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { holdCall, resetBrokerForTests } from "../src/broker.ts";
import {
	type CommandDeps,
	clearSuggestions,
	createCommands,
	GRANT_SCOPE_OPTIONS,
	OVERRIDE_APPROVE,
	OVERRIDE_DENY,
	OVERRIDE_EXPIRE,
	recordSuggestion,
} from "../src/commands.ts";
import { type ResolvedConfig, resolveConfig, smartApproveConfigSchema } from "../src/config.ts";
import type { FrozenCall, PendingApproval, PolicyRule } from "../src/contracts.ts";
import { hashArguments } from "../src/policy.ts";
import { openStore, type SmartApproveStore } from "../src/store.ts";
import { STATUS_KEY, type UiHost, WIDGET_BYPASS } from "../src/ui.ts";

const NOW = 1_700_000_000_000;
/** Deterministic so a test can queue a matching (or deliberately wrong) answer. */
const CHALLENGE = "type-me-42";
const SECRET_CONTENT = "root::0:0:::";

const ARGS: Record<string, unknown> = { path: "/etc/shadow", content: SECRET_CONTENT };
const ARGS_HASH = hashArguments(ARGS);

// ---------------------------------------------------------------------------
// Fake UI
// ---------------------------------------------------------------------------

interface FakeUi {
	ui: UiHost;
	selects: Array<{ title: string; options: Array<{ label: string; description?: string }> }>;
	confirms: Array<{ title: string; message: string }>;
	inputs: Array<{ title: string; placeholder: string | undefined }>;
	notices: Array<{ message: string; type: string | undefined }>;
	widgets: Array<{ key: string; lines: string[] | undefined }>;
	statuses: Array<{ key: string; text: string | undefined }>;
}

interface UiScript {
	hasUI?: boolean;
	/** Answers consumed in order; an exhausted queue answers `undefined`/`false`. */
	selects?: Array<string | undefined>;
	inputs?: Array<string | undefined>;
	confirms?: boolean[];
}

function createFakeUi(script: UiScript = {}): FakeUi {
	const selects: FakeUi["selects"] = [];
	const confirms: FakeUi["confirms"] = [];
	const inputs: FakeUi["inputs"] = [];
	const notices: FakeUi["notices"] = [];
	const widgets: FakeUi["widgets"] = [];
	const statuses: FakeUi["statuses"] = [];
	const selectQueue = [...(script.selects ?? [])];
	const inputQueue = [...(script.inputs ?? [])];
	const confirmQueue = [...(script.confirms ?? [])];
	const ui: UiHost = {
		hasUI: script.hasUI ?? true,
		select: async (title, options) => {
			selects.push({ title, options });
			return selectQueue.length === 0 ? undefined : selectQueue.shift();
		},
		confirm: async (title, message) => {
			confirms.push({ title, message });
			return confirmQueue.length === 0 ? false : (confirmQueue.shift() ?? false);
		},
		input: async (title, placeholder) => {
			inputs.push({ title, placeholder });
			return inputQueue.length === 0 ? undefined : inputQueue.shift();
		},
		notify: (message, type) => {
			notices.push({ message, type });
		},
		setStatus: (key, text) => {
			statuses.push({ key, text });
		},
		setWidget: (key, lines) => {
			widgets.push({ key, lines });
		},
	};
	return { ui, selects, confirms, inputs, notices, widgets, statuses };
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let root: string;
let store: SmartApproveStore;
let resolved: ResolvedConfig;
let clock: number;

beforeEach(() => {
	resetBrokerForTests();
	clearSuggestions();
	clock = NOW;
	root = mkdtempSync(path.join(os.tmpdir(), "smart-approve-commands-"));
	resolved = resolveConfig([], [], {
		cwd: path.join(root, "project"),
		agentDir: path.join(root, "agent"),
		home: root,
	});
	store = openStore(path.join(root, "state", "state.sqlite"));
});

afterEach(() => {
	store.close();
	rmSync(root, { recursive: true, force: true });
	resetBrokerForTests();
	clearSuggestions();
});

interface HarnessOptions {
	script?: UiScript;
	models?: Array<{ id: string; provider: string }>;
	current?: { id: string; provider: string };
	/** `provider/id` -> family. Defaults to the provider. */
	families?: Record<string, string>;
	resolvedOverrides?: Partial<ResolvedConfig>;
	bypassActive?: boolean;
}

interface Harness {
	deps: CommandDeps;
	fake: FakeUi;
	writes: Array<Record<string, unknown>>;
	bypass: { active: boolean; reasons: string[]; disables: number };
	run(argv: string): Promise<string>;
}

function harness(options: HarnessOptions = {}): Harness {
	const fake = createFakeUi(options.script);
	const writes: Array<Record<string, unknown>> = [];
	const bypass = { active: options.bypassActive ?? false, reasons: [] as string[], disables: 0 };
	const models = options.models ?? [];
	let ids = 0;
	const effective: ResolvedConfig = { ...resolved, ...options.resolvedOverrides };

	const deps: CommandDeps = {
		resolved: effective,
		store,
		ui: fake.ui,
		now: () => clock,
		randomId: () => {
			ids += 1;
			return `id-${ids}`;
		},
		randomChallenge: () => CHALLENGE,
		recomputeHash: hashArguments,
		bypass: {
			active: () => bypass.active,
			enable: reason => {
				bypass.active = true;
				bypass.reasons.push(reason);
			},
			disable: () => {
				bypass.active = false;
				bypass.disables += 1;
			},
		},
		models: {
			list: () => models,
			current: () => options.current,
			family: model => options.families?.[`${model.provider}/${model.id}`] ?? model.provider,
		},
		writeConfig: async patch => {
			writes.push(patch);
			return path.join(root, "agent", "smart-approve.yml");
		},
	};

	const commands = createCommands(deps);
	return {
		deps,
		fake,
		writes,
		bypass,
		run: async argv => (await commands.run(argv)).lines.join("\n"),
	};
}

// ---------------------------------------------------------------------------
// Store seeding
// ---------------------------------------------------------------------------

function seedCall(auditId: string, overrides: Partial<PendingApproval> = {}): PendingApproval {
	store.beginAudit({
		auditId,
		toolCallId: `${auditId}-call`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		cwd: resolved.paths.cwd,
		retryFamilyKey: `family-${auditId}`,
		createdAt: NOW - 60_000,
	});
	store.commitAudit({
		auditId,
		toolCallId: `${auditId}-call`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		cwd: resolved.paths.cwd,
		decision: "escalate",
		stage: "escalation",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		retryFamilyKey: `family-${auditId}`,
		retryCount: 0,
		createdAt: NOW - 60_000,
	});
	const record: PendingApproval = {
		auditId,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		nonce: `nonce-${auditId}`,
		sourceAgentId: "Researcher",
		cwd: resolved.paths.cwd,
		state: "awaiting-human",
		createdAt: NOW - 60_000,
		expiresAt: NOW + 3_600_000,
		exemptAttempts: 0,
		...overrides,
	};
	store.putPending(record);
	return record;
}

function frozen(args: Record<string, unknown> = ARGS): FrozenCall {
	return {
		toolName: "write",
		toolCallId: "call-1",
		rawArguments: Object.freeze({ ...args }),
		argumentsHash: hashArguments(args),
		frozenAt: NOW,
	};
}

function hold(auditId: string, args: Record<string, unknown> = ARGS): void {
	holdCall({ auditId, nonce: `nonce-${auditId}`, frozenCall: frozen(args), expiresAt: NOW + 600_000 });
}

function storedRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
	return {
		id: "rule-1",
		kind: "allow-exact",
		toolName: "write",
		target: "/srv/app/build.log",
		reason: "build log is disposable",
		createdBy: "human-override",
		specificity: 412,
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

describe("argument parsing", () => {
	test("no arguments prints usage covering every subcommand", async () => {
		const h = harness();
		const out = await h.run("");
		for (const name of ["setup", "status", "rules", "pending", "review", "override", "unguarded", "guarded"]) {
			expect(out).toContain(name);
		}
	});

	test("an unknown subcommand is named and does not silently no-op", async () => {
		const out = await harness().run("frobnicate");
		expect(out).toContain("Unknown subcommand `frobnicate`");
	});

	test("subcommands needing an audit ID say so instead of guessing", async () => {
		expect(await harness().run("review")).toContain("needs an audit ID");
		expect(await harness().run("override")).toContain("needs an audit ID");
		expect(await harness().run("apply-suggestion")).toContain("needs an audit ID");
	});
});

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

describe("setup", () => {
	const ANTHROPIC = { id: "claude-fast", provider: "anthropic" };
	const OPENAI = { id: "gpt-fast", provider: "openai" };

	test("with no authenticated model it writes nothing and never prompts", async () => {
		const h = harness({ models: [] });
		const out = await h.run("setup");
		expect(out).toContain("No model in this session has configured authentication");
		expect(out).toContain("Nothing was written");
		expect(h.writes).toHaveLength(0);
		expect(h.fake.confirms).toHaveLength(0);
	});

	test("recommends an authenticated model from a different family than the session model", async () => {
		const h = harness({
			models: [OPENAI, ANTHROPIC],
			current: OPENAI,
			families: { "openai/gpt-fast": "openai", "anthropic/claude-fast": "anthropic" },
		});
		const out = await h.run("setup");
		expect(out).toContain("Recommended judge: anthropic/claude-fast");
		expect(out).toContain("its family differs from the session model");
	});

	test("says so when only a same-family model is authenticated", async () => {
		const h = harness({ models: [OPENAI], current: OPENAI, families: { "openai/gpt-fast": "openai" } });
		const out = await h.run("setup");
		expect(out).toContain("Recommended judge: openai/gpt-fast");
		expect(out).toContain("No authorized model from a different family is available");
	});

	test("previews the config path and the timeout budget before asking", async () => {
		const h = harness({ models: [ANTHROPIC] });
		const out = await h.run("setup");
		expect(out).toContain("2 attempt(s) x 10000 ms + 1000 ms cleanup = 21000 ms worst case");
		expect(out).toContain("handler self-deadline 28000 ms");
		expect(out).toContain("smart-approve.yml");
	});

	test("cancelling writes nothing", async () => {
		const h = harness({ models: [ANTHROPIC], script: { confirms: [false] } });
		const out = await h.run("setup");
		expect(out).toContain("Cancelled. Nothing was written.");
		expect(h.writes).toHaveLength(0);
	});

	test("confirming writes exactly the authorized-model patch, once", async () => {
		const h = harness({ models: [OPENAI, ANTHROPIC], script: { confirms: [true] } });
		const out = await h.run("setup");
		expect(h.writes).toEqual([{ judge: { authorizedModels: ["openai/gpt-fast"] } }]);
		expect(out).toContain(path.join(root, "agent", "smart-approve.yml"));
	});
});

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

describe("status", () => {
	test("reports the open-pending count together with the command that lists them", async () => {
		seedCall("audit-a");
		seedCall("audit-b");
		const out = await harness().run("status");
		expect(out).toContain("Open pending approvals: 2");
		expect(out).toContain("`/smart-approve pending`");
	});

	test("excludes records that already expired from the open count", async () => {
		seedCall("audit-a");
		seedCall("audit-old", { expiresAt: NOW - 1 });
		const out = await harness().run("status");
		expect(out).toContain("Open pending approvals: 1");
	});

	test("never leaks literal arguments even while the broker holds them", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("status");
		expect(out).not.toContain(SECRET_CONTENT);
		expect(out).toContain("path:");
	});

	test("reports an unconfigured judge as not ready with the setup command", async () => {
		const out = await harness().run("status");
		expect(out).toContain("Gate: NOT READY");
		expect(out).toContain("no judge model authorized — run `/smart-approve setup`");
	});

	test("reports authorized models that this session cannot authenticate", async () => {
		const withModel: ResolvedConfig = {
			...resolved,
			config: {
				...resolved.config,
				judge: { ...resolved.config.judge, authorizedModels: ["anthropic/claude-fast"] },
			},
		};
		const out = await harness({ resolvedOverrides: withModel, models: [{ id: "gpt", provider: "openai" }] }).run(
			"status",
		);
		expect(out).toContain("authorized models are not available in this session: anthropic/claude-fast");
	});

	test("surfaces compatibility warnings rather than hiding them", async () => {
		const out = await harness({
			resolvedOverrides: { warnings: ["OMP 18 changed resolveApproval; host classification may drift"] },
		}).run("status");
		expect(out).toContain("Compatibility warnings:");
		expect(out).toContain("host classification may drift");
	});

	test("shows bypass state and broker health", async () => {
		const out = await harness({ bypassActive: true }).run("status");
		expect(out).toContain("UNGUARDED");
		expect(out).toContain("bypass:           ACTIVE (session only)");
		expect(out).toContain("main approval UI: ABSENT");
	});
});

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

describe("rules", () => {
	test("an allow-exact missing argumentsHash or cwd reads as advisory, not as a bypass", async () => {
		// The dangerous misreading: an operator sees "may skip the judge" on a rule
		// that is in fact still judged, and believes the gate is configured.
		store.putRule(storedRule());
		store.putRule(storedRule({ id: "rule-2", kind: "allow-pattern", target: "/srv/app/**", specificity: 210 }));
		const out = await harness().run("rules");
		expect(out).toContain("advisory posture — still judged (no argumentsHash, no cwd)");
		expect(out).toContain("posture hint only — never skips the judge");
		expect(out).not.toContain("skips the judge for this precise call");
	});

	test("a fully qualified allow-exact reads as a real bypass", async () => {
		store.putRule(
			storedRule({
				id: "rule-pinned",
				argumentsHash: "a".repeat(64),
				cwd: resolved.paths.cwd,
			}),
		);
		const out = await harness().run("rules");
		expect(out).toContain("skips the judge for this precise call in this directory");
	});

	test("posture degrades the moment any one of the three fields is missing", async () => {
		store.putRule(storedRule({ id: "no-hash", cwd: resolved.paths.cwd }));
		store.putRule(storedRule({ id: "no-cwd", argumentsHash: "a".repeat(64) }));
		store.putRule(
			storedRule({ id: "patterned", target: "/srv/**", argumentsHash: "a".repeat(64), cwd: resolved.paths.cwd }),
		);
		const out = await harness().run("rules");
		expect(out).toContain("advisory posture — still judged (no argumentsHash)");
		expect(out).toContain("advisory posture — still judged (no cwd)");
		expect(out).toContain("advisory posture — still judged (target is a pattern)");
	});

	test("show names the missing field so the operator can fix it", async () => {
		store.putRule(storedRule());
		const out = await harness().run("rules show rule-1");
		expect(out).toContain("argsHash:    (absent — cannot skip the judge)");
		expect(out).toContain("cwd:         (absent — cannot skip the judge)");
	});

	test("show renders one rule with its posture and specificity", async () => {
		store.putRule(storedRule());
		const out = await harness().run("rules show rule-1");
		expect(out).toContain("Rule rule-1");
		expect(out).toContain("target:      /srv/app/build.log (exact)");
		expect(out).toContain("specificity: 412");
	});

	test("revoke without confirmation changes nothing", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant({
			id: "grant-1",
			auditId: "audit-a",
			argumentsHash: ARGS_HASH,
			canonicalHash: "canon-1",
			policyHash: resolved.policyHash,
			cwd: resolved.paths.cwd,
			scope: "session",
			expiresAt: NOW + 600_000,
			createdBy: "human",
			reason: "approved once",
		});

		const out = await harness({ script: { confirms: [false] } }).run("rules revoke rule-1");
		expect(out).toContain("Cancelled");
		expect(store.listRules()).toHaveLength(1);
		expect(store.listGrants()).toHaveLength(1);
	});

	test("confirmed revoke removes the rule and invalidates outstanding grants", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant({
			id: "grant-1",
			auditId: "audit-a",
			argumentsHash: ARGS_HASH,
			canonicalHash: "canon-1",
			policyHash: resolved.policyHash,
			cwd: resolved.paths.cwd,
			scope: "persistent",
			expiresAt: NOW + 600_000,
			createdBy: "human",
			reason: "approved once",
		});

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		expect(out).toContain("Revoked rule rule-1");
		expect(out).toContain("Invalidated 1 outstanding allow grant(s)");
		expect(store.listRules()).toHaveLength(0);
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("a configuration rule cannot be revoked from the command", async () => {
		const configured: PolicyRule = storedRule({ id: "cfg-1", createdBy: "project", source: "smart-approve.yml" });
		const out = await harness({ resolvedOverrides: { rules: [configured] } }).run("rules revoke cfg-1");
		expect(out).toContain("cannot be revoked here");
		expect(out).toContain("Edit the configuration file");
	});
});

// ---------------------------------------------------------------------------
// pending
// ---------------------------------------------------------------------------

describe("pending", () => {
	test("works with no arguments and lists the open record", async () => {
		seedCall("audit-a");
		const out = await harness().run("pending");
		expect(out).toContain("1 open Smart Approve escalation:");
		expect(out).toContain("audit-a");
		expect(out).toContain("path:/etc/shadow");
		expect(out).toContain("destructive-action");
		expect(out).toContain("Researcher");
	});

	test("reports mintability from the live broker", async () => {
		seedCall("audit-a");
		hold("audit-a");
		expect(await harness().run("pending")).toContain("can mint an exact grant");
	});

	test("after a restart with an empty broker every record is intent-only", async () => {
		seedCall("audit-a");
		hold("audit-a");
		// Simulate the process dying: durable records survive, in-memory ones do not.
		resetBrokerForTests();
		const out = await harness().run("pending");
		expect(out).toContain("audit-a");
		expect(out).toContain("intent-only — literal arguments are gone");
		expect(out).not.toContain("can mint an exact grant");
	});

	test("excludes resolved and expired records", async () => {
		seedCall("audit-open");
		seedCall("audit-denied");
		seedCall("audit-stale", { expiresAt: NOW - 1 });
		store.updatePendingState("audit-denied", "denied", NOW);

		const out = await harness().run("pending");
		expect(out).toContain("1 open Smart Approve escalation:");
		expect(out).toContain("audit-open");
		expect(out).not.toContain("audit-denied");
		expect(out).not.toContain("audit-stale");
	});

	test("sweeps timed-out waits into expired while listing", async () => {
		seedCall("audit-stale", { expiresAt: NOW - 1 });
		await harness().run("pending");
		expect(store.getPending("audit-stale")?.state).toBe("expired");
	});

	test("says plainly when nothing is open", async () => {
		expect(await harness().run("pending")).toContain("No Smart Approve escalations are open");
	});
});

// ---------------------------------------------------------------------------
// review
// ---------------------------------------------------------------------------

describe("review", () => {
	test("renders the immutable verdict, event history, and retry family", async () => {
		seedCall("audit-a");
		store.appendEvent({ auditId: "audit-a", type: "judged", detail: "escalate", actor: "judge", at: NOW - 59_000 });
		store.appendEvent({
			auditId: "audit-a",
			type: "escalated",
			detail: "pending approval opened",
			actor: "gate",
			at: NOW - 58_000,
		});
		store.recordStrike("family-audit-a", "audit-a", NOW - 58_000);

		const out = await harness().run("review audit-a");
		expect(out).toContain("Original verdict (immutable)");
		expect(out).toContain("decision: escalate at stage escalation");
		expect(out).toContain("judged");
		expect(out).toContain("pending approval opened");
		expect(out).toContain("Retry family: family-audit-a — 1 strike");
	});

	test("renders literal arguments only while the broker holds them", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("review audit-a");
		expect(out).toContain("(from the live in-memory broker)");
		expect(out).toContain(SECRET_CONTENT);
		expect(out).toContain("It can mint an exact grant");
	});

	test("never reconstructs arguments from persistence once the broker is empty", async () => {
		seedCall("audit-a");
		const out = await harness().run("review audit-a");
		expect(out).not.toContain(SECRET_CONTENT);
		expect(out).toContain("never");
		expect(out).toContain("nothing here is reconstructed from the audit database");
		expect(out).toContain("Intent-only — literal arguments are gone");
	});

	test("shows a live judge suggestion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files are never an agent target",
		});
		const out = await harness().run("review audit-a");
		expect(out).toContain("deny-pattern write -> /etc/**");
		expect(out).toContain("Non-binding");
	});

	test("an unknown audit ID is reported, not invented", async () => {
		expect(await harness().run("review audit-missing")).toContain(
			"No Smart Approve record for audit ID audit-missing",
		);
	});
});

// ---------------------------------------------------------------------------
// apply-suggestion
// ---------------------------------------------------------------------------

describe("apply-suggestion", () => {
	test("refuses when no suggestion is held in memory", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("No live judge suggestion");
		expect(store.listRules()).toHaveLength(0);
	});

	test("a model-suggested wildcard allow stays non-bypass posture even after confirmation", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "allow-exact",
			toolName: "write",
			target: "/srv/app/**",
			rationale: "the build directory is disposable",
		});

		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("normalized:  allow-pattern");
		expect(out).toContain("downgraded to a posture hint and still cannot skip the judge");

		const rules = store.listRules();
		expect(rules).toHaveLength(1);
		expect(rules[0]?.kind).toBe("allow-pattern");
	});

	test("an exact allow with no pattern operator is kept exact", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "allow-exact",
			toolName: "write",
			target: "/srv/app/build.log",
			rationale: "one disposable file",
		});
		await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(store.listRules()[0]?.kind).toBe("allow-exact");
	});

	test("declining the confirmation inserts nothing", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files",
		});
		const out = await harness({ script: { confirms: [false] } }).run("apply-suggestion audit-a");
		expect(out).toContain("Cancelled. No rule was inserted.");
		expect(store.listRules()).toHaveLength(0);
	});

	test("a suggestion that fails the rule schema is rejected before insertion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", { kind: "deny-exact", toolName: "write", target: "", rationale: "empty target" });
		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("does not validate and was not inserted");
		expect(store.listRules()).toHaveLength(0);
	});

	test("an applied suggestion is linked to the originating audit", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files",
		});
		await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		const events = store.listEvents("audit-a");
		expect(events.some(e => e.type === "overridden" && e.detail.includes("deny-pattern"))).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// override
// ---------------------------------------------------------------------------

const SCOPE_ONE_TIME = GRANT_SCOPE_OPTIONS[0]?.label ?? "";
const SCOPE_SESSION = GRANT_SCOPE_OPTIONS[1]?.label ?? "";
const SCOPE_PERSISTENT = GRANT_SCOPE_OPTIONS[2]?.label ?? "";

describe("override", () => {
	test("shows the original immutable verdict before asking anything", async () => {
		seedCall("audit-a");
		const out = await harness().run("override audit-a");
		expect(out).toContain("Original verdict (append-only; nothing below rewrites it)");
		expect(out).toContain("escalate at stage escalation");
		expect(out).toContain("overwrites the system password database");
	});

	test("a mismatched challenge changes nothing and is recorded", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE], inputs: ["not-the-challenge"] },
		}).run("override audit-a");

		expect(out).toContain("Challenge did not match");
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.listEvents("audit-a").some(e => e.detail.includes("override challenge failed"))).toBe(true);
	});

	test("cancelling the action prompt changes nothing", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("override audit-a");
		expect(out).toContain("Cancelled. Nothing changed.");
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a one-time grant is minted from the live literal arguments", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "verified by hand"] },
		}).run("override audit-a");

		expect(out).toContain(`Granted a one-time allow bound to call hash ${ARGS_HASH}`);
		const grants = store.listGrants();
		expect(grants).toHaveLength(1);
		expect(grants[0]?.scope).toBe("one-time");
		expect(grants[0]?.argumentsHash).toBe(ARGS_HASH);
		expect(grants[0]?.reason).toBe("verified by hand");
		expect(store.getPending("audit-a")?.state).toBe("approved-granted");

		const types = store.listEvents("audit-a").map(e => e.type);
		expect(types).toContain("overridden");
		expect(types).toContain("granted");
	});

	test("a one-time grant is consumed exactly once", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeDefined();
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("a session grant outlives the in-memory arguments", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_SESSION], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		const grant = store.listGrants()[0];
		expect(grant?.scope).toBe("session");
		expect(grant?.expiresAt).toBe(NOW + resolved.config.timeouts.pendingApprovalTtlMs);
	});

	test("a persistent grant needs a second explicit confirmation", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const declined = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT], inputs: [CHALLENGE, "ok"], confirms: [false] },
		}).run("override audit-a");

		expect(declined).toContain("needs a second explicit confirmation. Nothing was granted.");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
	});

	test("a persistent grant is minted once the second confirmation arrives", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const h = harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT], inputs: [CHALLENGE, "ok"], confirms: [true] },
		});
		await h.run("override audit-a");

		expect(store.listGrants()[0]?.scope).toBe("persistent");
		expect(h.fake.confirms).toHaveLength(1);
		expect(h.fake.confirms[0]?.title).toBe("Persistent allow");
	});

	test("evicted arguments refuse a grant and record intent to approve instead", async () => {
		seedCall("audit-a");
		// No hold(): a restart, subagent teardown, or broker TTL expiry got here first.
		const out = await harness({
			script: {
				selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT],
				inputs: [CHALLENGE, "still want it"],
				confirms: [true],
			},
		}).run("override audit-a");

		expect(out).toContain("No grant was minted");
		expect(out).toContain("Recorded intent to approve only");
		expect(out).toContain("re-opens a live approval dialog");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.getPending("audit-a")?.state).toBe("approved-intent");
		expect(store.listEvents("audit-a").some(e => e.type === "intent-recorded")).toBe(true);
	});

	test("held arguments whose hash no longer matches refuse a grant", async () => {
		seedCall("audit-a");
		hold("audit-a", { path: "/etc/shadow", content: "different bytes" });
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(out).toContain("No grant was minted");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a policy change since the block refuses a grant", async () => {
		seedCall("audit-a", { policyHash: "policy-from-yesterday" });
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(out).toContain("Configuration or policy changed since this call was blocked");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("deny works without the literal arguments", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("Denied. The block stands");
		expect(store.getPending("audit-a")?.state).toBe("denied");
		expect(store.listEvents("audit-a").some(e => e.type === "denied")).toBe(true);
	});

	test("expire works without the literal arguments", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { selects: [OVERRIDE_EXPIRE], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("Expired");
		expect(store.getPending("audit-a")?.state).toBe("expired");
	});

	test("a resolved record cannot be reopened", async () => {
		seedCall("audit-a");
		store.updatePendingState("audit-a", "denied", NOW);
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");
		expect(out).toContain("already resolved (denied)");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a record past its pending TTL is swept to expired and cannot be actioned", async () => {
		seedCall("audit-a", { expiresAt: NOW - 1 });
		const out = await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("already resolved (expired)");
		expect(store.getPending("audit-a")?.state).toBe("expired");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("an approved-intent record past its TTL is refused rather than granted", async () => {
		seedCall("audit-a", { expiresAt: NOW - 1 });
		store.updatePendingState("audit-a", "approved-intent", NOW - 2);
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "too late"] },
		}).run("override audit-a");

		expect(out).toContain("no longer be actioned");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("an unknown audit ID points at the pending list", async () => {
		const out = await harness().run("override audit-missing");
		expect(out).toContain("No Smart Approve escalation with audit ID audit-missing");
		expect(out).toContain("/smart-approve pending");
	});

	test("an approved-intent record can still be approved once its arguments return", async () => {
		seedCall("audit-a");
		await harness({ script: { selects: [OVERRIDE_APPROVE], inputs: [CHALLENGE, "later"] } }).run(
			"override audit-a",
		);
		expect(store.getPending("audit-a")?.state).toBe("approved-intent");

		// The agent retries; the gate freezes the identical call again.
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "now verified"] },
		}).run("override audit-a");

		expect(store.listGrants()).toHaveLength(1);
		expect(store.getPending("audit-a")?.state).toBe("approved-granted");
	});
});

// ---------------------------------------------------------------------------
// bypass
// ---------------------------------------------------------------------------

describe("unguarded and guarded", () => {
	test("a mismatched challenge leaves the gate on", async () => {
		const h = harness({ script: { inputs: ["nope"] } });
		const out = await h.run("unguarded");
		expect(out).toContain("Smart Approve stays on");
		expect(h.bypass.active).toBe(false);
		expect(h.bypass.reasons).toHaveLength(0);
	});

	test("cancelling the challenge prompt leaves the gate on", async () => {
		const h = harness({ script: { inputs: [undefined] } });
		await h.run("unguarded");
		expect(h.bypass.active).toBe(false);
	});

	test("a typed challenge enables a session-scoped bypass with a persistent warning", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "debugging a broken sandbox"] } });
		const out = await h.run("unguarded");

		expect(h.bypass.active).toBe(true);
		expect(h.bypass.reasons).toEqual(["debugging a broken sandbox"]);
		expect(out).toContain("Smart Approve is UNGUARDED for this session");
		expect(out).toContain("bypass ends when this session ends");

		const widget = h.fake.widgets.find(w => w.key === WIDGET_BYPASS);
		expect(widget?.lines?.join("\n")).toContain("SMART APPROVE IS UNGUARDED");
		expect(h.fake.statuses).toContainEqual({
			key: STATUS_KEY,
			text: "UNGUARDED — Smart Approve is disabled for this session",
		});
		expect(h.fake.notices.some(n => n.type === "error")).toBe(true);
	});

	test("enabling a bypass appends an immutable audit event and persists no bypass state", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "reason"] } });
		const out = await h.run("unguarded");

		const auditId = /Audit ID: (\S+)/.exec(out)?.[1];
		expect(auditId).toBeDefined();
		const events = store.listEvents(auditId ?? "");
		expect(events.map(e => e.type)).toEqual(["bypass-enabled"]);
		expect(events[0]?.actor).toBe("human");

		// The bypass lives in session memory only: nothing durable can revive it.
		expect(store.listRules()).toHaveLength(0);
		expect(store.listGrants()).toHaveLength(0);
		expect(h.writes).toHaveLength(0);
	});

	test("guarded re-enables immediately, clears the warning, and audits it", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "reason"] } });
		await h.run("unguarded");
		const out = await h.run("guarded");

		expect(h.bypass.active).toBe(false);
		expect(h.bypass.disables).toBe(1);
		expect(out).toContain("Smart Approve is guarded again");
		expect(h.fake.widgets.at(-1)).toEqual({ key: WIDGET_BYPASS, lines: undefined });
		expect(h.fake.statuses.at(-1)).toEqual({ key: STATUS_KEY, text: undefined });

		const auditId = /Audit ID: (\S+)/.exec(out)?.[1];
		expect(store.listEvents(auditId ?? "").map(e => e.type)).toEqual(["bypass-disabled"]);
	});

	test("guarded is idempotent and does not fabricate an audit event", async () => {
		const h = harness();
		const out = await h.run("guarded");
		expect(out).toContain("already guarded");
		expect(out).not.toContain("Audit ID");
	});

	test("no configuration key can silently disable the gate", () => {
		const defaults = smartApproveConfigSchema.parse({});
		const keys: string[] = [];
		const walk = (value: unknown, prefix: string): void => {
			if (value === null || typeof value !== "object" || Array.isArray(value)) return;
			for (const [key, child] of Object.entries(value)) {
				const full = prefix === "" ? key : `${prefix}.${key}`;
				keys.push(full);
				walk(child, full);
			}
		};
		walk(defaults, "");

		expect(keys.length).toBeGreaterThan(20);
		for (const key of keys) {
			expect(key).not.toMatch(/bypass|unguarded|disabl|yolo|skip/i);
		}

		// The schema is strict, so a future "off switch" cannot be smuggled in either.
		expect(smartApproveConfigSchema.safeParse({ ...defaults, disabled: true }).success).toBe(false);
		expect(
			smartApproveConfigSchema.safeParse({ ...defaults, judge: { ...defaults.judge, bypass: true } }).success,
		).toBe(false);
	});
});

describe("rule revocation is global, exactly as its confirm dialog promises", () => {
	// The dialog is a safety lever a human reads before pulling it. If it says
	// "every outstanding allow grant" it must mean every one, not this directory's.
	const OTHER_REPO = "/srv/other-checkout";

	function grantIn(id: string, cwd: string) {
		return {
			id,
			auditId: "audit-a",
			argumentsHash: ARGS_HASH,
			canonicalHash: "canon-1",
			policyHash: resolved.policyHash,
			cwd,
			scope: "persistent" as const,
			expiresAt: NOW + 600_000,
			createdBy: "human",
			reason: "approved once",
		};
	}

	test("the confirm dialog states the scope it actually has", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		const h = harness({ script: { confirms: [false] } });
		await h.run("rules revoke rule-1");
		const asked = h.fake.confirms.at(-1)?.message ?? "";
		expect(asked).toContain("every");
		expect(asked).toContain("other working directory");
	});

	test("revoking clears a grant held in a different checkout", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("here", resolved.paths.cwd));
		store.putGrant(grantIn("elsewhere", OTHER_REPO));

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		expect(out).toContain("Invalidated 2 outstanding allow grant(s), across every working directory");
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, OTHER_REPO, NOW)).toBeUndefined();
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("the count means grants that could still admit a call, not every row", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("live", resolved.paths.cwd));
		store.putGrant({ ...grantIn("spent", resolved.paths.cwd), consumedAt: NOW - 1_000 });
		store.putGrant({ ...grantIn("lapsed", resolved.paths.cwd), expiresAt: NOW - 1 });

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		// Only the live one could have admitted anything; calling three "outstanding"
		// would overstate what the operator just prevented.
		expect(out).toContain("Invalidated 1 outstanding allow grant(s)");
	});

	test("spent and lapsed grants survive revocation as audit history", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("live", resolved.paths.cwd));
		store.putGrant({ ...grantIn("spent", resolved.paths.cwd), consumedAt: NOW - 1_000 });
		store.putGrant({ ...grantIn("lapsed", resolved.paths.cwd), expiresAt: NOW - 1 });

		await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		// A consumed grant records what actually ran. Erasing it would destroy
		// evidence, and it can authorize nothing, so revocation leaves it alone.
		const remaining = store
			.listGrants()
			.map(g => g.id)
			.sort();
		expect(remaining).toEqual(["lapsed", "spent"]);
	});

	test("cancelling revokes nothing anywhere", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("elsewhere", OTHER_REPO));
		await harness({ script: { confirms: [false] } }).run("rules revoke rule-1");
		expect(store.listGrants()).toHaveLength(1);
	});
});
